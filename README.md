# Demo Mô Phỏng Giao Thức PGP

Chương trình minh họa toàn bộ quy trình mã hóa lai (**Hybrid Cryptosystem**) theo mô hình **PGP (Pretty Good Privacy)** thông qua giao tiếp TCP Socket.

Hệ thống gồm 3 thành phần:
- **Alice** — bên gửi, mã hóa và ký số thông điệp theo 6 bước
- **Bob** — bên nhận, giải mã và xác thực thông điệp theo 6 bước ngược lại
- **Hacker** — MITM proxy ngồi giữa Alice và Bob, thực hiện 3 kịch bản tấn công

Mỗi bước trong pipeline đều **dừng lại hiển thị Input và Output** để người xem theo dõi chi tiết từng giai đoạn.

---

## Kiến trúc hệ thống

```
Kịch bản bình thường:
  Alice ──────────────────────────────────────► Bob (Port 5000)

Kịch bản có Hacker (MITM):
  Alice ──► Hacker (Port 5001) ──► Bob (Port 5000)
```

---

## Pipeline mã hóa PGP

### Phía Alice — 6 bước mã hóa (Gửi)

| Bước | Tên | Thuật toán | Input | Output |
|------|-----|-----------|-------|--------|
| **A.1** | Ký số | RSA PKCS#1 v1.5 + SHA-256 | Plaintext + `alice_private.pem` | `SignaturePacket` (message + signature) |
| **A.2** | Nén | ZLIB (deflate) | `SignaturePacket` (đã serialize) | `compressed_data` |
| **A.3** | Gắn MDC | SHA-1 | `compressed_data` | `data_with_mdc` = data + SHA-1(data) |
| **A.4** | Mã hóa đối xứng | AES-256-CBC | `data_with_mdc` + session key + IV | `EncryptedDataPacket` (iv + ciphertext) |
| **A.5** | Mã hóa session key | RSA-OAEP | session key + `bob_public.pem` | `SessionKeyPacket` |
| **A.6** | Đóng gói Armor | Base64 | `SessionKeyPacket` + `EncryptedDataPacket` | ASCII Armor (chuỗi PGP) |

### Phía Bob — 6 bước giải mã (Nhận)

| Bước | Tên | Thuật toán | Input | Output |
|------|-----|-----------|-------|--------|
| **B.1** | Giải Armor | Base64 decode | ASCII Armor | `SessionKeyPacket` + `EncryptedDataPacket` |
| **B.2** | Giải mã session key | RSA-OAEP | `SessionKeyPacket` + `bob_private.pem` | `session_key` (32 bytes) |
| **B.3** | Giải mã đối xứng | AES-256-CBC | `EncryptedDataPacket` + `session_key` | `data_with_mdc` |
| **B.4** | Kiểm tra MDC | SHA-1 | `data_with_mdc` | `compressed_data` *(lỗi nếu bị chỉnh sửa)* |
| **B.5** | Giải nén | ZLIB (inflate) | `compressed_data` | `SignaturePacket` (đã serialize) |
| **B.6** | Xác thực chữ ký | RSA PKCS#1 v1.5 | `SignaturePacket` + `alice_public.pem` | `VerificationResult` |

---

## Luồng dữ liệu đầy đủ

```
Plaintext
  │
  ▼ A.1  sign(message, alice_private)
         → SignaturePacket { message, signature }
  │
  ▼ A.2  zlib.compress(serialize(sig_packet))
         → compressed_data [bytes]
  │
  ▼ A.3  create_mdc(compressed_data)
         → data_with_mdc = compressed_data ‖ SHA-1(compressed_data)
  │
  ▼ A.4  AES_CBC_encrypt(data_with_mdc, session_key, IV)
         → EncryptedDataPacket { iv, ciphertext }
  │
  ▼ A.5  RSA_OAEP_encrypt(session_key, bob_public)
         → SessionKeyPacket { encrypted_session_key, recipient_key_id }
  │
  ▼ A.6  base64(serialize(pkt1) + serialize(pkt2))
         → "-----BEGIN PGP MESSAGE-----\n...\n-----END PGP MESSAGE-----"
  │
  ────────── TCP Socket ──────────
  │
  ▼ B.1  base64_decode → parse 2 JSON packet
  │
  ▼ B.2  RSA_OAEP_decrypt(encrypted_session_key, bob_private)
         → session_key [32 bytes]
  │
  ▼ B.3  AES_CBC_decrypt(ciphertext, session_key, iv)
         → data_with_mdc
  │
  ▼ B.4  SHA-1(data_with_mdc[:-20]) == data_with_mdc[-20:] ?
         → PHÁT HIỆN GIẢI MẠO nếu không khớp ✘
  │
  ▼ B.5  zlib.decompress(compressed_data)
         → serialize(SignaturePacket)
  │
  ▼ B.6  RSA_verify(signature, message, alice_public)
         → is_authentic: True ✔ / False ✘
```

---

## 3 Kịch bản tấn công MITM

| # | Kịch bản | Hacker làm gì | Bob phát hiện tại | Lý do |
|---|---------|--------------|------------------|-------|
| **1** | Pass-through | Không sửa gì | Không bị phát hiện ✔ | Baseline |
| **2** | Sửa ciphertext AES | XOR 16 bytes vào `ciphertext` (giữ nguyên cấu trúc PGP) | **B.4** — MDC check ✘ | SHA-1(data hỏng) ≠ MDC gốc |
| **3** | Giả mạo PGP hoàn chỉnh | Dùng `bob_public.pem` xây gói PGP mới, ký bằng bytes ngẫu nhiên | **B.6** — Verify signature ✘ | Không có `alice_private.pem` |

### Kịch bản 2 — Sửa ciphertext AES (thất bại tại B.4)

Hacker XOR trực tiếp vào ciphertext, **không đụng** cấu trúc PGP hay session key:
```
B.1 ✔ — cấu trúc JSON nguyên vẹn
B.2 ✔ — session key không bị đụng
B.3 ✔ — AES giải mã được, nhưng data bị hỏng
B.4 ✘ — SHA-1(data hỏng) ≠ MDC gốc → PHÁT HIỆN!
```
> **MDC** bảo vệ tính toàn vẹn dữ liệu sau khi giải mã AES.

### Kịch bản 3 — Giả mạo PGP hoàn chỉnh (thất bại tại B.6)

Hacker **giỏi nhất có thể** — biết format + có `bob_public.pem` (công khai):
```
B.1 ✔ — cấu trúc JSON hợp lệ (hacker biết format)
B.2 ✔ — session key mã hóa bằng bob_public.pem (ai cũng có thể lấy)
B.3 ✔ — AES mã hóa/giải mã đúng
B.4 ✔ — MDC tính đúng cho nội dung giả
B.5 ✔ — ZLIB nén đúng
B.6 ✘ — chữ ký ngẫu nhiên ≠ RSA(alice_private) → PHÁT HIỆN!
```
> **Chữ ký số RSA (B.6) là lớp bảo vệ cuối cùng và không thể bị giả mạo** — hacker không có `alice_private.pem`.

---

## Cấu trúc thư mục

```
PGP/
├── src/
│   ├── tcp_alice.py          # Entry: Alice gửi (step-by-step, TCP)
│   ├── tcp_bob.py            # Entry: Bob nhận (step-by-step, TCP)
│   ├── tcp_hacker.py         # Entry: MITM Proxy — 3 kịch bản
│   │
│   ├── packet_types.py       # Dataclass: SessionKeyPacket, EncryptedDataPacket, ...
│   ├── serializer.py         # serialize() / deserialize() JSON ↔ packet
│   ├── armor.py              # armor() / dearmor() — ASCII Armor Base64
│   ├── sign.py               # sign_message() / verify_signature() — RSA + SHA-256
│   ├── session_key.py        # encrypt / decrypt session key — RSA-OAEP
│   ├── aes_cipher.py         # AES-256-CBC encrypt / decrypt
│   ├── mdc.py                # create_mdc() / verify_mdc() — SHA-1
│   ├── compressor.py         # compress / decompress wrapper
│   ├── compress.py           # ZLIB thực tế
│   ├── keygen.py             # generate_rsa_keypair() — RSA-2048
│   ├── setup_keys.py         # Script sinh cặp khóa Alice và Bob
│   └── crypto_symmetric/
│       └── aes.py            # AES CBC core (PyCryptodome)
│
├── keys/
│   ├── alice_private.pem     # Alice dùng để ký (A.1)
│   ├── alice_public.pem      # Bob dùng để xác thực chữ ký (B.6)
│   ├── bob_private.pem       # Bob dùng để giải mã session key (B.2)
│   └── bob_public.pem        # Alice / Hacker dùng để mã hóa session key (A.5)
│
├── shared/                   # Bob ghi file kết quả vào đây
├── docs/
│   └── packet_format.md      # Đặc tả chi tiết từng loại packet
├── requirements.txt
└── README.md
```

---

## Cài đặt

```bash
pip install -r requirements.txt
```

Thư viện cần cài: **pycryptodome** — RSA, AES, SHA-256, SHA-1.  
Phần còn lại dùng thư viện chuẩn Python: `zlib`, `hashlib`, `socket`, `json`, `base64`.

---

## Hướng dẫn chạy

### Bước 0 — Sinh khóa RSA *(chỉ cần 1 lần)*

```bash
python -m src.setup_keys
```

### Kịch bản A — Alice gửi thẳng đến Bob

```bash
# Terminal 1
python -m src.tcp_bob

# Terminal 2
python -m src.tcp_alice --host 127.0.0.1 --port 5000
```

### Kịch bản B — Có Hacker ngồi giữa

```bash
# Terminal 1
python -m src.tcp_bob

# Terminal 2 — Hacker (chọn kịch bản 1, 2, hoặc 3)
python -m src.tcp_hacker

# Terminal 3
python -m src.tcp_alice --host 127.0.0.1 --port 5001
```

---

## Yêu cầu hệ thống

- Python **3.8+**
- pycryptodome **3.x**
