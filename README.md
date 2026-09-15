# PGP Demo — Mô phỏng giao thức PGP qua TCP Socket

Chương trình minh họa đầy đủ quy trình mã hóa lai (**hybrid cryptosystem**) theo mô hình PGP,
bao gồm pipeline mã hóa 6 bước phía Alice, pipeline giải mã 6 bước phía Bob,
và kịch bản tấn công Man-in-the-Middle (MITM) bởi Hacker.

---

## Mô hình hoạt động

```
Alice ──► [TCP Port 5001] ──► Hacker (MITM) ──► [TCP Port 5000] ──► Bob
               hoặc
Alice ──────────────────────────────────────────► [TCP Port 5000] ──► Bob
```

Mỗi bước trong pipeline đều **dừng lại và hiển thị Input/Output** để người dùng
theo dõi chi tiết từng giai đoạn mã hóa / giải mã.

---

## Pipeline mã hóa PGP

### Phía Alice (Gửi) — 6 bước

| Bước | Mô tả | Thuật toán |
|------|-------|-----------|
| **A.1** | Ký số thông điệp | SHA-256 + RSA PKCS#1 v1.5 |
| **A.2** | Nén dữ liệu | ZLIB (deflate) |
| **A.3** | Gắn MDC (Modification Detection Code) | SHA-1 |
| **A.4** | Mã hóa đối xứng | AES-256-CBC + Initialization Vector (IV) |
| **A.5** | Mã hóa session key | RSA-OAEP (Public Key của Bob) |
| **A.6** | Đóng gói ASCII Armor | Base64 + BEGIN/END PGP MESSAGE |

### Phía Bob (Nhận) — 6 bước ngược lại

| Bước | Mô tả | Thuật toán |
|------|-------|-----------|
| **B.1** | Giải Radix-64 (Dearmor) | Base64 decode + tách packet |
| **B.2** | Giải mã Session Key | RSA-OAEP (Private Key của Bob) |
| **B.3** | Giải mã đối xứng | AES-256-CBC |
| **B.4** | Kiểm tra MDC | SHA-1 integrity check |
| **B.5** | Giải nén | ZLIB (inflate) |
| **B.6** | Xác thực chữ ký | RSA PKCS#1 v1.5 + SHA-256 (Public Key Alice) |

---

## Kịch bản tấn công MITM (Hacker)

| Kịch bản | Mô tả | Bob phát hiện tại |
|---------|-------|-----------------|
| **[1]** Pass-through | Không sửa gì, chuyển tiếp nguyên bản | Không bị phát hiện ✔ |
| **[2]** Thay JSON giả | Thay base64 bằng payload JSON giả | **B.1** — dearmor thất bại ✘ |
| **[3]** Giả mạo PGP hoàn chỉnh | Biết format + có `bob_public.pem`, xây gói PGP hợp lệ nhưng ký ngẫu nhiên | **B.6** — chữ ký RSA sai ✘ |

> **Kết luận bảo mật:** Chữ ký số RSA tại B.6 là lớp bảo vệ cuối cùng
> và không thể bị vượt qua — hacker không có `alice_private.pem`.

---

## Cấu trúc thư mục

```
PGP/
├── src/
│   ├── tcp_alice.py          # 🚀 Entry: Alice gửi (step-by-step, TCP)
│   ├── tcp_bob.py            # 🚀 Entry: Bob nhận (step-by-step, TCP)
│   ├── tcp_hacker.py         # 🚀 Entry: MITM Proxy — 3 kịch bản tấn công
│   │
│   ├── packet_types.py       # Định nghĩa dataclass packet (SessionKeyPacket, EncryptedDataPacket, ...)
│   ├── serializer.py         # serialize() / deserialize() JSON ↔ packet
│   ├── armor.py              # armor() / dearmor() — ASCII Armor (Base64)
│   ├── sign.py               # sign_message() / verify_signature() — RSA + SHA-256
│   ├── session_key.py        # encrypt/decrypt session key — RSA-OAEP
│   ├── aes_cipher.py         # AES-256-CBC encrypt/decrypt
│   ├── mdc.py                # create_mdc() / verify_mdc() — SHA-1
│   ├── compressor.py         # compress_data() / decompress_data() wrapper
│   ├── compress.py           # ZLIB thực tế
│   ├── keygen.py             # generate_rsa_keypair() — RSA-2048
│   ├── setup_keys.py         # Script sinh khóa Alice và Bob
│   └── crypto_symmetric/
│       └── aes.py            # AES CBC thực tế (Crypto.Cipher)
│
├── keys/                     # Chứa các file khóa RSA (tạo bởi setup_keys.py)
│   ├── alice_private.pem
│   ├── alice_public.pem
│   ├── bob_private.pem
│   └── bob_public.pem
│
├── shared/                   # Bob lưu file đã giải mã vào đây
│   └── message_decrypted.txt
│
├── docs/
│   └── packet_format.md      # Đặc tả chi tiết từng loại packet
│
├── requirements.txt
└── README.md
```

---

## Cài đặt

```bash
pip install -r requirements.txt
```

Thư viện duy nhất cần cài:
- **pycryptodome** — Cung cấp RSA, AES, SHA-256, SHA-1

Phần còn lại dùng thư viện chuẩn Python: `zlib`, `hashlib`, `socket`, `json`, `base64`.

---

## Hướng dẫn chạy

### Bước 0 — Sinh khóa RSA (chỉ cần 1 lần)

```bash
python -m src.setup_keys
```

Sinh ra `keys/alice_private.pem`, `keys/alice_public.pem`, `keys/bob_private.pem`, `keys/bob_public.pem`.

---

### Kịch bản A — Alice gửi thẳng đến Bob

```bash
# Terminal 1: Khởi động Bob (lắng nghe port 5000)
python -m src.tcp_bob

# Terminal 2: Alice gửi tin nhắn đến Bob
python -m src.tcp_alice --host 127.0.0.1 --port 5000
```

---

### Kịch bản B — Có Hacker ngồi giữa

```bash
# Terminal 1: Bob (port 5000)
python -m src.tcp_bob

# Terminal 2: Hacker MITM (lắng nghe Alice tại port 5001, forward đến Bob port 5000)
python -m src.tcp_hacker

# Terminal 3: Alice kết nối đến Hacker (port 5001)
python -m src.tcp_alice --host 127.0.0.1 --port 5001
```

Trong terminal Hacker, chọn kịch bản tấn công:
- `[1]` — Pass-through (Alice/Bob thành công)
- `[2]` — Thay JSON giả (Bob thất bại tại B.1)
- `[3]` — Giả mạo PGP hoàn chỉnh (Bob thất bại tại B.6)

---

## Luồng dữ liệu chi tiết

```
Plaintext
  │
  ▼ A.1 sign_message(msg, alice_priv)
SignaturePacket { message, signature }
  │
  ▼ A.2 compress_data(serialize(sig_packet))
compressed_data [bytes]
  │
  ▼ A.3 create_mdc(compressed_data)
data_with_mdc = compressed_data || SHA-1(compressed_data)
  │
  ▼ A.4 encrypt_symmetric(data_with_mdc, session_key, IV)
EncryptedDataPacket { iv, ciphertext }
  │
  ▼ A.5 encrypt_session_key(session_key, bob_public)
SessionKeyPacket { encrypted_session_key, recipient_key_id }
  │
  ▼ A.6 armor(session_key_pkt, enc_data_pkt)
"-----BEGIN PGP MESSAGE-----\n...base64...\n-----END PGP MESSAGE-----"
  │
  ▼ TCP Socket
  │
  ▼ B.1 dearmor(armor_text)
SessionKeyPacket + EncryptedDataPacket
  │
  ▼ B.2 decrypt_session_key(sess_key_pkt, bob_priv)
session_key [32 bytes]
  │
  ▼ B.3 decrypt_symmetric(enc_data_pkt, session_key)
data_with_mdc [bytes]
  │
  ▼ B.4 verify_mdc(data_with_mdc)
compressed_data [bytes]  ← lỗi nếu bị chỉnh sửa
  │
  ▼ B.5 decompress_data(compressed_data)
serialized SignaturePacket
  │
  ▼ B.6 verify_signature(msg, alice_public, sig_packet)
VerificationResult { is_authentic, message }
```

---

## Yêu cầu hệ thống

- Python **3.8+**
- pycryptodome **3.x**
