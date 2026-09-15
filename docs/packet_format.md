# Packet Format — Chương trình Demo Giao thức PGP

Tài liệu này là "hợp đồng interface" giữa các module. Mọi thành viên cần đọc và
thống nhất **trước khi** code, không tự ý đổi tên trường / kiểu dữ liệu khi đã chốt.

Quy ước chung:
- Ngôn ngữ: Python
- Kiểu dữ liệu nhị phân dùng `bytes`; khi cần lưu file / truyền qua JSON thì
  encode bằng `base64`.
- Mọi hàm mã hóa/ký/nén trả về `dict` có key cố định (không dùng tuple không tên).
- Thuật toán dùng số nguyên (mã hằng số) để dễ mở rộng, tránh so sánh chuỗi.

```python
ALG_HASH_SHA256 = 0x01
ALG_HASH_SHA1   = 0x02   # dùng riêng cho MDC

ALG_SIGN_RSA    = 0x01
ALG_SIGN_DSA    = 0x02
ALG_SIGN_EDDSA  = 0x03

ALG_SYM_AES     = 0x01
ALG_SYM_IDEA    = 0x02
ALG_SYM_CAST128 = 0x03

ALG_ASYM_RSA     = 0x01
ALG_ASYM_ELGAMAL = 0x02

ALG_COMPRESS_ZIP  = 0x01
ALG_COMPRESS_ZLIB = 0x02
```

---

## A. QUY TRÌNH PHÁT (Sender) — Bước 1 → Bước 6

### Bước 1 — Signature Packet (Ký số)
Input: `message: bytes`, `sender_private_key`
Output:

```python
SignaturePacket = {
    "tag": "SIG",
    "hash_algo": int,        # VD: ALG_HASH_SHA256
    "sign_algo": int,        # VD: ALG_SIGN_RSA
    "signature": bytes,      # chữ ký số trên H(message)
    "message": bytes,        # thông điệp gốc M, giữ nguyên kèm theo
}
```
Ghi chú: `signature = Sign(private_key_A, Hash(message))`

---

### Bước 2 — Compressed Packet (Nén)
Input: `SignaturePacket` (serialize `message + signature` thành 1 khối bytes)
Output:

```python
CompressedPacket = {
    "tag": "COMP",
    "compress_algo": int,    # ALG_COMPRESS_ZIP / ZLIB
    "compressed_data": bytes,  # nén(message || signature)
}
```

---

### Bước 3 — MDC Packet (Modification Detection Code)
Input: `CompressedPacket.compressed_data`
Output:

```python
MDCPacket = {
    "tag": "MDC",
    "mdc_hash_algo": int,     # ALG_HASH_SHA1
    "mdc_value": bytes,       # SHA-1(compressed_data)
    "data_with_mdc": bytes,   # compressed_data || mdc_value
}
```
Ghi chú: `data_with_mdc` là phần sẽ được đưa sang bước 4 để mã hóa đối xứng.

---

### Bước 4 — Symmetric-Encrypted Data Packet (Mã hóa đối xứng)
Input: `MDCPacket.data_with_mdc`, session key `K` (sinh ngẫu nhiên tại bước này)
Output:

```python
EncryptedDataPacket = {
    "tag": "ENCDATA",
    "sym_algo": int,       # ALG_SYM_AES / IDEA / CAST128
    "iv": bytes,           # vector khởi tạo (nếu mode CBC/GCM)
    "ciphertext": bytes,   # AES_Encrypt(K, data_with_mdc)
}
```
Session key `K` (bytes, random) được giữ tạm trong bộ nhớ để dùng ở Bước 5,
**không** được ghi ra packet ở bước này.

---

### Bước 5 — Session-Key Packet (Mã hóa bất đối xứng khóa phiên)
Input: session key `K`, `receiver_public_key`
Output:

```python
SessionKeyPacket = {
    "tag": "SESSKEY",
    "asym_algo": int,           # ALG_ASYM_RSA / ELGAMAL
    "recipient_key_id": str,    # định danh public key của B (VD: fingerprint)
    "encrypted_session_key": bytes,  # Encrypt(pubkey_B, K)
}
```

---

### Bước 6 — Radix-64 Message (Đóng gói cuối + ASCII Armor)
Input: `SessionKeyPacket` + `EncryptedDataPacket` (ghép theo thứ tự cố định)
Output:

```python
PGPMessage = {
    "tag": "PGPMSG",
    "version": "1.0",
    "session_key_packet": SessionKeyPacket,   # sẽ serialize trước khi encode
    "encrypted_data_packet": EncryptedDataPacket,
    "armor_text": str,   # toàn bộ message trên serialize -> bytes -> Radix-64 (base64) -> str
}
```
Quy ước thứ tự ghép nhị phân trước khi encode:
`bytes_to_armor = serialize(SessionKeyPacket) + serialize(EncryptedDataPacket)`
`armor_text = base64.b64encode(bytes_to_armor).decode("ascii")`

Đây chính là chuỗi văn bản (giống khối `-----BEGIN PGP MESSAGE-----`) được gửi qua email/kênh truyền.

---

## B. QUY TRÌNH NHẬN (Receiver) — Bước 1 → Bước 6 (ngược lại)

### Bước 1 — Giải mã Radix-64
Input: `armor_text: str`
Output: `bytes_raw: bytes` → parse lại thành `SessionKeyPacket` + `EncryptedDataPacket`
(dùng đúng hàm `deserialize` đối xứng với `serialize` ở bước A.6)

### Bước 2 — Giải mã Session Key
Input: `SessionKeyPacket.encrypted_session_key`, `receiver_private_key`
Output:

```python
session_key: bytes   # K = Decrypt(private_key_B, encrypted_session_key)
```

### Bước 3 — Giải mã đối xứng
Input: `EncryptedDataPacket.ciphertext`, `EncryptedDataPacket.iv`, `session_key`
Output:

```python
data_with_mdc: bytes   # = AES_Decrypt(K, iv, ciphertext)
```

### Bước 4 — Kiểm tra MDC
Input: `data_with_mdc`
Xử lý:
```python
compressed_data = data_with_mdc[:-20]   # bỏ 20 byte cuối (SHA-1 = 20 bytes)
mdc_received    = data_with_mdc[-20:]
mdc_calculated  = SHA1(compressed_data)
```
Output:

```python
MDCCheckResult = {
    "tag": "MDC_CHECK",
    "is_valid": bool,          # mdc_received == mdc_calculated
    "compressed_data": bytes,  # trả về nếu is_valid == True
}
```
Nếu `is_valid == False` → **dừng toàn bộ quy trình**, báo lỗi "dữ liệu bị chỉnh sửa".

### Bước 5 — Giải nén
Input: `MDCCheckResult.compressed_data`
Output:

```python
decompressed_data: bytes   # message || signature (chưa tách rời)
```

### Bước 6 — Xác thực chữ ký (Verification)
Input: `decompressed_data` (tách ra `message`, `signature`), `sender_public_key`
Xử lý:
```python
hash_calculated = Hash(message)
hash_from_sig   = Verify(public_key_A, signature)   # thu hồi giá trị băm tham chiếu
```
Output:

```python
VerificationResult = {
    "tag": "VERIFY_RESULT",
    "is_authentic": bool,     # hash_calculated == hash_from_sig
    "message": bytes,         # thông điệp gốc M nếu hợp lệ
}
```

---

## C. Bảng tổng hợp interface giữa các module (theo phân công 4 người)

| Bước | Packet / Kết quả | Người tạo ra (Sender side) | Người tiêu thụ |
|---|---|---|---|
| A.1 Ký số | `SignaturePacket` | Người 1 | Người 3 (ghép pipeline gửi) |
| A.2 Nén | `CompressedPacket` | Người 2 | Người 3 |
| A.3 MDC | `MDCPacket` | Người 2 | Người 3 |
| A.4 Mã đối xứng | `EncryptedDataPacket` | Người 2 | Người 3 |
| A.5 Mã khóa phiên | `SessionKeyPacket` | Người 1 | Người 3 |
| A.6 Radix-64 | `PGPMessage` | Người 3 | Người 4 (nhận armor_text để gửi đi) |
| B.1–B.6 (nhận) | `MDCCheckResult`, `VerificationResult`, ... | Người 4 (gọi lại hàm giải mã của Người 1 & 2) | Người 4 (hiển thị kết quả ở CLI/GUI) |

**Lưu ý quan trọng:** Người 4 khi viết pipeline nhận **tái sử dụng trực tiếp**
các hàm giải mã/giải nén/verify do Người 1, Người 2 cung cấp (không viết lại) —
đây là lý do vì sao chốt đúng format và tên hàm ngay từ đầu giúp tiết kiệm
công sức nhất.

