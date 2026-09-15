"""
src/packet_types.py

Định nghĩa cấu trúc dữ liệu (packet) dùng chung cho toàn bộ dự án.
Mọi module (keygen, sign, aes, compress, mdc, radix64, sender, receiver)
đều import từ đây thay vì tự định nghĩa dict/class riêng.

Quy ước:
- Các trường nhị phân dùng kiểu `bytes`.
- Các trường "loại thuật toán" dùng số nguyên (int), tra theo các hằng số
  ALG_* bên dưới, để dễ mở rộng và tránh so sánh chuỗi rải rác trong code.
"""

from dataclasses import dataclass, field


# ============================================================
# HẰNG SỐ THUẬT TOÁN — dùng chung toàn dự án
# ============================================================

# Thuật toán băm
ALG_HASH_SHA256 = 0x01
ALG_HASH_SHA1 = 0x02  # dùng riêng cho MDC

# Thuật toán ký số (bất đối xứng)
ALG_SIGN_RSA = 0x01
ALG_SIGN_DSA = 0x02
ALG_SIGN_EDDSA = 0x03

# Thuật toán mã hóa đối xứng
ALG_SYM_AES = 0x01
ALG_SYM_IDEA = 0x02
ALG_SYM_CAST128 = 0x03

# Thuật toán mã hóa bất đối xứng (dùng cho session key)
ALG_ASYM_RSA = 0x01
ALG_ASYM_ELGAMAL = 0x02

# Thuật toán nén
ALG_COMPRESS_ZIP = 0x01
ALG_COMPRESS_ZLIB = 0x02


# ============================================================
# A. CÁC PACKET Ở QUY TRÌNH PHÁT (SENDER)
# ============================================================

@dataclass
class SignaturePacket:
    """Kết quả Bước A.1 — Ký số."""
    hash_algo: int = ALG_HASH_SHA256
    sign_algo: int = ALG_SIGN_RSA
    signature: bytes = b""     # chữ ký số trên Hash(message)
    message: bytes = b""       # thông điệp gốc, giữ nguyên kèm theo
    tag: str = "SIG"


@dataclass
class CompressedPacket:
    """Kết quả Bước A.2 — Nén (message || signature)."""
    compress_algo: int = ALG_COMPRESS_ZLIB
    compressed_data: bytes = b""
    tag: str = "COMP"


@dataclass
class MDCPacket:
    """Kết quả Bước A.3 — Gắn MDC (Modification Detection Code)."""
    mdc_hash_algo: int = ALG_HASH_SHA1
    mdc_value: bytes = b""         # SHA-1(compressed_data)
    data_with_mdc: bytes = b""     # compressed_data || mdc_value
    tag: str = "MDC"


@dataclass
class EncryptedDataPacket:
    """Kết quả Bước A.4 — Mã hóa đối xứng data_with_mdc bằng session key."""
    sym_algo: int = ALG_SYM_AES
    iv: bytes = b""            # vector khởi tạo (CBC/GCM...)
    ciphertext: bytes = b""    # AES_Encrypt(K, data_with_mdc)
    tag: str = "ENCDATA"


@dataclass
class SessionKeyPacket:
    """Kết quả Bước A.5 — Mã hóa session key bằng public key người nhận."""
    asym_algo: int = ALG_ASYM_RSA
    recipient_key_id: str = ""             # fingerprint / định danh public key B
    encrypted_session_key: bytes = b""     # Encrypt(pubkey_B, K)
    tag: str = "SESSKEY"


@dataclass
class PGPMessage:
    """Kết quả Bước A.6 — Gói tin hoàn chỉnh sau Radix-64 (ASCII Armor)."""
    version: str = "1.0"
    session_key_packet: SessionKeyPacket = field(default_factory=SessionKeyPacket)
    encrypted_data_packet: EncryptedDataPacket = field(default_factory=EncryptedDataPacket)
    armor_text: str = ""   # chuỗi base64 cuối cùng, gửi qua kênh truyền
    tag: str = "PGPMSG"


# ============================================================
# B. CÁC PACKET Ở QUY TRÌNH NHẬN (RECEIVER)
# ============================================================

@dataclass
class MDCCheckResult:
    """Kết quả Bước B.4 — Kiểm tra MDC."""
    is_valid: bool = False
    compressed_data: bytes = b""   # chỉ có giá trị khi is_valid == True
    tag: str = "MDC_CHECK"


@dataclass
class VerificationResult:
    """Kết quả Bước B.6 — Xác thực chữ ký."""
    is_authentic: bool = False
    message: bytes = b""           # thông điệp gốc, chỉ có giá trị khi is_authentic == True
    tag: str = "VERIFY_RESULT"


# ============================================================
# TRA CỨU DÙNG CHO serializer.py
# ============================================================

# Ánh xạ tên class -> class, để deserialize() dựng lại đúng kiểu packet
PACKET_CLASSES = {
    "SignaturePacket": SignaturePacket,
    "CompressedPacket": CompressedPacket,
    "MDCPacket": MDCPacket,
    "EncryptedDataPacket": EncryptedDataPacket,
    "SessionKeyPacket": SessionKeyPacket,
    "PGPMessage": PGPMessage,
    "MDCCheckResult": MDCCheckResult,
    "VerificationResult": VerificationResult,
}

# Khai báo field nào là kiểu bytes trong từng packet, để serializer.py biết
# field nào cần encode/decode base64 khi chuyển qua JSON.
BYTES_FIELDS = {
    "SignaturePacket": ["signature", "message"],
    "CompressedPacket": ["compressed_data"],
    "MDCPacket": ["mdc_value", "data_with_mdc"],
    "EncryptedDataPacket": ["iv", "ciphertext"],
    "SessionKeyPacket": ["encrypted_session_key"],
    "MDCCheckResult": ["compressed_data"],
    "VerificationResult": ["message"],
}
