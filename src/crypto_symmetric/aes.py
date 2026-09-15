# ============================================================
# Người phụ trách: Ngô Quốc Mạnh-B24DCAT178 (CORE CRYPTO)
# Module: src/crypto_symmetric/aes.py
#
# Phụ trách:
#   A.4 - Symmetric-Encrypted Data Packet
#   B.3 - Giải mã đối xứng
#
# Thuật toán:
#   AES-256-CBC
#
# Input/Output tuân theo packet_format.md
# ============================================================

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# Mã thuật toán AES theo packet_format.md
ALG_SYM_AES = 0x01


# ============================================================
# A.4 - SINH SESSION KEY
# ============================================================

def generate_session_key():
    """
    Sinh session key ngẫu nhiên 32 bytes (AES-256).

    Return:
        bytes: session key
    """

    return get_random_bytes(32)


# ============================================================
# A.4 - MÃ HÓA ĐỐI XỨNG
# ============================================================

def encrypt_symmetric(data_with_mdc, session_key):
    """
    Mã hóa data_with_mdc bằng AES-256-CBC.

    Input:
        data_with_mdc: bytes
        session_key: bytes

    Output:
        EncryptedDataPacket
    """

    if not isinstance(data_with_mdc, bytes):
        raise TypeError("data_with_mdc phải là bytes")

    if not isinstance(session_key, bytes):
        raise TypeError("session_key phải là bytes")

    if len(session_key) != 32:
        raise ValueError("Session key phải có 32 bytes")

    # AES-CBC sử dụng IV 16 bytes
    iv = get_random_bytes(16)

    cipher = AES.new(
        session_key,
        AES.MODE_CBC,
        iv
    )

    # Padding trước khi mã hóa
    padded_data = pad(
        data_with_mdc,
        AES.block_size
    )

    ciphertext = cipher.encrypt(padded_data)

    return {
        "tag": "ENCDATA",
        "sym_algo": ALG_SYM_AES,
        "iv": iv,
        "ciphertext": ciphertext
    }


# ============================================================
# B.3 - GIẢI MÃ ĐỐI XỨNG
# ============================================================

def decrypt_symmetric(encrypted_data_packet, session_key):
    """
    Giải mã EncryptedDataPacket bằng AES-256-CBC.

    Input:
        encrypted_data_packet: dict
        session_key: bytes

    Return:
        data_with_mdc: bytes
    """

    if not isinstance(session_key, bytes):
        raise TypeError("session_key phải là bytes")

    if len(session_key) != 32:
        raise ValueError("Session key phải có 32 bytes")

    iv = encrypted_data_packet["iv"]
    ciphertext = encrypted_data_packet["ciphertext"]

    cipher = AES.new(
        session_key,
        AES.MODE_CBC,
        iv
    )

    padded_data = cipher.decrypt(ciphertext)

    data_with_mdc = unpad(
        padded_data,
        AES.block_size
    )

    return data_with_mdc
