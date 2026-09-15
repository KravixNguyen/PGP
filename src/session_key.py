"""
src/session_key.py
Người phụ trách: Bùi Nhật Minh (Core Crypto)

Bước A.5 (gửi) / B.2 (nhận) — đúng theo docs/packet_format.md.
Mã hóa/giải mã Session Key đối xứng bằng RSA (PKCS1_OAEP).
"""

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

from src.packet_types import SessionKeyPacket, ALG_ASYM_RSA


# ============================================================
# A.5 — MÃ HÓA KHÓA PHIÊN (session_key -> SessionKeyPacket)
# ============================================================

def encrypt_session_key(session_key: bytes, receiver_public_key: bytes) -> SessionKeyPacket:
    if not isinstance(session_key, bytes):
        raise TypeError(f"encrypt_session_key() cần bytes, nhận phải: {type(session_key)}")

    try:
        key = RSA.import_key(receiver_public_key)
        cipher_rsa = PKCS1_OAEP.new(key)
        encrypted_key = cipher_rsa.encrypt(session_key)
    except ValueError as e:
        raise ValueError(f"Lỗi mã hóa session key (khóa public không hợp lệ): {e}")

    return SessionKeyPacket(
        asym_algo=ALG_ASYM_RSA,
        recipient_key_id="auto-generated", # Có thể thay bằng hàm tính KeyID thực tế nếu cần
        encrypted_session_key=encrypted_key
    )


# ============================================================
# B.2 — GIẢI MÃ KHÓA PHIÊN (SessionKeyPacket -> session_key)
# ============================================================

def decrypt_session_key(packet: SessionKeyPacket, receiver_private_key: bytes) -> bytes:
    if not isinstance(packet, SessionKeyPacket):
        raise TypeError("decrypt_session_key() cần SessionKeyPacket hợp lệ.")

    try:
        key = RSA.import_key(receiver_private_key)
        cipher_rsa = PKCS1_OAEP.new(key)
        session_key = cipher_rsa.decrypt(packet.encrypted_session_key)
        return session_key
    except ValueError:
        # Xảy ra khi dùng sai private key để giải mã
        raise ValueError("Giải mã Session Key thất bại (có thể sai Private Key hoặc dữ liệu bị hỏng).")


# ============================================================
# TEST NHANH
# ============================================================

if __name__ == "__main__":
    from src.keygen import generate_rsa_keypair
    import os

    priv_key, pub_key = generate_rsa_keypair(1024)
    fake_priv_key = generate_rsa_keypair(1024)[0]
    
    # Giả lập khóa AES-256 (32 bytes) sinh ngẫu nhiên từ Bước A.4
    original_session_key = os.urandom(32)

    # --- Test 1: Mã hóa/Giải mã round-trip ---
    pkt = encrypt_session_key(original_session_key, pub_key)
    decrypted_key = decrypt_session_key(pkt, priv_key)
    assert original_session_key == decrypted_key, "Test 1 FAIL: Session key round-trip không khớp"
    print("Test 1 (Mã hóa và giải mã khóa phiên thành công): PASS")

    # --- Test 2: Sai Private Key phải raise lỗi rõ ràng, không crash ---
    try:
        decrypt_session_key(pkt, fake_priv_key)
        raise AssertionError("Test 2 FAIL: Không báo lỗi khi dùng sai Private Key")
    except ValueError as e:
        print(f"Test 2 (Chặn truy cập khi sai Private Key): PASS - {e}")

    print("\nOK: cả 2 test session_key đều thành công.")