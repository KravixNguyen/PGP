"""
src/sign.py
Người phụ trách: Bùi Nhật Minh (Core Crypto)

Bước A.1 (gửi) / B.6 (nhận) — đúng theo docs/packet_format.md.
Thực hiện băm SHA-256 và ký/xác thực bằng RSA.
"""

from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

from src.packet_types import SignaturePacket, VerificationResult, ALG_HASH_SHA256


# ============================================================
# A.1 — KÝ SỐ (message -> SignaturePacket)
# ============================================================

def sign_message(message: bytes, sender_private_key: bytes) -> SignaturePacket:
    if not isinstance(message, bytes):
        raise TypeError(f"sign_message() cần bytes, nhận phải: {type(message)}")
    if not isinstance(sender_private_key, bytes):
        raise TypeError("sender_private_key phải ở định dạng bytes (PEM).")

    try:
        key = RSA.import_key(sender_private_key)
    except ValueError as e:
        raise ValueError(f"Lỗi nạp khóa bí mật để ký: {e}")

    h = SHA256.new(message)
    signature_bytes = pkcs1_15.new(key).sign(h)

    return SignaturePacket(
        hash_algo=ALG_HASH_SHA256,
        signature=signature_bytes,
        message=message,  # Lưu message gốc để receiver khôi phục sau khi giải mã
    )


# ============================================================
# B.6 — XÁC THỰC (decompressed_data + packet -> VerificationResult)
# ============================================================

def verify_signature(decompressed_data: bytes, sender_public_key: bytes, signature_packet: SignaturePacket) -> VerificationResult:
    if not isinstance(decompressed_data, bytes):
        return VerificationResult(is_authentic=False, message="Dữ liệu đầu vào không phải bytes".encode("utf-8"))
    if not isinstance(signature_packet, SignaturePacket):
        return VerificationResult(is_authentic=False, message="Packet chữ ký không hợp lệ".encode("utf-8"))

    try:
        key = RSA.import_key(sender_public_key)
        h = SHA256.new(decompressed_data)
        pkcs1_15.new(key).verify(h, signature_packet.signature)
        return VerificationResult(is_authentic=True, message=decompressed_data)
    except (ValueError, TypeError):
        # Bắt lỗi sai khóa, sai định dạng chữ ký -> Không để crash chương trình
        return VerificationResult(is_authentic=False, message="Chữ ký không hợp lệ hoặc dữ liệu bị sửa đổi".encode("utf-8"))


# ============================================================
# TEST NHANH
# ============================================================

if __name__ == "__main__":
    from src.keygen import generate_rsa_keypair
    
    msg = b"Du lieu can ky PGP"
    priv_key, pub_key = generate_rsa_keypair(1024)
    fake_pub_key = generate_rsa_keypair(1024)[1]

    # --- Test 1: Ký và xác thực thành công ---
    sig_pkt = sign_message(msg, priv_key)
    res_valid = verify_signature(msg, pub_key, sig_pkt)
    assert res_valid.is_valid is True, "Test 1 FAIL: Xác thực sai dữ liệu đúng"
    print("Test 1 (Ký và xác thực dữ liệu gốc): PASS")

    # --- Test 2: Dữ liệu bị chỉnh sửa phải fail chuẩn mực (không crash) ---
    res_invalid_msg = verify_signature(b"Du lieu da bi hack", pub_key, sig_pkt)
    assert res_invalid_msg.is_valid is False, "Test 2 FAIL: Chấp nhận dữ liệu giả"
    print("Test 2 (Từ chối dữ liệu bị chỉnh sửa): PASS")

    # --- Test 3: Sai public key phải fail chuẩn mực (không crash) ---
    res_wrong_key = verify_signature(msg, fake_pub_key, sig_pkt)
    assert res_wrong_key.is_valid is False, "Test 3 FAIL: Chấp nhận sai khóa"
    print("Test 3 (Bắt lỗi khi kiểm tra bằng sai Public Key): PASS")

    print("\nOK: cả 3 test sign đều thành công.")