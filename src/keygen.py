"""
src/keygen.py
Người phụ trách: Bùi Nhật Minh (Core Crypto)

Sinh cặp khóa bất đối xứng (RSA) và các tiện ích nạp/xuất khóa cơ bản.
Làm nền tảng cho chữ ký số và mã hóa khóa phiên.
"""

from Crypto.PublicKey import RSA


# ============================================================
# QUẢN LÝ KHÓA (KEYGEN & KEYRING)
# ============================================================

def generate_rsa_keypair(bits: int = 2048) -> tuple[bytes, bytes]:
    """
    Sinh cặp khóa RSA.
    Trả về tuple (private_key_pem, public_key_pem) dưới dạng bytes.
    """
    if not isinstance(bits, int) or bits < 1024:
        raise ValueError("Số bit khóa RSA không hợp lệ (phải >= 1024).")

    key = RSA.generate(bits)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    
    return private_key, public_key


# ============================================================
# TEST NHANH — chạy trực tiếp file này để tự kiểm tra
# ============================================================

if __name__ == "__main__":
    # --- Test 1: Sinh khóa thành công ---
    priv, pub = generate_rsa_keypair(1024)  # Dùng 1024 cho test nhanh
    assert b"BEGIN RSA PRIVATE KEY" in priv, "Test 1 FAIL: Lỗi định dạng Private Key"
    assert b"BEGIN PUBLIC KEY" in pub, "Test 1 FAIL: Lỗi định dạng Public Key"
    print("Test 1 (Sinh khóa RSA chuẩn định dạng): PASS")

    # --- Test 2: Báo lỗi khi tham số sai ---
    try:
        generate_rsa_keypair(512)
        raise AssertionError("Test 2 FAIL: Không báo lỗi khi độ dài khóa quá ngắn")
    except ValueError as e:
        print(f"Test 2 (Chặn số bit khóa nhỏ): PASS - {e}")
    
    print("\nOK: cả 2 test keygen đều thành công.")