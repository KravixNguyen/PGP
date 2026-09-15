"""
src/armor.py
Người phụ trách: Nguyễn Hải Long

Bước A.6 (gửi) / B.1 (nhận) — đúng theo docs/packet_format.md.

Công thức đúng nguyên văn tài liệu:
    bytes_to_armor = serialize(SessionKeyPacket) + serialize(EncryptedDataPacket)
    armor_text = base64.b64encode(bytes_to_armor).decode("ascii")

Ghi chú kỹ thuật: nối 2 chuỗi JSON liền nhau (kết quả của serialize()) không
thể tách lại bằng json.loads() thông thường (báo lỗi "Extra data") vì
json.loads() chỉ chấp nhận đúng 1 giá trị JSON. Ở đây dùng
json.JSONDecoder().raw_decode() để đọc object JSON ĐẦU TIÊN và biết chính
xác vị trí nó kết thúc, từ đó đọc tiếp object JSON THỨ HAI ngay sau đó.
Cách này giữ nguyên 100% công thức ghép trong packet_format.md, không cần
thêm length-prefix hay đổi định dạng gì cả.
"""

import base64
import json

from src.packet_types import PGPMessage, SessionKeyPacket, EncryptedDataPacket
from src.serializer import serialize, deserialize


def _skip_whitespace(text: str, idx: int) -> int:
    """Bỏ qua khoảng trắng (nếu có) giữa 2 khối JSON liền nhau."""
    while idx < len(text) and text[idx] in " \t\n\r":
        idx += 1
    return idx


# ============================================================
# A.6 — ARMOR (packet -> armor_text)
# ============================================================

def armor(session_key_packet: SessionKeyPacket,
          encrypted_data_packet: EncryptedDataPacket) -> PGPMessage:
    if not isinstance(session_key_packet, SessionKeyPacket):
        raise TypeError(
            f"armor() cần SessionKeyPacket, nhận phải: {type(session_key_packet)}"
        )
    if not isinstance(encrypted_data_packet, EncryptedDataPacket):
        raise TypeError(
            f"armor() cần EncryptedDataPacket, nhận phải: {type(encrypted_data_packet)}"
        )

    # Đúng nguyên văn công thức trong packet_format.md
    bytes_to_armor = serialize(session_key_packet) + serialize(encrypted_data_packet)
    armor_text = base64.b64encode(bytes_to_armor).decode("ascii")

    return PGPMessage(
        version="1.0",
        session_key_packet=session_key_packet,
        encrypted_data_packet=encrypted_data_packet,
        armor_text=armor_text,
    )


# ============================================================
# B.1 — DEARMOR (armor_text -> packet)
# ============================================================

def dearmor(armor_text: str):
    if not isinstance(armor_text, str):
        raise TypeError(f"dearmor() cần str, nhận phải: {type(armor_text)}")

    try:
        bytes_raw = base64.b64decode(armor_text.encode("ascii"))
        text = bytes_raw.decode("utf-8")
    except Exception as e:
        raise ValueError(f"dearmor(): armor_text không hợp lệ (lỗi base64/utf-8) - {e}")

    decoder = json.JSONDecoder()

    try:
        first_obj, end_idx = decoder.raw_decode(text, 0)
        start_idx = _skip_whitespace(text, end_idx)
        second_obj, _ = decoder.raw_decode(text, start_idx)
    except json.JSONDecodeError as e:
        raise ValueError(f"dearmor(): armor_text bị hỏng, không tách được 2 packet - {e}")

    session_key_packet = deserialize(json.dumps(first_obj, ensure_ascii=False).encode("utf-8"))
    encrypted_data_packet = deserialize(json.dumps(second_obj, ensure_ascii=False).encode("utf-8"))

    if not isinstance(session_key_packet, SessionKeyPacket):
        raise ValueError("dearmor(): phần đầu không phải SessionKeyPacket — dữ liệu sai định dạng")
    if not isinstance(encrypted_data_packet, EncryptedDataPacket):
        raise ValueError("dearmor(): phần sau không phải EncryptedDataPacket — dữ liệu sai định dạng")

    return session_key_packet, encrypted_data_packet


# ============================================================
# TEST NHANH — chạy trực tiếp file này để tự kiểm tra
# (python3 -m src.armor)
# ============================================================

if __name__ == "__main__":
    from src.packet_types import ALG_ASYM_RSA, ALG_SYM_AES

    sess = SessionKeyPacket(
        asym_algo=ALG_ASYM_RSA,
        recipient_key_id="B-fingerprint-123",
        encrypted_session_key=b"\x99\x88fake_encrypted_session_key",
    )
    enc = EncryptedDataPacket(
        sym_algo=ALG_SYM_AES,
        iv=b"0123456789ABCDEF",
        ciphertext=b"fake_ciphertext_data...",
    )

    # --- Test 1: armor() đúng công thức packet_format.md ---
    # Kiểm tra armor_text giải mã base64 ra phải khớp CHÍNH XÁC
    # serialize(SessionKeyPacket) + serialize(EncryptedDataPacket) —
    # đảm bảo không lệch 1 byte nào so với tài liệu gốc.
    pgp_msg = armor(sess, enc)
    expected_bytes = serialize(sess) + serialize(enc)
    assert base64.b64decode(pgp_msg.armor_text) == expected_bytes, \
        "Test 1 FAIL: armor_text khong dung cong thuc packet_format.md"
    print("Test 1 (armor() đúng công thức packet_format.md): PASS")

    # --- Test 2: armor() -> dearmor() round-trip ---
    # Ghép rồi tách lại phải ra đúng 2 packet gốc, kể cả với dữ liệu
    # nhị phân (bytes) tùy ý bên trong SessionKeyPacket/EncryptedDataPacket.
    sess_back, enc_back = dearmor(pgp_msg.armor_text)
    assert sess_back == sess, "Test 2 FAIL: SessionKeyPacket round-trip sai"
    assert enc_back == enc, "Test 2 FAIL: EncryptedDataPacket round-trip sai"
    print("Test 2 (armor/dearmor round-trip): PASS")

    # --- Test 3: armor_text bị hỏng phải báo lỗi rõ ràng, không crash ---
    # Giả lập dữ liệu bị chỉnh sửa/lỗi đường truyền (base64 không hợp lệ)
    # -> dearmor() phải raise ValueError, không được để lộ exception kỹ
    # thuật ra ngoài làm crash chương trình.
    try:
        dearmor("!!!not_a_valid_base64_@#$")
        raise AssertionError("Test 3 FAIL: khong raise loi khi armor_text hong")
    except ValueError as e:
        print("Test 3 (armor_text hỏng báo lỗi đúng cách): PASS -", e)

    print("\nOK: cả 3 test đều thành công.")