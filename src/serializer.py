"""
src/serializer.py
Người phụ trách: Nguyễn Hải Long

Cung cấp 2 hàm dùng chung toàn dự án để chuyển đổi packet (dataclass)
<-> bytes. Mọi module khác PHẢI dùng serialize()/deserialize() ở đây,
không được tự viết lại logic riêng (theo quy ước README mục 4).

Cách hoạt động:
    1. dataclass -> dict (duyệt các field bằng dataclasses.fields)
    2. Các field kiểu bytes (khai báo trong packet_types.BYTES_FIELDS)
       được encode sang base64 str để có thể đưa vào JSON.
    3. Field nào là 1 packet lồng bên trong (vd PGPMessage chứa
       SessionKeyPacket, EncryptedDataPacket) cũng được xử lý đệ quy.
    4. Hỗ trợ đệ quy cho các list chứa packet con hoặc chuỗi bytes.
    5. dict cuối cùng -> JSON string -> encode utf-8 -> bytes.
    Deserialize làm ngược lại, dựa vào field "__class__" trong dữ liệu để
    tra PACKET_CLASSES và biết dựng lại đúng loại dataclass.
"""

import json
import base64
import dataclasses

from src.packet_types import PACKET_CLASSES, BYTES_FIELDS


# ============================================================
# SERIALIZE — packet (dataclass) -> bytes
# ============================================================

def _packet_to_dict(packet) -> dict:
    """
    Chuyển 1 dataclass packet thành dict thuần, xử lý:
    - field bytes -> base64 str
    - field là packet lồng bên trong (dataclass khác) -> đệ quy thành dict
    - field là list -> duyệt từng phần tử để đệ quy hoặc encode base64
    """
    if not dataclasses.is_dataclass(packet):
        raise TypeError(
            f"serialize() chỉ nhận dataclass packet, nhận phải: {type(packet)}"
        )

    class_name = type(packet).__name__
    bytes_fields = BYTES_FIELDS.get(class_name, [])

    result = {}

    for f in dataclasses.fields(packet):
        value = getattr(packet, f.name)

        if dataclasses.is_dataclass(value):
            # packet lồng bên trong
            result[f.name] = _packet_to_dict(value)

        elif isinstance(value, list):
            # Xử lý list chứa dataclass hoặc bytes
            result[f.name] = [
                _packet_to_dict(item) if dataclasses.is_dataclass(item)
                else (base64.b64encode(item).decode("ascii") if isinstance(item, (bytes, bytearray)) else item)
                for item in value
            ]

        elif f.name in bytes_fields and isinstance(value, (bytes, bytearray)):
            result[f.name] = base64.b64encode(value).decode("ascii")

        else:
            result[f.name] = value

    # Đánh dấu rõ class gốc để deserialize() dựng lại đúng kiểu
    result["__class__"] = class_name

    return result


def serialize(packet) -> bytes:
    """
    Input:  packet (1 trong các dataclass định nghĩa ở packet_types.py)
    Output: bytes  (JSON, utf-8 encoded)
    """
    as_dict = _packet_to_dict(packet)
    json_str = json.dumps(as_dict, ensure_ascii=False)

    return json_str.encode("utf-8")


# ============================================================
# DESERIALIZE — bytes -> packet (dataclass)
# ============================================================

def _dict_to_packet(data: dict):
    """
    Dựng lại 1 dataclass từ dict, dựa vào key "__class__" để tra
    PACKET_CLASSES. Xử lý đệ quy cho packet lồng nhau và các list.
    """
    class_name = data.get("__class__")

    if class_name not in PACKET_CLASSES:
        raise ValueError(
            f"deserialize(): không nhận diện được class '{class_name}'"
        )

    packet_cls = PACKET_CLASSES[class_name]
    bytes_fields = BYTES_FIELDS.get(class_name, [])

    kwargs = {}

    for key, value in data.items():
        if key == "__class__":
            continue

        if isinstance(value, dict) and "__class__" in value:
            # field là packet lồng bên trong -> đệ quy dựng lại
            kwargs[key] = _dict_to_packet(value)

        elif isinstance(value, list):
            # field là một list -> duyệt để dựng lại dataclass hoặc decode bytes
            parsed_list = []
            for item in value:
                if isinstance(item, dict) and "__class__" in item:
                    parsed_list.append(_dict_to_packet(item))
                elif key in bytes_fields and isinstance(item, str):
                    parsed_list.append(base64.b64decode(item.encode("ascii")))
                else:
                    parsed_list.append(item)
            kwargs[key] = parsed_list

        elif key in bytes_fields and isinstance(value, str):
            kwargs[key] = base64.b64decode(value.encode("ascii"))

        else:
            kwargs[key] = value

    return packet_cls(**kwargs)


def deserialize(data: bytes):
    """
    Input:  data: bytes (JSON, utf-8 — kết quả từ serialize())
    Output: packet (dataclass tương ứng, tự nhận diện qua "__class__")
    """
    try:
        json_str = data.decode("utf-8")
        as_dict = json.loads(json_str)

        if not isinstance(as_dict, dict):
            raise ValueError("Dữ liệu giải mã không phải là một object (dict).")

        return _dict_to_packet(as_dict)

    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ValueError(f"deserialize(): Gói tin bị hỏng hoặc sai định dạng - {e}")


# ============================================================
# TEST NHANH — chạy trực tiếp file này để tự kiểm tra
# (python3 -m src.serializer)
# ============================================================

if __name__ == "__main__":
    from src.packet_types import SignaturePacket, PGPMessage, SessionKeyPacket, EncryptedDataPacket

    # --- Test 1: Round-trip packet đơn giản ---
    # Kiểm tra serialize() rồi deserialize() lại phải ra đúng packet ban đầu,
    # bao gồm cả field kiểu bytes (signature, message) được encode/decode
    # base64 đúng cách.
    pkt1 = SignaturePacket(signature=b"\x01\x02fake_sig", message=b"Hello PGP demo!")
    result1 = deserialize(serialize(pkt1))
    assert result1 == pkt1, "Test 1 FAIL: round-trip packet don gian sai"
    print("Test 1 (round-trip packet đơn giản): PASS")

    # --- Test 2: Round-trip packet lồng nhau ---
    # PGPMessage chứa 2 packet con (SessionKeyPacket, EncryptedDataPacket).
    # Đây là case quan trọng nhất vì phải đệ quy đúng ở cả serialize
    # và deserialize, không được làm phẳng (flatten) sai cấu trúc.
    sess = SessionKeyPacket(recipient_key_id="B-fingerprint-123", encrypted_session_key=b"\x99\x88seckey")
    enc = EncryptedDataPacket(iv=b"0123456789ABCDEF", ciphertext=b"ciphertextdata")
    pkt2 = PGPMessage(session_key_packet=sess, encrypted_data_packet=enc, armor_text="dummy")
    result2 = deserialize(serialize(pkt2))
    assert result2 == pkt2, "Test 2 FAIL: round-trip packet long nhau sai"
    assert isinstance(result2.session_key_packet, SessionKeyPacket), "Test 2 FAIL: field long sai kieu"
    print("Test 2 (round-trip packet lồng nhau): PASS")

    # --- Test 3: Dữ liệu hỏng phải báo lỗi rõ ràng, không crash ---
    # deserialize() nhận bytes không phải JSON hợp lệ -> phải raise
    # ValueError (đã được bọc trong try/except), không được để lộ
    # exception kỹ thuật (JSONDecodeError) ra ngoài làm crash chương trình.
    try:
        deserialize(b"day khong phai JSON hop le {{{")
        raise AssertionError("Test 3 FAIL: khong raise loi khi du lieu hong")
    except ValueError as e:
        print("Test 3 (dữ liệu hỏng báo lỗi đúng cách): PASS -", e)

    print("\nOK: cả 3 test đều thành công.")