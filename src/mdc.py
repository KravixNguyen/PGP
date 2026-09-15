# ============================================================
# Người phụ trách: Ngô Quốc Mạnh-B24DCAT178 (CORE CRYPTO)
# Module: src/mdc/mdc.py
#
# Phụ trách:
#   A.3 - Tạo MDC
#   B.4 - Kiểm tra MDC
#
# Thuật toán:
#   SHA-1
#
# Input/Output tuân theo packet_format.md
# ============================================================

import hashlib

# Mã SHA-1 theo packet_format.md
ALG_HASH_SHA1 = 0x02


# ============================================================
# A.3 - TẠO MDC
# ============================================================

def create_mdc(compressed_data):
    """
    Tạo MDC bằng SHA-1 trên compressed_data.

    MDC = SHA1(compressed_data)

    Output:
        MDCPacket
    """

    if not isinstance(compressed_data, bytes):
        raise TypeError("compressed_data phải là bytes")

    # SHA-1 tạo ra 20 bytes
    mdc_value = hashlib.sha1(
        compressed_data
    ).digest()

    # Ghép compressed_data + MDC
    data_with_mdc = (
        compressed_data +
        mdc_value
    )

    return {
        "tag": "MDC",
        "mdc_hash_algo": ALG_HASH_SHA1,
        "mdc_value": mdc_value,
        "data_with_mdc": data_with_mdc
    }


# ============================================================
# B.4 - KIỂM TRA MDC
# ============================================================

def verify_mdc(data_with_mdc):
    """
    Kiểm tra MDC.

    20 bytes cuối là MDC đã nhận.
    Phần còn lại là compressed_data.

    Output:
        MDCCheckResult
    """

    if not isinstance(data_with_mdc, bytes):
        raise TypeError("data_with_mdc phải là bytes")

    # SHA-1 có độ dài 20 bytes
    if len(data_with_mdc) < 20:
        return {
            "tag": "MDC_CHECK",
            "is_valid": False,
            "compressed_data": b""
        }

    # Tách compressed_data và MDC
    compressed_data = data_with_mdc[:-20]
    mdc_received = data_with_mdc[-20:]

    # Tính lại MDC
    mdc_calculated = hashlib.sha1(
        compressed_data
    ).digest()

    # So sánh
    is_valid = (
        mdc_received == mdc_calculated
    )

    return {
        "tag": "MDC_CHECK",
        "is_valid": is_valid,
        "compressed_data": (
            compressed_data
            if is_valid
            else b""
        )
    }
