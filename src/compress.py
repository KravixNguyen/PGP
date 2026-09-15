# ============================================================
# Người phụ trách: Ngô Quốc Mạnh-B24DCAT178 (CORE CRYPTO)
# Module: src/compression/compress.py
#
# Phụ trách:
#   A.2 - Compressed Packet
#   B.5 - Giải nén
#
# Thuật toán:
#   ZLIB
#
# Input/Output tuân theo packet_format.md
# ============================================================

import zlib

# Mã thuật toán ZLIB theo packet_format.md
ALG_COMPRESS_ZLIB = 0x02


# ============================================================
# A.2 - NÉN DỮ LIỆU
# ============================================================

def compress_data(data):
    """
    Nén dữ liệu bằng ZLIB.

    Input:
        data: bytes

    Output:
        CompressedPacket
    """

    if not isinstance(data, bytes):
        raise TypeError("data phải là bytes")

    compressed_data = zlib.compress(data)

    return {
        "tag": "COMP",
        "compress_algo": ALG_COMPRESS_ZLIB,
        "compressed_data": compressed_data
    }


# ============================================================
# B.5 - GIẢI NÉN DỮ LIỆU
# ============================================================

def decompress_data(compressed_data):
    """
    Giải nén dữ liệu bằng ZLIB.

    Input:
        compressed_data: bytes

    Return:
        decompressed_data: bytes
    """

    if not isinstance(compressed_data, bytes):
        raise TypeError("compressed_data phải là bytes")

    decompressed_data = zlib.decompress(
        compressed_data
    )

    return decompressed_data
