"""
src/compressor.py
Alias module — re-export từ compress.py để khớp tên file theo README.

README yêu cầu import từ `src.compressor`, nhưng logic thực tế nằm ở
`src/compress.py`. File này chỉ re-export để không phải đổi tên file gốc.
"""

from src.compress import compress_data, decompress_data, ALG_COMPRESS_ZLIB

__all__ = ["compress_data", "decompress_data", "ALG_COMPRESS_ZLIB"]
