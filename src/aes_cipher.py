"""
src/aes_cipher.py
Alias module — re-export từ crypto_symmetric/aes.py để khớp tên file theo README.

README yêu cầu import từ `src.aes_cipher`, nhưng logic thực tế nằm ở
`src/crypto_symmetric/aes.py`. File này chỉ re-export để không phải đổi cấu trúc.
"""

from src.crypto_symmetric.aes import (
    generate_session_key,
    encrypt_symmetric,
    decrypt_symmetric,
    ALG_SYM_AES,
)

__all__ = [
    "generate_session_key",
    "encrypt_symmetric",
    "decrypt_symmetric",
    "ALG_SYM_AES",
]
