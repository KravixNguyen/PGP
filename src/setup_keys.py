"""
src/setup_keys.py
Chạy 1 lần để sinh cặp khóa RSA-2048 cho Alice và Bob.
Lưu tất cả vào thư mục keys/ để Alice và Bob dùng chung.

Chạy:
    python -m src.setup_keys
"""

import sys
import os
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from src.keygen import generate_rsa_keypair


KEYS_DIR = Path(__file__).parent.parent / "keys"


def main():
    KEYS_DIR.mkdir(exist_ok=True)

    print()
    print("════════════════════════════════════════════════════════════════════")
    print("  SETUP — Sinh cặp khóa RSA-2048 cho Alice và Bob")
    print("════════════════════════════════════════════════════════════════════")
    print()

    # Sinh khóa Alice
    print("  Đang sinh khóa RSA-2048 cho Alice ...", end=" ", flush=True)
    alice_priv, alice_pub = generate_rsa_keypair(2048)
    (KEYS_DIR / "alice_private.pem").write_bytes(alice_priv)
    (KEYS_DIR / "alice_public.pem").write_bytes(alice_pub)
    print("✔")

    # Sinh khóa Bob
    print("  Đang sinh khóa RSA-2048 cho Bob   ...", end=" ", flush=True)
    bob_priv, bob_pub = generate_rsa_keypair(2048)
    (KEYS_DIR / "bob_private.pem").write_bytes(bob_priv)
    (KEYS_DIR / "bob_public.pem").write_bytes(bob_pub)
    print("✔")

    print()
    print(f"  Đã lưu khóa vào thư mục: {KEYS_DIR.resolve()}")
    print()
    print("  ┌─ Phân phối khóa (giả lập trao đổi public key trước) ────────┐")
    print("  │  Alice nhận:  keys/bob_public.pem   (để mã hóa cho Bob)      │")
    print("  │  Bob nhận:    keys/alice_public.pem  (để xác thực chữ ký)    │")
    print("  └──────────────────────────────────────────────────────────────┘")
    print()
    print("  Bước tiếp theo:")
    print("    Terminal 1 (Alice): python -m src.alice")
    print("    Terminal 2 (Bob):   python -m src.bob")
    print()


if __name__ == "__main__":
    main()
