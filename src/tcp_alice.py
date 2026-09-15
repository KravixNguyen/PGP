"""
src/tcp_alice.py
CLIENT ALICE — Phía người gửi qua TCP Socket (chế độ step-by-step).

Mỗi bước A.1→A.6 sẽ dừng lại để hiển thị Input/Output trước khi tiếp tục.

Chạy:
    python -m src.tcp_alice
    python -m src.tcp_alice --host 192.168.1.10 --port 5000
"""

import sys
import socket
import argparse
import textwrap
from pathlib import Path
from Crypto.Hash import SHA256

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# Import từng bước riêng lẻ (không dùng send_message tổng hợp)
from src.sign import sign_message
from src.session_key import encrypt_session_key
from src.compressor import compress_data
from src.mdc import create_mdc
from src.aes_cipher import generate_session_key, encrypt_symmetric
from src.serializer import serialize
from src.armor import armor
from src.packet_types import EncryptedDataPacket

# ============================================================
# CẤU HÌNH
# ============================================================

BASE_DIR     = Path(__file__).parent.parent
KEYS_DIR     = BASE_DIR / "keys"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5000
LINE_WIDTH   = 64
END_MARKER   = b"<<<END>>>"

PGP_HEADER   = "-----BEGIN PGP MESSAGE-----"
PGP_FOOTER   = "-----END PGP MESSAGE-----"


# ============================================================
# HELPER HIỂN THỊ
# ============================================================

SEP = "  " + "─" * 64

def fmt_bytes(data: bytes, preview: int = 20) -> str:
    """Hiển thị bytes dạng HEX + kích thước."""
    if not data:
        return "(rỗng)"
    hex_str = data[:preview].hex().upper()
    suffix  = "..." if len(data) > preview else ""
    return f"{hex_str}{suffix}  [{len(data):,} bytes]"

def fmt_str(text: str, max_len: int = 72) -> str:
    """Hiển thị chuỗi cắt ngắn nếu dài."""
    text = text.replace("\n", "↵")
    if len(text) <= max_len:
        return text
    return text[:max_len] + f"...  [{len(text):,} ký tự]"

def step_header(step_id: str, title: str, algo: str):
    """In tiêu đề bước."""
    print()
    print(f"  ╔══════════════════════════════════════════════════════════════╗")
    print(f"  ║  Bước {step_id}  {title:<53}║")
    print(f"  ║  Thuật toán : {algo:<48}║")
    print(f"  ╚══════════════════════════════════════════════════════════════╝")
    print()

def show_input(pairs: list):
    """In danh sách (nhãn, giá trị) phần Input."""
    print("  📥 INPUT:")
    for label, val in pairs:
        print(f"     {label:<22}: {val}")
    print()

def show_output(pairs: list):
    """In danh sách (nhãn, giá trị) phần Output."""
    print("  📤 OUTPUT:")
    for label, val in pairs:
        print(f"     {label:<22}: {val}")

def wait_execute():
    """Chờ người dùng nhấn Enter để thực hiện bước."""
    print()
    input("  ▶  Nhấn Enter để THỰC HIỆN bước này ... ")
    print()

def wait_next():
    """Chờ người dùng nhấn Enter để qua bước tiếp."""
    print()
    input("  ▶  Nhấn Enter để chuyển sang bước TIẾP THEO ... ")
    print(SEP)


# ============================================================
# KEYS
# ============================================================

def load_keys():
    missing = []
    for name in ["alice_private.pem", "bob_public.pem"]:
        if not (KEYS_DIR / name).exists():
            missing.append(name)
    if missing:
        print()
        print("  [LỖI] Chưa tìm thấy file khóa:", ", ".join(missing))
        print("  Hãy chạy:  python -m src.setup_keys")
        sys.exit(1)
    alice_priv = (KEYS_DIR / "alice_private.pem").read_bytes()
    bob_pub    = (KEYS_DIR / "bob_public.pem").read_bytes()
    return alice_priv, bob_pub


def wrap_armor(armor_text: str) -> str:
    body = "\n".join(textwrap.wrap(armor_text, LINE_WIDTH))
    return f"{PGP_HEADER}\nVersion: PGP-Demo 1.0\n\n{body}\n\n{PGP_FOOTER}"


# ============================================================
# PIPELINE STEP-BY-STEP
# ============================================================

def run_pipeline(message: bytes, alice_priv: bytes, bob_pub: bytes) -> str:
    """
    Chạy toàn bộ pipeline mã hóa PGP từng bước, dừng lại ở mỗi bước
    để hiển thị Input → chờ Enter → thực hiện → hiển thị Output → chờ Enter.
    Trả về: pgp_text (chuỗi ASCII Armor hoàn chỉnh)
    """

    print()
    print(SEP)
    print("  🔐  BẮT ĐẦU MÃ HÓA PGP — 6 BƯỚC")
    print(SEP)

    # ──────────────────────────────────────────────────────────
    # BƯỚC A.1 — KÝ SỐ
    # ──────────────────────────────────────────────────────────
    step_header("A.1", "Ký số thông điệp", "SHA-256 + RSA PKCS#1 v1.5")

    msg_preview = message[:60].decode("utf-8", errors="replace")
    show_input([
        ("Nội dung gốc",    f'"{msg_preview}"'),
        ("Kích thước",      f"{len(message):,} bytes"),
        ("Khóa ký",         "alice_private.pem  (RSA-2048)"),
        ("Hash",            "SHA-256(message)  →  dùng để ký"),
    ])

    # Tính hash trước để hiển thị
    h_preview = SHA256.new(message).digest()

    wait_execute()
    print("  ⚙  Đang tính SHA-256 và ký RSA ...", end=" ", flush=True)
    sig_packet = sign_message(message, alice_priv)
    print("✔")

    show_output([
        ("SHA-256(message)",  fmt_bytes(h_preview)),
        ("Chữ ký (RSA sig)",  fmt_bytes(sig_packet.signature)),
        ("Nội dung kèm theo", f"{len(sig_packet.message):,} bytes"),
        ("Kết quả",           "SignaturePacket(message, signature)"),
    ])
    wait_next()

    # ──────────────────────────────────────────────────────────
    # BƯỚC A.2 — NÉN
    # ──────────────────────────────────────────────────────────
    step_header("A.2", "Nén dữ liệu", "ZLIB (deflate)")

    sig_bytes    = serialize(sig_packet)
    show_input([
        ("Đầu vào",          "serialize(SignaturePacket)"),
        ("Kích thước",       f"{len(sig_bytes):,} bytes"),
        ("Thuật toán",       "ZLIB deflate"),
    ])

    wait_execute()
    print("  ⚙  Đang nén ZLIB ...", end=" ", flush=True)
    comp_dict    = compress_data(sig_bytes)
    comp_data    = comp_dict["compressed_data"]
    ratio        = len(comp_data) / len(sig_bytes) * 100
    print("✔")

    show_output([
        ("Kích thước sau nén", f"{len(comp_data):,} bytes"),
        ("Tỉ lệ nén",          f"{ratio:.1f}%  (càng thấp càng tốt)"),
        ("Hex preview",         fmt_bytes(comp_data)),
    ])
    wait_next()

    # ──────────────────────────────────────────────────────────
    # BƯỚC A.3 — GẮN MDC
    # ──────────────────────────────────────────────────────────
    step_header("A.3", "Gắn MDC (Modification Detection Code)", "SHA-1(compressed_data)")

    show_input([
        ("Đầu vào",     "compressed_data"),
        ("Kích thước",  f"{len(comp_data):,} bytes"),
        ("MDC formula", "SHA-1(compressed_data)  →  20 bytes"),
    ])

    wait_execute()
    print("  ⚙  Đang tính SHA-1 MDC ...", end=" ", flush=True)
    mdc_dict     = create_mdc(comp_data)
    mdc_val      = mdc_dict["mdc_value"]
    data_mdc     = mdc_dict["data_with_mdc"]
    print("✔")

    show_output([
        ("MDC (SHA-1)",      fmt_bytes(mdc_val)),
        ("data_with_mdc",    f"compressed_data || MDC  =  {len(data_mdc):,} bytes"),
        ("Hex preview MDC",  mdc_val.hex().upper()),
        ("Mục đích",         "Bob sẽ kiểm tra lại MDC này ở bước B.4"),
    ])
    wait_next()

    # ──────────────────────────────────────────────────────────
    # BƯỚC A.4 — MÃ HÓA ĐỐI XỨNG AES
    # ──────────────────────────────────────────────────────────
    step_header("A.4", "Mã hóa đối xứng", "AES-256-CBC  (session key ngẫu nhiên)")

    session_key  = generate_session_key()
    show_input([
        ("Đầu vào",                  f"data_with_mdc  [{len(data_mdc):,} bytes]"),
        ("Session key",               fmt_bytes(session_key) + "  (ngẫu nhiên)"),
        ("Chế độ",                    "AES-256-CBC"),
        ("Initialization Vector (IV)","Ngẫu nhiên, sinh tự động"),
    ])

    wait_execute()
    print("  ⚙  Đang mã hóa AES-256-CBC ...", end=" ", flush=True)
    enc_dict     = encrypt_symmetric(data_mdc, session_key)
    iv_bytes     = enc_dict["iv"]
    ciphertext   = enc_dict["ciphertext"]
    print("✔")

    show_output([
        ("Initialization Vector (IV)", fmt_bytes(iv_bytes)),
        ("Ciphertext",                 fmt_bytes(ciphertext)),
        ("Session key",                fmt_bytes(session_key) + "  ← sẽ mã hóa ở A.5"),
    ])
    wait_next()

    # ──────────────────────────────────────────────────────────
    # BƯỚC A.5 — MÃ HÓA SESSION KEY
    # ──────────────────────────────────────────────────────────
    step_header("A.5", "Mã hóa Session Key", "RSA-OAEP  (Public Key của Bob)")

    show_input([
        ("Session key",    fmt_bytes(session_key) + "  [32 bytes]"),
        ("Public key",     "bob_public.pem  (RSA-2048)"),
        ("Thuật toán",     "RSA-OAEP (PKCS#1 v2.1)"),
        ("Mục đích",       "Chỉ Bob (có private key) mới giải mã được"),
    ])

    wait_execute()
    print("  ⚙  Đang mã hóa session key bằng RSA-OAEP ...", end=" ", flush=True)
    sess_key_pkt = encrypt_session_key(session_key, bob_pub)
    enc_sk       = sess_key_pkt.encrypted_session_key
    print("✔")

    show_output([
        ("Encrypted session key", fmt_bytes(enc_sk)),
        ("Recipient key ID",      sess_key_pkt.recipient_key_id),
        ("Kết quả",               "SessionKeyPacket  ← gửi kèm cho Bob"),
    ])
    wait_next()

    # ──────────────────────────────────────────────────────────
    # BƯỚC A.6 — ĐÓNG GÓI ASCII ARMOR
    # ──────────────────────────────────────────────────────────
    step_header("A.6", "Đóng gói ASCII Armor", "Base64 + BEGIN/END PGP MESSAGE")

    enc_data_pkt = EncryptedDataPacket(iv=iv_bytes, ciphertext=ciphertext)
    show_input([
        ("SessionKeyPacket",            f"encrypted_session_key  [{len(enc_sk):,} bytes]"),
        ("EncryptedDataPacket",          f"Initialization Vector (IV) [{len(iv_bytes)} bytes] + ciphertext [{len(ciphertext):,} bytes]"),
        ("Quy trình",                    "serialize → base64 encode → bọc BEGIN/END PGP MESSAGE"),
    ])

    wait_execute()
    print("  ⚙  Đang đóng gói ASCII Armor ...", end=" ", flush=True)
    pgp_message  = armor(sess_key_pkt, enc_data_pkt)
    pgp_text     = wrap_armor(pgp_message.armor_text)
    pgp_lines    = pgp_text.splitlines()
    print("✔")

    show_output([
        ("Định dạng",     "ASCII Armor  (PGP standard)"),
        ("Tổng dòng",     f"{len(pgp_lines)} dòng"),
        ("Kích thước",    f"{len(pgp_text.encode()):,} bytes"),
        ("Preview",       pgp_lines[0]),
        ("",              pgp_lines[1] if len(pgp_lines) > 1 else ""),
        ("",              pgp_lines[3][:60] + "..." if len(pgp_lines) > 3 else ""),
    ])

    print()
    print("  ✅  MÃ HÓA PGP HOÀN TẤT — 6/6 BƯỚC HOÀN THÀNH")
    print(SEP)

    return pgp_text


# ============================================================
# MAIN
# ============================================================

def main():
    parser = argparse.ArgumentParser(description="PGP Alice — TCP Sender (Step-by-Step)")
    parser.add_argument("--host", default=DEFAULT_HOST,
                        help=f"IP/Host của Bob (default: {DEFAULT_HOST})")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                        help=f"Port của Bob (default: {DEFAULT_PORT})")
    args = parser.parse_args()

    print()
    print("════════════════════════════════════════════════════════════════════")
    print("  CLIENT ALICE — PGP Sender  [TCP Socket | Step-by-Step Mode]")
    print("════════════════════════════════════════════════════════════════════")
    print()
    print("  Tải khóa ...", end=" ", flush=True)
    alice_priv, bob_pub = load_keys()
    print("✔")
    print()

    # ── NHẬP NỘI DUNG ──────────────────────────────────────
    print("  ┌─ Nhập nội dung muốn gửi cho Bob ──────────────────────────────")
    print("  │  (Nhấn Enter 2 lần liên tiếp trên dòng trống để kết thúc)")
    print("  └────────────────────────────────────────────────────────────────")
    print()

    lines = []
    while True:
        try:
            line = input("  > ")
        except EOFError:
            break
        if line == "" and lines and lines[-1] == "":
            lines.pop()
            break
        lines.append(line)

    if not lines:
        print("  (Không có nội dung. Thoát.)")
        sys.exit(0)

    message = "\n".join(lines).encode("utf-8")
    print()
    print(f"  Nội dung: {len(message):,} bytes")

    # ── CHẠY PIPELINE STEP-BY-STEP ─────────────────────────
    pgp_text  = run_pipeline(message, alice_priv, bob_pub)
    pgp_bytes = pgp_text.encode("utf-8")

    # ── KẾT NỐI VÀ GỬI QUA TCP ─────────────────────────────
    print()
    print(f"  ┌─ Kết nối đến Bob ──────────────────────────────────────────────")
    print(f"  │  Host : {args.host}")
    print(f"  │  Port : {args.port}")
    print(f"  └────────────────────────────────────────────────────────────────")
    print()
    print(f"  🔌 Đang kết nối ...", end=" ", flush=True)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((args.host, args.port))
        print("✔")
    except ConnectionRefusedError:
        print("✘")
        print(f"\n  [LỖI] Không thể kết nối đến {args.host}:{args.port}")
        print("  → Hãy chạy Bob trước:  python -m src.tcp_bob")
        sys.exit(1)
    except socket.timeout:
        print("✘\n  [LỖI] Timeout kết nối.")
        sys.exit(1)

    with sock:
        print(f"  ⬆  Đang gửi {len(pgp_bytes):,} bytes ...", end=" ", flush=True)
        sock.sendall(pgp_bytes + END_MARKER)
        print("✔")

        print("  ⏳ Chờ Bob xác nhận ...", end=" ", flush=True)
        try:
            sock.settimeout(600)  # 10 phút — đủ thời gian cho Bob làm step-by-step
            ack = sock.recv(1024).decode("utf-8", errors="replace")
        except socket.timeout:
            print("✘\n  [LỖI] Timeout chờ phản hồi Bob (600s).")
            sys.exit(1)

        if ack.startswith("OK"):
            print("✔")
            print()
            print("  ╔══════════════════════════════════════════════════════════════╗")
            print("  ║  ✔  GỬI THÀNH CÔNG — Bob đã nhận và xác thực tin nhắn!    ║")
            print("  ╚══════════════════════════════════════════════════════════════╝")
        else:
            print("✘")
            print(f"\n  Bob từ chối: {ack}")
            sys.exit(1)

    print()


if __name__ == "__main__":
    main()
