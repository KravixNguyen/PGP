"""
src/tcp_bob.py
CLIENT BOB — Phía người nhận qua TCP Socket.

Bob khởi động như một TCP Server, chờ Alice kết nối và gửi file .pgp.
Toàn bộ logic giải mã PGP giữ nguyên từ receiver.py.

Chạy:
    python -m src.tcp_bob
    python -m src.tcp_bob --host 0.0.0.0 --port 5000
"""

import sys
import socket
import argparse
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# Import từng bước giải mã riêng lẻ (không dùng receive_message tổng hợp)
from src.armor import dearmor
from src.session_key import decrypt_session_key
from src.aes_cipher import decrypt_symmetric
from src.mdc import verify_mdc
from src.compressor import decompress_data
from src.sign import verify_signature
from src.serializer import deserialize
from src.packet_types import SignaturePacket, VerificationResult

# ============================================================
# ĐƯỜNG DẪN & CẤU HÌNH MẶC ĐỊNH
# ============================================================

BASE_DIR  = Path(__file__).parent.parent
KEYS_DIR  = BASE_DIR / "keys"
OUT_DIR   = BASE_DIR / "shared"

DEFAULT_HOST = "0.0.0.0"   # Lắng nghe mọi interface
DEFAULT_PORT = 5000

PGP_HEADER = "-----BEGIN PGP MESSAGE-----"
PGP_FOOTER = "-----END PGP MESSAGE-----"

BUFFER_SIZE = 4096          # Bytes đọc mỗi lần recv()
END_MARKER  = b"<<<END>>>"  # Đánh dấu Alice đã gửi xong


def unwrap_armor(pgp_text: str) -> str:
    """Tách armor_text (base64 thuần) ra khỏi header/footer."""
    lines      = pgp_text.strip().splitlines()
    in_body    = False
    body_lines = []

    for line in lines:
        stripped = line.strip()
        if stripped == PGP_HEADER:
            in_body = True
            continue
        if stripped == PGP_FOOTER:
            break
        if in_body:
            if stripped == "" or (":" in stripped and len(stripped) < 60):
                continue
            body_lines.append(stripped)

    return "".join(body_lines)


def load_keys():
    """Tải khóa từ thư mục keys/."""
    missing = []
    for name in ["bob_private.pem", "alice_public.pem"]:
        if not (KEYS_DIR / name).exists():
            missing.append(name)

    if missing:
        print()
        print("  [LỖI] Chưa tìm thấy file khóa:", ", ".join(missing))
        print("  Hãy chạy:  python -m src.setup_keys")
        print()
        sys.exit(1)

    bob_priv  = (KEYS_DIR / "bob_private.pem").read_bytes()
    alice_pub = (KEYS_DIR / "alice_public.pem").read_bytes()
    return bob_priv, alice_pub


def recv_all(conn: socket.socket) -> bytes:
    """Nhận toàn bộ dữ liệu cho đến khi gặp END_MARKER."""
    chunks = []
    while True:
        chunk = conn.recv(BUFFER_SIZE)
        if not chunk:
            break
        chunks.append(chunk)
        if END_MARKER in b"".join(chunks):
            break
    data = b"".join(chunks)
    # Cắt bỏ marker
    if END_MARKER in data:
        data = data[: data.index(END_MARKER)]
    return data


# ============================================================
# HELPER HIỂN THỊ STEP-BY-STEP
# ============================================================

SEP = "  " + "─" * 64

def fmt_bytes(data: bytes, preview: int = 20) -> str:
    if not data:
        return "(rỗng)"
    hex_str = data[:preview].hex().upper()
    suffix  = "..." if len(data) > preview else ""
    return f"{hex_str}{suffix}  [{len(data):,} bytes]"

def step_header(step_id: str, title: str, algo: str):
    print()
    print(f"  ╔══════════════════════════════════════════════════════════════╗")
    print(f"  ║  Bước {step_id}  {title:<53}║")
    print(f"  ║  Thuật toán : {algo:<48}║")
    print(f"  ╚══════════════════════════════════════════════════════════════╝")
    print()

def show_input(pairs: list):
    print("  📥 INPUT:")
    for label, val in pairs:
        print(f"     {label:<22}: {val}")
    print()

def show_output(pairs: list):
    print("  📤 OUTPUT:")
    for label, val in pairs:
        print(f"     {label:<22}: {val}")

def wait_execute():
    print()
    input("  ▶  Nhấn Enter để THỰC HIỆN bước này ... ")
    print()

def wait_next():
    print()
    input("  ▶  Nhấn Enter để chuyển sang bước TIẾP THEO ... ")
    print(SEP)

def show_error_output(step_id: str, error_msg: str, extra_pairs: list = None):
    """Hiển thị Output khi bước thất bại, kèm thông tin lỗi rõ ràng."""
    pairs = [("Kết quả", f"✘ THẤT BẠI — bước {step_id} không thực hiện được")]
    if extra_pairs:
        pairs.extend(extra_pairs)
    pairs.append(("Lý do lỗi", error_msg))
    pairs.append(("Ảnh hưởng", "PGP phát hiện giả mạo — không giải mã được"))
    show_output(pairs)

def wait_fail():
    """Chờ Enter sau khi hiển thị lỗi trước khi thoát."""
    print()
    input("  ▶  Nhấn Enter để xác nhận lỗi ... ")
    print(SEP)
    print()

# ============================================================
# PIPELINE GIẢI MÃ STEP-BY-STEP
# ============================================================

def decrypt_pipeline(armor_text: str, bob_priv: bytes, alice_pub: bytes):
    """
    Giải mã PGP từng bước B.1→B.6, dừng lại ở mỗi bước để
    hiển thị Input/Output và chờ Enter.
    Returns: VerificationResult
    Raises: ValueError nếu dữ liệu hỏng.
    """
    print()
    print(SEP)
    print("  🔓  BẮT ĐẦU GIẢI MÃ PGP — 6 BƯỚC")
    print(SEP)

    # ──────────────────────────────────────────────────────────
    # BƯỚC B.1 — GIẢI RADIX-64 / DEARMOR
    # ──────────────────────────────────────────────────────────
    step_header("B.1", "Giải Radix-64 (Dearmor)", "Base64 decode + tách packet")

    armor_preview = armor_text[:60].replace("\n", "↵")
    show_input([
        ("armor_text (preview)", armor_preview + "..."),
        ("Tổng kí tự",         f"{len(armor_text):,}"),
        ("Mục tiêu",            "Tách SessionKeyPacket + EncryptedDataPacket"),
    ])

    wait_execute()
    print("  ⚙  Đang giải mã Radix-64 ...", end=" ", flush=True)
    try:
        sess_key_pkt, enc_data_pkt = dearmor(armor_text)
    except Exception as e:
        print("✘")
        # Hiển thị Output lỗi đầy đủ trước khi thoát
        show_error_output("B.1", str(e), [
            ("Dữ liệu nhận",        armor_preview[:60] + "..."),
            ("Nội dung base64",     "Không parse được thành SessionKeyPacket + EncDataPacket"),
            ("Giải thích",           "Hacker đã thay base64 hợp lệ bằng nội dung giả"),
        ])
        wait_fail()
        raise ValueError(f"dearmor() thất bại: {e}")
    print("✔")

    show_output([
        ("SessionKeyPacket",           f"encrypted_session_key  [{len(sess_key_pkt.encrypted_session_key):,} bytes]"),
        ("Recipient key ID",           sess_key_pkt.recipient_key_id),
        ("EncryptedDataPacket",        f"Initialization Vector (IV) [{len(enc_data_pkt.iv)} bytes] + ciphertext [{len(enc_data_pkt.ciphertext):,} bytes]"),
    ])
    wait_next()

    # ──────────────────────────────────────────────────────────
    # BƯỚC B.2 — GIẢI MÃ SESSION KEY
    # ──────────────────────────────────────────────────────────
    step_header("B.2", "Giải mã Session Key", "RSA-OAEP  (Private Key của Bob)")

    show_input([
        ("Encrypted session key", fmt_bytes(sess_key_pkt.encrypted_session_key)),
        ("Khóa giải mã",         "bob_private.pem  (RSA-2048)"),
        ("Thuật toán",           "RSA-OAEP (PKCS#1 v2.1)"),
        ("Mục tiêu",             "Lấy lại session key 32 bytes để giải mã AES"),
    ])

    wait_execute()
    print("  ⚙  Đang giải mã session key bằng RSA-OAEP ...", end=" ", flush=True)
    try:
        session_key = decrypt_session_key(sess_key_pkt, bob_priv)
    except Exception as e:
        print("✘")
        show_error_output("B.2", str(e), [
            ("Encrypted session key", fmt_bytes(sess_key_pkt.encrypted_session_key)),
            ("Giải thích",            "Session key bị mã hóa sai — có thể dung cho Bob sai"),
        ])
        wait_fail()
        raise ValueError(f"decrypt_session_key() thất bại: {e}")
    print("✔")

    show_output([
        ("Session key (32 bytes)", fmt_bytes(session_key)),
        ("Dạng HEX",              session_key.hex().upper()),
        ("Kết quả",              "Session key giống hệt key Alice tạo ra ở A.4"),
    ])
    wait_next()

    # ──────────────────────────────────────────────────────────
    # BƯỚC B.3 — GIẢI MÃ ĐỐI XỨNG AES
    # ──────────────────────────────────────────────────────────
    step_header("B.3", "Giải mã đối xứng", "AES-256-CBC")

    show_input([
        ("Initialization Vector (IV)", fmt_bytes(enc_data_pkt.iv)),
        ("Ciphertext",                 fmt_bytes(enc_data_pkt.ciphertext)),
        ("Session key",                fmt_bytes(session_key)),
        ("Thuật toán",               "AES-256-CBC decrypt"),
    ])

    wait_execute()
    print("  ⚙  Đang giải mã AES-256-CBC ...", end=" ", flush=True)
    enc_dict = {"iv": enc_data_pkt.iv, "ciphertext": enc_data_pkt.ciphertext}
    try:
        data_with_mdc = decrypt_symmetric(enc_dict, session_key)
    except Exception as e:
        print("✘")
        show_error_output("B.3", str(e), [
            ("Initialization Vector (IV)", fmt_bytes(enc_data_pkt.iv)),
            ("Ciphertext (preview)",       fmt_bytes(enc_data_pkt.ciphertext)),
            ("Giải thích",                "Session key hoặc IV sai — giải mã thất bại"),
        ])
        wait_fail()
        raise ValueError(f"decrypt_symmetric() thất bại: {e}")
    print("✔")

    show_output([
        ("data_with_mdc",   fmt_bytes(data_with_mdc)),
        ("Kích thước",       f"{len(data_with_mdc):,} bytes  (compressed_data || SHA-1 MDC)"),
        ("Bước tiếp",       "Kiểm tra 20 bytes cuối = SHA-1 MDC ở B.4"),
    ])
    wait_next()

    # ──────────────────────────────────────────────────────────
    # BƯỚC B.4 — KIỂM TRA MDC
    # ──────────────────────────────────────────────────────────
    step_header("B.4", "Kiểm tra MDC (toàn vẹn dữ liệu)", "SHA-1 integrity check")

    # MDC = 20 bytes cuối cùng
    stored_mdc = data_with_mdc[-20:]
    show_input([
        ("data_with_mdc",    fmt_bytes(data_with_mdc)),
        ("MDC lưu trữ",      stored_mdc.hex().upper() + "  [20 bytes cuối]"),
        ("Công thức kiểm",  "SHA-1(compressed_data) phải == MDC lưu trữ"),
    ])

    wait_execute()
    print("  ⚙  Đang kiểm tra SHA-1 MDC ...", end=" ", flush=True)
    mdc_result = verify_mdc(data_with_mdc)
    if not mdc_result["is_valid"]:
        print("✘")
        show_error_output("B.4", "SHA-1(data) không khớp với MDC được gắn kèm", [
            ("MDC lưu trữ (Alice gửi)",  stored_mdc.hex().upper()),
            ("SHA-1 tính lại (Bob)",       "Không khớp — data bị đổi trước khi mã hóa AES"),
            ("Giải thích",                 "Hacker đã sửa nội dung của giao dịch"),
        ])
        wait_fail()
        raise ValueError("MDC check FAIL: dữ liệu bị chỉnh sửa trong quá trình truyền!")

    comp_data = mdc_result["computed_mdc"] if "computed_mdc" in mdc_result else b""
    print("✔")

    compressed_data = mdc_result["compressed_data"]
    show_output([
        ("MDC lưu trữ",    stored_mdc.hex().upper()),
        ("Kết quả",        "✔ HỢP LỆ — dữ liệu nguyên vẹn"),
        ("compressed_data",  fmt_bytes(compressed_data)),
    ])
    wait_next()

    # ──────────────────────────────────────────────────────────
    # BƯỚC B.5 — GIẢI NÉN
    # ──────────────────────────────────────────────────────────
    step_header("B.5", "Giải nén", "ZLIB inflate")

    show_input([
        ("compressed_data",  fmt_bytes(compressed_data)),
        ("Kích thước",       f"{len(compressed_data):,} bytes"),
        ("Thuật toán",       "ZLIB inflate  (ngược lại ZLIB deflate ở A.2)"),
    ])

    wait_execute()
    print("  ⚙  Đang giải nén ZLIB ...", end=" ", flush=True)
    try:
        decompressed = decompress_data(compressed_data)
    except Exception as e:
        print("✘")
        show_error_output("B.5", str(e), [
            ("compressed_data",  fmt_bytes(compressed_data)),
            ("Giải thích",        "Dữ liệu không phải định dạng ZLIB hợp lệ"),
        ])
        wait_fail()
        raise ValueError(f"decompress_data() thất bại: {e}")
    print("✔")

    show_output([
        ("Kích thước gốc",    f"{len(decompressed):,} bytes"),
        ("Hex preview",        fmt_bytes(decompressed)),
        ("Nội dung",          "serialized SignaturePacket (message + chữ ký)"),
    ])
    wait_next()

    # ──────────────────────────────────────────────────────────
    # BƯỚC B.6 — XÁC THỰC CHỮ KÝ
    # ──────────────────────────────────────────────────────────
    step_header("B.6", "Xác thực chữ ký", "RSA PKCS#1 v1.5 + SHA-256  (Public Key Alice)")

    sig_packet = deserialize(decompressed)
    if not isinstance(sig_packet, SignaturePacket):
        raise ValueError("Dữ liệu giải nén không phải SignaturePacket hợp lệ.")

    original_msg = sig_packet.message
    msg_preview  = original_msg[:60].decode("utf-8", errors="replace")

    show_input([
        ("Message (plaintext)", f'"{msg_preview}"  [{len(original_msg):,} bytes]'),
        ("Chữ ký (RSA sig)",    fmt_bytes(sig_packet.signature)),
        ("Khóa xác thực",      "alice_public.pem  (RSA-2048)"),
        ("Thuật toán",         "SHA-256(message) rồi verify với RSA"),
    ])

    wait_execute()
    print("  ⚙  Đang xác thực chữ ký RSA ...", end=" ", flush=True)
    result = verify_signature(original_msg, alice_pub, sig_packet)
    print("✔")

    if result.is_authentic:
        show_output([
            ("Kết quả",          "✔ CHỮ KÝ HỢP LỆ — tin nhắn xác thực từ Alice"),
            ("Message khôi phục",  f'"{msg_preview}"'),
            ("Kích thước",          f"{len(original_msg):,} bytes"),
        ])
    else:
        show_error_output("B.6", "RSA verify: chữ ký không khớp với public key của Alice", [
            ("Message (plaintext)",  f'"{msg_preview}"  [{len(original_msg):,} bytes]'),
            ("Chữ ký (RSA sig)",     fmt_bytes(sig_packet.signature)),
            ("Giải thích",           "Hacker không có private key Alice — không tạo được chữ ký hợp lệ"),
        ])
        wait_fail()

    print()
    print("  ✅  GIẢI MÃ PGP HOÀN TẤT — 6/6 BƯỚC HOÀN THÀNH")
    print(SEP)


    return result

def main():
    parser = argparse.ArgumentParser(description="PGP Bob — TCP Receiver")
    parser.add_argument("--host", default=DEFAULT_HOST,
                        help=f"Host lắng nghe (default: {DEFAULT_HOST})")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                        help=f"Port lắng nghe (default: {DEFAULT_PORT})")
    args = parser.parse_args()

    OUT_DIR.mkdir(exist_ok=True)

    print()
    print("════════════════════════════════════════════════════════════════════")
    print("  CLIENT BOB — PGP Receiver  [TCP Socket Mode]")
    print("════════════════════════════════════════════════════════════════════")
    print()
    print("  Tải khóa ...", end=" ", flush=True)
    bob_priv, alice_pub = load_keys()
    print("✔")
    print()

    # ── TẠO TCP SERVER ──────────────────────────────────────
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((args.host, args.port))
    server_sock.listen(1)

    print("  ┌─ Đang lắng nghe ────────────────────────────────────────────────")
    print(f"  │  Host : {args.host}")
    print(f"  │  Port : {args.port}")
    print("  └────────────────────────────────────────────────────────────────")
    print()
    print("  ⏳ Chạy liên tục — Ctrl+C để tắt server")
    print()

    conn_count = 0
    while True:
        try:
            print(f"  [{conn_count + 1}] Đang chờ kết nối từ Alice ...")
            conn, addr = server_sock.accept()
        except KeyboardInterrupt:
            print("\n\n  Server đã tắt. Tạm biệt!")
            server_sock.close()
            sys.exit(0)

        conn_count += 1
        handle_connection(conn, addr, bob_priv, alice_pub, OUT_DIR)
        print()
        print("  ─────────────────────────────────────────────────────────────────")
        print()


def handle_connection(conn: socket.socket, addr, bob_priv: bytes, alice_pub: bytes, out_dir: Path):
    """Xử lý một kết nối từ Alice (hoặc Hacker MITM)."""
    with conn:
        client_ip, client_port = addr
        print(f"  ✔  Kết nối từ {client_ip}:{client_port}")
        print()

        # ── NHẬN DỮ LIỆU ────────────────────────────────────
        print("  ⬇  Đang nhận dữ liệu PGP ...", end=" ", flush=True)
        raw_data = recv_all(conn)
        pgp_text = raw_data.decode("utf-8")
        print(f"✔  ({len(raw_data):,} bytes)")
        print()

        # Lưu file .pgp nhận được
        pgp_file = out_dir / "message.pgp"
        pgp_file.write_text(pgp_text, encoding="utf-8")

        # Preview
        pgp_lines = pgp_text.splitlines()
        print("  ┌─ Nội dung file .pgp nhận được ─────────────────────────────────")
        for ln in pgp_lines[:7]:
            print(f"  │  {ln}")
        if len(pgp_lines) > 7:
            print(f"  │  ... ({len(pgp_lines)} dòng tổng cộng)")
        print("  └────────────────────────────────────────────────────────────────")

        # ── GIẢI MÃ STEP-BY-STEP ─────────────────────────────
        armor_text = unwrap_armor(pgp_text)
        if not armor_text:
            conn.sendall(b"ERROR: Invalid PGP format")
            print()
            print("  [LỖI] Không tách được base64 từ dữ liệu nhận được.")
            return

        try:
            result = decrypt_pipeline(armor_text, bob_priv, alice_pub)
        except ValueError as e:
            try:
                conn.sendall(b"ERROR: " + str(e).encode())
            except (ConnectionAbortedError, BrokenPipeError, OSError):
                print("  ⚠  Không thể gửi lỗi về Alice/Hacker — kết nối đã đóng.")
            print()
            print("  ╔══════════════════════════════════════════════════════════════╗")
            print("  ║  CẢNH BÁO: DỮ LIỆU BỊ CHỈNH SỬA / FILE HỎNG              ║")
            print("  ╚══════════════════════════════════════════════════════════════╝")
            print()
            print(f"  Chi tiết lỗi: {e}")
            return

        # ── KẾT QUẢ ─────────────────────────────────────────
        if result.is_authentic:
            print()
            print("  ╔══════════════════════════════════════════════════════════════╗")
            print("  ║  ✔  XÁC THỰC THÀNH CÔNG — Tin nhắn hợp lệ từ Alice        ║")
            print("  ╚══════════════════════════════════════════════════════════════╝")
            print()

            recovered = result.message.decode("utf-8", errors="replace")

            print("  ┌─ Nội dung file Alice gửi ──────────────────────────────────────")
            for ln in recovered.splitlines():
                print(f"  │  {ln}")
            print("  └────────────────────────────────────────────────────────────────")
            print()

            out_plain = out_dir / "message_decrypted.txt"
            out_plain.write_text(recovered, encoding="utf-8")
            print(f"  Đã lưu: {out_plain.resolve()}")
            print()

            try:
                conn.sendall(b"OK: Message received and verified successfully")
            except (ConnectionAbortedError, BrokenPipeError, OSError):
                print("  ⚠  Alice đã đóng kết nối trước khi nhận ACK (có thể do timeout phía Alice).")

        else:
            try:
                conn.sendall(b"ERROR: Signature verification failed")
            except (ConnectionAbortedError, BrokenPipeError, OSError):
                pass
            print()
            print("  ╔══════════════════════════════════════════════════════════════╗")
            print("  ║  ✘  XÁC THỰC THẤT BẠI — Chữ ký không hợp lệ!             ║")
            print("  ╚══════════════════════════════════════════════════════════════╝")


if __name__ == "__main__":
    main()
