"""
src/tcp_hacker.py
HACKER — Man-in-the-Middle (MITM) Proxy.

Ba kịch bản tấn công:
  [1] Chuyển tiếp nguyên bản          → Bob thành công (baseline)
  [2] Thay payload bằng JSON giả       → Bob thất bại tại B.1 (dearmor)
  [3] Giả mạo PGP hoàn chỉnh          → Bob qua B.1-B.5, thất bại tại B.6 (chữ ký)
      (Hacker biết format + có bob_public.pem, nhưng không có alice_private.pem)

Chạy (từ thư mục gốc dự án):
    1. python -m src.tcp_bob
    2. python -m src.tcp_hacker
    3. python -m src.tcp_alice --host 127.0.0.1 --port 5001
"""

import sys
import os
import socket
import base64
import textwrap
from pathlib import Path
from typing import Tuple

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# ============================================================
# CẤU HÌNH
# ============================================================

HACKER_HOST  = "0.0.0.0"
HACKER_PORT  = 5001
BOB_HOST     = "127.0.0.1"
BOB_PORT     = 5000
BUFFER_SIZE  = 4096
END_MARKER   = b"<<<END>>>"
PGP_HEADER   = "-----BEGIN PGP MESSAGE-----"
PGP_FOOTER   = "-----END PGP MESSAGE-----"
LINE_WIDTH   = 64

BASE_DIR     = Path(__file__).parent.parent
KEYS_DIR     = BASE_DIR / "keys"


# ============================================================
# HELPER MẠNG
# ============================================================

def recv_all(conn: socket.socket) -> bytes:
    chunks = []
    while True:
        chunk = conn.recv(BUFFER_SIZE)
        if not chunk:
            break
        chunks.append(chunk)
        if END_MARKER in b"".join(chunks):
            break
    data = b"".join(chunks)
    if END_MARKER in data:
        data = data[: data.index(END_MARKER)]
    return data


# ============================================================
# HELPER PGP ARMOR
# ============================================================

def extract_armor_body(pgp_text: str) -> Tuple[str, str]:
    lines, header_lines, body_lines = pgp_text.strip().splitlines(), [], []
    in_body = False
    for line in lines:
        s = line.strip()
        if s == PGP_HEADER:
            header_lines.append(line); in_body = True; continue
        if s == PGP_FOOTER:
            break
        if in_body:
            if s == "" or (":" in s and len(s) < 60):
                header_lines.append(line); continue
            body_lines.append(s)
    return "\n".join(header_lines), "".join(body_lines)


def rebuild_pgp(header_block: str, new_body_b64: str) -> str:
    body_wrapped = "\n".join(textwrap.wrap(new_body_b64, LINE_WIDTH))
    return f"{header_block}\n\n{body_wrapped}\n\n{PGP_FOOTER}"


def wrap_armor(armor_text: str) -> str:
    body = "\n".join(textwrap.wrap(armor_text, LINE_WIDTH))
    return f"{PGP_HEADER}\nVersion: PGP-Demo 1.0\n\n{body}\n\n{PGP_FOOTER}"


# ============================================================
# KỊCH BẢN 1 — CHUYỂN TIẾP NGUYÊN BẢN
# ============================================================

def attack_passthrough(pgp_text: str) -> str:
    """Không sửa gì, forward nguyên bản."""
    print()
    print("  [Hacker] Không sửa gì, chuyển tiếp nguyên bản ...")
    return pgp_text


# ============================================================
# KỊCH BẢN 2 — THAY PAYLOAD BẰNG JSON GIẢ
# ============================================================

def attack_replace_content(pgp_text: str, hacker_message: str) -> str:
    """
    Thay toàn bộ base64 body bằng JSON giả.
    → Bob thất bại ngay tại B.1 vì không parse được cấu trúc PGP.
    """
    header_block, _ = extract_armor_body(pgp_text)
    fake_payload = (
        f'{{"hacked": true, "fake_message": "{hacker_message}", '
        f'"note": "NOT a valid PGP packet — injected by Hacker!"}}'
    )
    fake_b64 = base64.b64encode(fake_payload.encode("utf-8")).decode("ascii")

    print()
    print(f"  [Hacker] Thay body base64 bằng JSON giả: \"{hacker_message}\"")
    print("  [Hacker] Bob sẽ thất bại tại B.1 — dearmor() không parse được!")
    return rebuild_pgp(header_block, fake_b64)


# ============================================================
# KỊCH BẢN 3 — GIẢ MẠO PGP HOÀN CHỈNH (THẤT BẠI TẠI B.6)
# ============================================================

def attack_forge_full_pgp(hacker_message: str, bob_pub_key: bytes) -> str:
    """
    Hacker biết toàn bộ format PGP + có Bob's public key.
    Xây dựng gói PGP HỢP LỆ hoàn toàn về mặt cấu trúc với nội dung giả,
    nhưng ký bằng BYTES NGẪU NHIÊN (không có alice_private.pem).

    Kết quả: Bob qua được B.1 → B.2 → B.3 → B.4 → B.5
             nhưng thất bại tại B.6 vì chữ ký RSA sai.
    """
    # Import pipeline PGP (hacker "biết" và cài đặt lại)
    try:
        from src.packet_types import (SignaturePacket, EncryptedDataPacket,
                                      ALG_HASH_SHA256, ALG_SIGN_RSA)
        from src.compressor import compress_data
        from src.mdc import create_mdc
        from src.aes_cipher import generate_session_key, encrypt_symmetric
        from src.session_key import encrypt_session_key
        from src.serializer import serialize
        from src.armor import armor as pgp_armor
    except ImportError:
        from packet_types import (SignaturePacket, EncryptedDataPacket,
                                   ALG_HASH_SHA256, ALG_SIGN_RSA)
        from compressor import compress_data
        from mdc import create_mdc
        from aes_cipher import generate_session_key, encrypt_symmetric
        from session_key import encrypt_session_key
        from serializer import serialize
        from armor import armor as pgp_armor

    msg_bytes = hacker_message.encode("utf-8")

    print()
    print("  ╔══════════════════════════════════════════════════════════════╗")
    print("  ║  [Hacker] Xây dựng gói PGP giả hoàn chỉnh...              ║")
    print("  ╚══════════════════════════════════════════════════════════════╝")
    print()

    # ── BƯỚC GIẢ A.1: Tạo SignaturePacket với CHỮ KÝ NGẪU NHIÊN ──
    print("  [A.1] Tạo chữ ký GIẢ (256 bytes ngẫu nhiên — không phải RSA Alice) ...", end=" ", flush=True)
    fake_signature = os.urandom(256)   # ← không phải RSA, chỉ là random bytes
    fake_sig_packet = SignaturePacket(
        hash_algo  = ALG_HASH_SHA256,
        sign_algo  = ALG_SIGN_RSA,
        signature  = fake_signature,
        message    = msg_bytes,
    )
    print("✔")
    print(f"     Nội dung giả : \"{hacker_message}\"")
    print(f"     Chữ ký ngẫu nhiên : {fake_signature[:12].hex().upper()}... [256 bytes]")

    # ── BƯỚC GIẢ A.2: Nén ZLIB ──────────────────────────────────
    print("  [A.2] Nén ZLIB (serialize SignaturePacket → compress) ...", end=" ", flush=True)
    sig_bytes   = serialize(fake_sig_packet)
    comp_dict   = compress_data(sig_bytes)
    comp_data   = comp_dict["compressed_data"]
    ratio       = len(comp_data) / len(sig_bytes) * 100
    print(f"✔  ({len(comp_data):,} bytes, {ratio:.0f}%)")

    # ── BƯỚC GIẢ A.3: Tính MDC ──────────────────────────────────
    print("  [A.3] Tính SHA-1 MDC ...", end=" ", flush=True)
    mdc_dict    = create_mdc(comp_data)
    data_mdc    = mdc_dict["data_with_mdc"]
    mdc_val     = mdc_dict["mdc_value"]
    print(f"✔  MDC = {mdc_val.hex().upper()[:20]}...")

    # ── BƯỚC GIẢ A.4: Mã hóa AES ────────────────────────────────
    print("  [A.4] Mã hóa AES-256-CBC với session key mới ...", end=" ", flush=True)
    session_key = generate_session_key()
    enc_dict    = encrypt_symmetric(data_mdc, session_key)
    iv_bytes    = enc_dict["iv"]
    ciphertext  = enc_dict["ciphertext"]
    print(f"✔  ({len(ciphertext):,} bytes ciphertext)")

    # ── BƯỚC GIẢ A.5: Mã hóa session key bằng BOB'S PUBLIC KEY ─
    print("  [A.5] Mã hóa session key bằng bob_public.pem (RSA-OAEP) ...", end=" ", flush=True)
    sess_key_pkt = encrypt_session_key(session_key, bob_pub_key)
    enc_sk       = sess_key_pkt.encrypted_session_key
    print(f"✔  ({len(enc_sk):,} bytes)")

    # ── BƯỚC GIẢ A.6: Đóng gói Armor ───────────────────────────
    print("  [A.6] Đóng gói ASCII Armor ...", end=" ", flush=True)
    enc_data_pkt = EncryptedDataPacket(iv=iv_bytes, ciphertext=ciphertext)
    pgp_msg      = pgp_armor(sess_key_pkt, enc_data_pkt)
    forged_pgp   = wrap_armor(pgp_msg.armor_text)
    forged_lines = forged_pgp.splitlines()
    print(f"✔  ({len(forged_lines)} dòng)")

    print()
    print("  ┌─ Dự đoán kết quả tại Bob ──────────────────────────────────────")
    print("  │  B.1 ✔ dearmor()           — cấu trúc JSON hợp lệ")
    print("  │  B.2 ✔ RSA decrypt key     — session key được mã hóa đúng bằng bob_pub")
    print("  │  B.3 ✔ AES decrypt         — AES CBC hợp lệ")
    print("  │  B.4 ✔ MDC check           — SHA-1 khớp (hacker tính đúng)")
    print("  │  B.5 ✔ ZLIB decompress     — nén hợp lệ")
    print("  │  B.6 ✘ Verify signature    — chữ ký ngẫu nhiên ≠ RSA(alice_private)")
    print("  └────────────────────────────────────────────────────────────────")

    return forged_pgp


# ============================================================
# XỬ LÝ 1 KẾT NỐI
# ============================================================

def handle_connection(alice_conn: socket.socket, alice_addr,
                      choice: str, hacker_message: str, bob_pub_key: bytes):
    with alice_conn:
        client_ip, client_port = alice_addr
        print(f"  ✔  Alice đã kết nối từ {client_ip}:{client_port}")
        print()

        # ── NHẬN TỪ ALICE ───────────────────────────────────
        print("  ⬇  Chặn gói tin từ Alice ...", end=" ", flush=True)
        raw_data = recv_all(alice_conn)
        pgp_text = raw_data.decode("utf-8")
        print(f"✔  ({len(raw_data):,} bytes nhận được)")

        pgp_lines = pgp_text.splitlines()
        print()
        print("  ┌─ Gói tin PGP gốc của Alice (Hacker đọc được) ──────────────────")
        for ln in pgp_lines[:7]:
            print(f"  │  {ln}")
        if len(pgp_lines) > 7:
            print(f"  │  ... ({len(pgp_lines)} dòng)")
        print("  └────────────────────────────────────────────────────────────────")
        print()

        # ── ÁP DỤNG TẤN CÔNG ────────────────────────────────
        print("  ╔══════════════════════════════════════════════════════════════╗")
        if choice == "1":
            print("  ║  Kịch bản 1: CHUYỂN TIẾP NGUYÊN BẢN                       ║")
        elif choice == "2":
            print("  ║  Kịch bản 2: THAY PAYLOAD BẰNG JSON GIẢ (thất bại B.1)   ║")
        else:
            print("  ║  Kịch bản 3: GIẢ MẠO PGP HOÀN CHỈNH (thất bại B.6)      ║")
        print("  ╚══════════════════════════════════════════════════════════════╝")

        if choice == "1":
            modified_pgp = attack_passthrough(pgp_text)
        elif choice == "2":
            modified_pgp = attack_replace_content(pgp_text, hacker_message)
        else:
            modified_pgp = attack_forge_full_pgp(hacker_message, bob_pub_key)

        # Preview gói tin sau khi sửa (kịch bản 2 và 3)
        if choice in ("2", "3"):
            mod_lines = modified_pgp.splitlines()
            print()
            print("  ┌─ Gói tin PGP GIẢ gửi cho Bob ─────────────────────────────────")
            for ln in mod_lines[:7]:
                print(f"  │  {ln}")
            if len(mod_lines) > 7:
                print(f"  │  ... ({len(mod_lines)} dòng)")
            print("  └────────────────────────────────────────────────────────────────")

        # ── FORWARD ĐẾN BOB ──────────────────────────────────
        print()
        print(f"  ➡  Chuyển tiếp đến Bob ({BOB_HOST}:{BOB_PORT}) ...", end=" ", flush=True)

        try:
            bob_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            bob_sock.settimeout(10)
            bob_sock.connect((BOB_HOST, BOB_PORT))
        except ConnectionRefusedError:
            print("✘")
            print(f"  [LỖI] Không kết nối được đến Bob tại {BOB_HOST}:{BOB_PORT}")
            alice_conn.sendall(b"ERROR: Bob unreachable")
            return

        print("✔")

        with bob_sock:
            modified_bytes = modified_pgp.encode("utf-8")
            bob_sock.sendall(modified_bytes + END_MARKER)
            print(f"  ✉  Đã gửi {len(modified_bytes):,} bytes đến Bob")

            print("  ⏳ Chờ Bob phản hồi ... (Bob đang làm step-by-step)", flush=True)
            try:
                bob_sock.settimeout(600)
                bob_response = bob_sock.recv(1024)
            except socket.timeout:
                bob_response = b"ERROR: Bob timeout"

            bob_msg = bob_response.decode("utf-8", errors="replace")
            print()

            print("  ╔══════════════════════════════════════════════════════════════╗")
            if bob_msg.startswith("OK"):
                print("  ║  Bob phản hồi: THÀNH CÔNG ✔                                 ║")
                print("  ╚══════════════════════════════════════════════════════════════╝")
                print()
                print("  → Bob chấp nhận tin nhắn (Kịch bản 1: pass-through).")
            else:
                print("  ║  Bob phản hồi: THẤT BẠI ✘                                  ║")
                print("  ╚══════════════════════════════════════════════════════════════╝")
                print()
                print(f"  → Bob từ chối: {bob_msg}")
                print()
                print("  ┌─ Kết luận bảo mật ──────────────────────────────────────────")
                if choice == "2":
                    print("  │  Hacker thay base64 → sai cấu trúc → Bob phát hiện tại B.1")
                elif choice == "3":
                    print("  │  Hacker xây PGP đúng format + đúng key → qua B.1-B.5")
                    print("  │  Nhưng không có alice_private.pem → chữ ký ngẫu nhiên")
                    print("  │  → Bob phát hiện tại B.6 (RSA verify thất bại)")
                    print("  │  ✅ Chữ ký số là lớp bảo vệ CUỐI CÙNG không thể vượt qua!")
                print("  └────────────────────────────────────────────────────────────")

            alice_conn.sendall(bob_response)


# ============================================================
# MAIN
# ============================================================

def main():
    print()
    print("════════════════════════════════════════════════════════════════════")
    print("  HACKER — Man-in-the-Middle MITM Proxy  [TCP Socket Mode]")
    print("════════════════════════════════════════════════════════════════════")
    print()
    print(f"  Hacker lắng nghe Alice tại : 0.0.0.0:{HACKER_PORT}")
    print(f"  Hacker forward đến Bob tại : {BOB_HOST}:{BOB_PORT}")
    print()
    print("  ⚠️  CẢNH BÁO: Chạy Alice với lệnh sau để kết nối qua Hacker:")
    print(f"      python -m src.tcp_alice --host 127.0.0.1 --port {HACKER_PORT}")
    print()

    # Tải Bob's public key (cần cho kịch bản 3)
    bob_pub_path = KEYS_DIR / "bob_public.pem"
    if bob_pub_path.exists():
        bob_pub_key = bob_pub_path.read_bytes()
        print("  🔑 Đã tải bob_public.pem  (dùng cho kịch bản 3)")
    else:
        bob_pub_key = None
        print("  ⚠  Không tìm thấy bob_public.pem — kịch bản 3 sẽ không khả dụng")
    print()

    # ── TẠO MITM SERVER ─────────────────────────────────────
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((HACKER_HOST, HACKER_PORT))
    server_sock.listen(1)

    print("  ⏳ Chạy liên tục — Ctrl+C để tắt server")
    print()

    conn_count = 0
    while True:
        # ── CHỌN KỊCH BẢN ───────────────────────────────────
        avail = "(1/2/3)" if bob_pub_key else "(1/2)"
        print("  ┌─ Chọn kịch bản tấn công ───────────────────────────────────────")
        print("  │  [1] Chuyển tiếp nguyên bản       → Bob THÀNH CÔNG ✔")
        print("  │  [2] Thay payload bằng JSON giả    → Bob thất bại tại B.1 ✘")
        print("  │  [3] Giả mạo PGP hoàn chỉnh        → Bob thất bại tại B.6 ✘")
        print("  │      (biết format + có bob_public.pem, không có alice_private.pem)")
        print("  └────────────────────────────────────────────────────────────────")

        valid = ("1", "2", "3") if bob_pub_key else ("1", "2")
        while True:
            try:
                choice = input(f"  Nhập lựa chọn {avail}: ").strip()
            except KeyboardInterrupt:
                print("\n\n  Server đã tắt. Tạm biệt!")
                server_sock.close()
                sys.exit(0)
            if choice in valid:
                break
            print(f"  → Chỉ nhập {'/'.join(valid)}!")

        hacker_message = ""
        if choice in ("2", "3"):
            print()
            try:
                hacker_message = input("  Nhập nội dung muốn giả mạo: ").strip()
            except KeyboardInterrupt:
                print("\n\n  Server đã tắt. Tạm biệt!")
                server_sock.close()
                sys.exit(0)
            if not hacker_message:
                hacker_message = "Đây là tin giả từ Hacker!"

        conn_count += 1
        print()
        print(f"  [{conn_count}] Đang chờ Alice kết nối tại port {HACKER_PORT} ...")
        print()

        try:
            alice_conn, alice_addr = server_sock.accept()
        except KeyboardInterrupt:
            print("\n\n  Server đã tắt. Tạm biệt!")
            server_sock.close()
            sys.exit(0)

        handle_connection(alice_conn, alice_addr, choice, hacker_message, bob_pub_key)

        print()
        print("  ─────────────────────────────────────────────────────────────────")
        print()


if __name__ == "__main__":
    main()
