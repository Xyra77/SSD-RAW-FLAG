#!/usr/bin/env python3
"""
==============================================================================
 LUKS Master Key Recovery dari RAM Dump (Cold-Boot Attack) + Auto Decrypt
==============================================================================

Skenario:
  - dump.raw  : RAM dump dari VM/host yang sempat menjalankan
                `cryptsetup luksOpen <device> <name>`
  - data.img  : LUKS2 container yang ingin dibuka, passphrase tidak diketahui
                (KDF Argon2id/PBKDF2 sehingga brute-force passphrase tidak
                praktis)

Strategi:
  1. Baca header LUKS2 dari data.img (cipher, key size, digest) lewat
     `cryptsetup luksDump`.
  2. Scan dump.raw untuk kandidat AES-256 key (32 byte) yang "self-consistent"
     dengan key schedule-nya sendiri yang juga tersimpan di memory
     (teknik cold-boot attack / "Lest We Remember", Halderman et al 2008).
     Untuk AES-XTS 512-bit, master key = key1(32 byte) || key2(32 byte),
     jadi kita scan untuk AES-256 key individual lebih dulu.
  3. Coba semua kombinasi pasangan (key1, key2) dari kandidat yang ditemukan,
     verifikasi terhadap digest LUKS via `cryptsetup --test-passphrase
     --volume-key-file`.
  4. Begitu pasangan yang valid ditemukan, decrypt seluruh data segment
     data.img secara manual dengan AES-XTS-plain64 (tanpa perlu device-mapper
     / root privilege khusus, jadi tetap jalan di container/sandbox biasa).
  5. Mount hasil decrypt (ext4) dan cari flag.

Requirement:
  - cryptsetup-bin (binary `cryptsetup`)
  - python packages: numpy, cryptography
  - akses mount loop device (butuh privilege container yang mengizinkan mount;
    kalau tidak ada, script tetap menghasilkan file image hasil decrypt yang
    bisa di-mount manual / dibuka pakai tool lain)

Cara pakai:
    python3 recover_flag.py --dump dump.raw --img data.img

==============================================================================
"""

import argparse
import os
import subprocess
import sys
import time

import numpy as np

from aes_key_schedule import SBOX, RCON, key_expansion

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:
    print("[!] Library 'cryptography' belum terinstall. Jalankan:")
    print("    pip install cryptography --break-system-packages")
    sys.exit(1)


SBOX_NP = np.array(SBOX, dtype=np.uint8)


# ---------------------------------------------------------------------------
# 1. Parsing info LUKS header
# ---------------------------------------------------------------------------

def get_luks_info(img_path):
    """Ambil cipher, key size (bits), dan offset data segment dari LUKS header."""
    result = subprocess.run(
        ["cryptsetup", "luksDump", img_path],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print("[!] Gagal membaca header LUKS:", result.stderr)
        sys.exit(1)

    dump = result.stdout
    key_bits = None
    cipher = None
    data_offset_bytes = None

    for line in dump.splitlines():
        line = line.strip()
        if line.startswith("Cipher key:") and key_bits is None:
            # contoh: "Cipher key: 512 bits"
            key_bits = int(line.split(":")[1].strip().split()[0])
        if line.startswith("cipher:") and cipher is None:
            cipher = line.split(":")[1].strip()
        if line.startswith("offset:") and data_offset_bytes is None:
            # contoh: "offset: 16777216 [bytes]"
            data_offset_bytes = int(line.split(":")[1].strip().split()[0])

    if key_bits is None or data_offset_bytes is None:
        print("[!] Tidak bisa menemukan informasi key size / data offset dari header.")
        sys.exit(1)

    print(f"[*] Cipher           : {cipher}")
    print(f"[*] Key size         : {key_bits} bits ({key_bits // 8} bytes)")
    print(f"[*] Data segment off : {data_offset_bytes} bytes")

    return {
        "cipher": cipher,
        "key_size_bits": key_bits,
        "key_size_bytes": key_bits // 8,
        "data_offset": data_offset_bytes,
    }


# ---------------------------------------------------------------------------
# 2. Scan memory dump untuk kandidat AES-256 key (cold-boot attack)
# ---------------------------------------------------------------------------

def aes256_round_key1_vectorized(keys32: np.ndarray) -> np.ndarray:
    """
    keys32: shape (N, 32) uint8 array, tiap baris kandidat AES-256 key.
    Return: shape (N, 16) -> word w8,w9,w10,w11 dari key schedule AES-256,
    yaitu 16 byte PERTAMA setelah raw key di expanded schedule.

    Kalau 16 byte yang SEHARUSNYA dihasilkan ini cocok dengan 16 byte yang
    benar-benar ada di memory tepat setelah key, kandidat ini sangat mungkin
    adalah AES-256 key asli yang sedang aktif dipakai (schedule-nya ada
    berdampingan di memory).
    """
    N = keys32.shape[0]
    w = keys32.reshape(N, 8, 4)  # w0..w7

    w7 = w[:, 7, :]
    rotated = np.roll(w7, -1, axis=1)        # RotWord
    subbed = SBOX_NP[rotated].copy()         # SubWord
    subbed[:, 0] ^= RCON[1]                  # XOR Rcon[1]

    w0, w1, w2, w3 = w[:, 0, :], w[:, 1, :], w[:, 2, :], w[:, 3, :]
    w8 = w0 ^ subbed
    w9 = w1 ^ w8
    w10 = w2 ^ w9
    w11 = w3 ^ w10

    return np.concatenate([w8, w9, w10, w11], axis=1)


def scan_dump_for_aes256_keys(dump_path, chunk_size=8 * 1024 * 1024, stride=16):
    """Scan seluruh dump.raw untuk kandidat AES-256 key (32 byte)."""
    candidates = []
    file_size = os.path.getsize(dump_path)
    overlap = 64

    print(f"[*] Scanning {dump_path} ({file_size / (1024**2):.1f} MB) untuk kandidat AES-256 key...")
    t0 = time.time()

    with open(dump_path, "rb") as f:
        pos = 0
        while pos < file_size:
            f.seek(pos)
            buf = f.read(chunk_size + overlap)
            if not buf:
                break
            n = len(buf)
            arr = np.frombuffer(buf, dtype=np.uint8)

            max_start = n - 48  # butuh 32 (key) + 16 (fingerprint berikutnya)
            if max_start <= 0:
                pos += chunk_size
                continue

            starts = np.arange(0, max_start, stride)
            idx = starts[:, None] + np.arange(32)[None, :]
            keys32 = arr[idx]

            expected_fp = aes256_round_key1_vectorized(keys32)
            idx_fp = starts[:, None] + 32 + np.arange(16)[None, :]
            actual_fp = arr[idx_fp]

            matches = np.all(expected_fp == actual_fp, axis=1)
            for mi in np.where(matches)[0]:
                candidates.append(pos + int(starts[mi]))

            pos += chunk_size

    print(f"[*] Scan selesai dalam {time.time()-t0:.1f}s, {len(candidates)} kandidat ditemukan.")
    return candidates


def verify_full_schedule(dump_data, offset):
    """Verifikasi penuh: cocokkan 240 byte expanded schedule AES-256 lengkap."""
    key = dump_data[offset:offset + 32]
    sched = key_expansion(key)
    actual = dump_data[offset:offset + 240]
    return sched == actual


# ---------------------------------------------------------------------------
# 3. Brute force pasangan key1/key2, verifikasi ke cryptsetup
# ---------------------------------------------------------------------------

def test_master_key(img_path, key_bytes, key_size_bits):
    """Uji 1 kandidat master key via cryptsetup --test-passphrase. True kalau cocok."""
    tmp_key_file = "/tmp/_candidate_key.bin"
    with open(tmp_key_file, "wb") as f:
        f.write(key_bytes)

    result = subprocess.run(
        [
            "cryptsetup", "open", "--type", "luks2", "--test-passphrase",
            f"--volume-key-file={tmp_key_file}",
            f"--key-size={key_size_bits}",
            img_path, "testmap_tmp",
        ],
        capture_output=True, text=True,
    )
    os.remove(tmp_key_file)
    return result.returncode == 0


def find_master_key(dump_path, img_path, key_size_bytes):
    """
    Cari master key lengkap dengan:
      1. Scan kandidat AES-256 (32 byte) individual di dump.raw
      2. Verifikasi full key schedule (mengurangi false positive)
      3. Coba semua kombinasi pasangan (key1, key2) untuk membentuk
         master key 'key_size_bytes' byte, uji ke cryptsetup
    """
    raw_candidates = scan_dump_for_aes256_keys(dump_path)

    with open(dump_path, "rb") as f:
        dump_data = f.read()

    verified = [off for off in raw_candidates if verify_full_schedule(dump_data, off)]
    print(f"[*] {len(verified)} kandidat lolos verifikasi full key schedule (240 byte).")

    if key_size_bytes == 32:
        # AES-256 biasa (bukan XTS), key tunggal 32 byte
        candidates_to_test = [(off, dump_data[off:off + 32]) for off in verified]
    elif key_size_bytes == 64:
        # AES-XTS 512-bit: key = key1(32) || key2(32), coba semua kombinasi
        print(f"[*] Key size 64 byte (AES-XTS) -> mencoba semua kombinasi pasangan "
              f"dari {len(verified)} kandidat ({len(verified)*(len(verified)-1)} kombinasi)...")
        candidates_to_test = []
        for off1 in verified:
            key1 = dump_data[off1:off1 + 32]
            for off2 in verified:
                if off1 == off2:
                    continue
                key2 = dump_data[off2:off2 + 32]
                candidates_to_test.append(((off1, off2), key1 + key2))
    else:
        print(f"[!] Key size {key_size_bytes} byte belum didukung script ini "
              f"(baru mendukung 32 byte AES-256 atau 64 byte AES-XTS-512).")
        sys.exit(1)

    print(f"[*] Menguji {len(candidates_to_test)} kandidat master key ke cryptsetup...")
    for label, key_bytes in candidates_to_test:
        if test_master_key(img_path, key_bytes, key_size_bytes * 8):
            print(f"[+] MASTER KEY DITEMUKAN! (sumber offset: {label})")
            print(f"[+] Key (hex): {key_bytes.hex()}")
            return key_bytes

    print("[!] Tidak ada kandidat yang cocok. Coba turunkan stride scan, atau "
          "perluas radius pencarian di sekitar offset yang dicurigai.")
    return None


# ---------------------------------------------------------------------------
# 4. Decrypt data segment manual dengan AES-XTS-plain64
# ---------------------------------------------------------------------------

def decrypt_data_segment(img_path, key_bytes, data_offset, out_path,
                          sector_size=512, batch_sectors=4096):
    """Decrypt seluruh data segment LUKS secara manual (tanpa device-mapper)."""
    print(f"[*] Decrypting data segment -> {out_path} ...")
    with open(img_path, "rb") as fin, open(out_path, "wb") as fout:
        fin.seek(data_offset)
        sector_num = 0
        while True:
            chunk = fin.read(sector_size * batch_sectors)
            if not chunk:
                break
            n_sectors = len(chunk) // sector_size
            out_buf = bytearray()
            for i in range(n_sectors):
                sector = chunk[i * sector_size:(i + 1) * sector_size]
                tweak = sector_num.to_bytes(16, "little")
                cipher = Cipher(algorithms.AES(key_bytes), modes.XTS(tweak))
                decryptor = cipher.decryptor()
                out_buf.extend(decryptor.update(sector))
                sector_num += 1
            fout.write(out_buf)

    print(f"[*] Selesai. Total sector ter-decrypt: {sector_num}")


# ---------------------------------------------------------------------------
# 5. Mount dan cari flag
# ---------------------------------------------------------------------------

def mount_and_find_flag(img_path, mount_point="/mnt/extracted"):
    os.makedirs(mount_point, exist_ok=True)
    result = subprocess.run(
        ["mount", "-o", "loop,ro", img_path, mount_point],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print("[!] Gagal mount filesystem hasil decrypt:")
        print(result.stderr)
        print(f"[!] File image hasil decrypt tetap tersedia di: {img_path}")
        print("    Coba mount manual: mount -o loop,ro <img_path> <mount_point>")
        return

    print(f"[+] Filesystem berhasil di-mount di {mount_point}")
    print("[*] Mencari file flag...")

    found_any = False
    for root, _, files in os.walk(mount_point):
        for fname in files:
            if "flag" in fname.lower():
                found_any = True
                fpath = os.path.join(root, fname)
                print(f"\n[+] Ditemukan: {fpath}")
                try:
                    with open(fpath, "r", errors="replace") as f:
                        print("    Isi   :", f.read().strip())
                except Exception as e:
                    print("    (gagal dibaca sebagai teks):", e)

    if not found_any:
        print("[!] Tidak ada file bernama 'flag*' ditemukan otomatis.")
        print(f"    Cek manual isi {mount_point} untuk mencari flag.")

    subprocess.run(["umount", mount_point], capture_output=True)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Recover LUKS master key dari RAM dump dan decrypt data.img"
    )
    parser.add_argument("--dump", required=True, help="Path ke dump.raw (RAM dump)")
    parser.add_argument("--img", required=True, help="Path ke data.img (LUKS container)")
    parser.add_argument("--out", default="decrypted_full.img",
                         help="Path output file image hasil decrypt")
    parser.add_argument("--mount-point", default="/mnt/extracted",
                         help="Mount point untuk filesystem hasil decrypt")
    parser.add_argument("--no-mount", action="store_true",
                         help="Skip mounting, cukup hasilkan file decrypted image")
    args = parser.parse_args()

    print("=" * 70)
    print(" LUKS Master Key Recovery dari RAM Dump")
    print("=" * 70)

    info = get_luks_info(args.img)

    master_key = find_master_key(args.dump, args.img, info["key_size_bytes"])
    if master_key is None:
        sys.exit(1)

    decrypt_data_segment(args.img, master_key, info["data_offset"], args.out)

    if not args.no_mount:
        mount_and_find_flag(args.out, args.mount_point)
    else:
        print(f"[*] Selesai. File hasil decrypt: {args.out}")


if __name__ == "__main__":
    main()
