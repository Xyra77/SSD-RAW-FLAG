# LUKS Master Key Recovery dari RAM Dump (Cold-Boot Attack)

Script ini otomatis menemukan LUKS master key dari RAM dump dan men-decrypt
LUKS container, tanpa perlu passphrase.

## Kebutuhan
```bash
apt-get install -y cryptsetup-bin
pip install numpy cryptography --break-system-packages
```

## Cara pakai
```bash
python3 recover_flag.py --dump dump.raw --img data.img
```

File hasil decrypt akan disimpan sebagai `decrypted_full.img`, lalu otomatis
di-mount ke `/mnt/extracted` dan script akan mencari semua file bernama
`flag*` di dalamnya.

## Opsi
- `--out <path>`        : nama file output hasil decrypt (default: decrypted_full.img)
- `--mount-point <path>`: lokasi mount (default: /mnt/extracted)
- `--no-mount`          : skip mounting, cukup hasilkan file image saja
  (kalau environment tidak mengizinkan mount loop device, hasil decrypt
  tetap bisa dibuka manual: `mount -o loop,ro decrypted_full.img /mnt/x`)

## Cara kerja singkat
1. Baca cipher & key size dari header LUKS (`cryptsetup luksDump`).
2. Scan `dump.raw` untuk kandidat AES-256 key (32 byte) yang "self-consistent"
   dengan key schedule-nya sendiri yang tersimpan berdampingan di memory
   (teknik cold-boot attack, vectorized dengan numpy supaya cepat).
3. Untuk AES-XTS 512-bit, coba semua kombinasi pasangan kandidat sebagai
   key1 || key2, verifikasi ke `cryptsetup --test-passphrase`.
4. Decrypt data segment secara manual pakai AES-XTS-plain64 (tidak butuh
   device-mapper/root, jadi tetap jalan di container terbatas).
5. Mount filesystem hasil decrypt dan cari flag.

## Catatan
- Hanya mendukung key size 32 byte (AES-256 biasa) atau 64 byte (AES-XTS-512,
  dipakai LUKS2 default `aes-xts-plain64`).
- Kalau tidak ada kandidat yang cocok, kemungkinan key tidak lagi ada di
  memory dump (sudah di-overwrite), atau cipher/alignment-nya berbeda dari
  asumsi script ini.
