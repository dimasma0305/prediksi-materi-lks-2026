# 7. Hashing

> Hash kriptografis (MD5, SHA-1, SHA-2) dirancang sebagai fungsi satu arah, tetapi *cara pakainya* yang sering salah. Di CTF, soal hashing jarang meminta memecahkan fungsi hash itu sendiri — yang diuji adalah mengenali **konstruksi yang rapuh**. Bintang utamanya: **length extension attack** terhadap MAC buatan sendiri berbentuk `signature = H(secret || message)`. Dengan hanya mengetahui `message` dan `signature` (tanpa tahu `secret`), penyerang bisa **menempa** signature valid untuk `message || padding || data_tambahan` — inilah yang dieksploitasi untuk memalsukan parameter dan mengambil **flag** di LKSN 2026.

## Konsep

Hash kriptografis menjamin: *preimage resistance*, *second-preimage*, dan *collision resistance*. Properti itu **tidak** mencakup kerahasiaan state internal — dan di situlah letak masalahnya.

Banyak aplikasi membangun **Message Authentication Code (MAC)** buatan sendiri untuk "menandatangani" data, mis. sebuah cookie atau query string, dengan pola **secret-prefix**:

```
signature = SHA256(secret || data)     # secret hanya diketahui server
```

Server lalu memvalidasi request dengan menghitung ulang `SHA256(secret || data)` dan membandingkannya dengan `signature` yang dikirim. Karena fungsi hash yang dipakai memakai konstruksi **Merkle–Damgård** (MD5, SHA-1, SHA-256, SHA-512), digest yang bocor ke client **adalah** salinan utuh state internal hash. Penyerang dapat melanjutkan komputasi dari state itu untuk menempa signature data yang lebih panjang — **tanpa pernah tahu `secret`**. (Kelas serangan hash lain seperti collision MD5/SHA-1 atau cracking hash lemah memang ada, tapi fokus halaman ini sepenuhnya pada length extension.)

## Cara Kerja

Konstruksi Merkle–Damgård memproses pesan **blok demi blok** (64 byte untuk MD5/SHA-1/SHA-256, 128 byte untuk SHA-512), mempertahankan **chaining state** yang di-update tiap blok. Output akhir = state setelah blok terakhir. **Tidak ada finalisasi** yang menyembunyikan state itu — digest = state.

Sebelum diproses, pesan di-*pad*: tambahkan satu bit `1` (byte `0x80`), lalu byte `0x00`, lalu **panjang pesan dalam bit** sebagai field 64-bit (little-endian untuk MD5; big-endian untuk SHA-1/SHA-256). Inilah **glue padding**.

Kunci serangan: penyerang meng-*set IV* fungsi hash ke `signature` yang bocor, lalu memproses `data_tambahan` seolah melanjutkan hash. Hasilnya adalah:

```
H(secret || data || glue_padding || data_tambahan)
```

yang merupakan signature **valid** untuk pesan baru `data || glue_padding || data_tambahan`. Satu-satunya yang perlu ditebak adalah **panjang `secret`** (untuk menghitung glue padding yang benar).

| Konstruksi hash | Contoh | Rentan length extension? |
|---|---|---|
| Merkle–Damgård (full digest) | MD5, SHA-1, SHA-256, SHA-512 | **Ya** |
| Sponge | SHA-3 / Keccak, SHAKE | Tidak (state > output) |
| Hash modern dengan proteksi | BLAKE2, BLAKE3 | Tidak (by design) |
| Merkle–Damgård ter-*truncate* | SHA-384, SHA-512/256 | Tidak (sebagian state disembunyikan) |
| MAC ber-nested | **HMAC**-SHA256 | Tidak (kunci di luar & dalam) |

> Catatan: `hash_extender` **tidak** mendukung CRC32. Algoritma yang didukungnya adalah MD4, MD5, RIPEMD-160, SHA-0, SHA-1, SHA-256, SHA-512, dan WHIRLPOOL — semuanya Merkle–Damgård. CRC32 memang bisa di-*extend* secara matematis, tetapi *bukan* M–D dan bukan hash kriptografis — jangan dipakai sebagai contoh M–D.

## Indikator / Cara Mengenali

Tanda sebuah target rentan length extension:

- Server mengirim **pasangan `data` + `signature`** dan memvalidasi dengan menghitung ulang hash; mis. `?file=avatar.png&sig=8a3f...`.
- Panjang `signature` cocok dengan digest hex hash M–D: **32** (MD5), **40** (SHA-1), **64** (SHA-256), **128** (SHA-512) karakter hex.
- Dokumentasi/sumber menyebut MAC dibentuk dengan **`secret` diprepend** lalu di-hash (secret-prefix), bukan `HMAC`.
- Parameter di-*concat* lalu di-hash, dan parsing-nya **last-wins** (parameter terakhir menimpa yang lebih awal) — sehingga `data_tambahan` seperti `&admin=true` menggantikan nilai sebelumnya.
- Panjang `secret` bisa ditebak dari rentang kecil (mis. 8–32 byte), atau bahkan diketahui dari konteks.

## Langkah Eksploitasi

1. **Konfirmasi konstruksi.** Pastikan signature = digest mentah hash M–D dari `secret || data`, bukan HMAC. Tentukan algoritma dari panjang digest.
2. **Tentukan data asli & target.** Catat `data` asli, `signature` asli, dan `data_tambahan` yang ingin disisipkan (mis. `&role=admin`).
3. **Brute-force panjang `secret`.** Inilah satu-satunya hambatan praktis: panjang `secret` tidak diketahui, jadi **iterasi kandidat** (mis. 1–64 byte). Untuk tiap kandidat, hitung satu pasang `(forged_data, forged_sig)`.
4. **Hitung dengan tool.** Beri `hash_extender`/`hashpump`: signature asli, data asli, data tambahan, dan panjang `secret` kandidat. Tool mengembalikan **signature baru** + **pesan baru** (sudah berisi glue padding).
5. **Encode glue padding.** Pesan baru mengandung byte non-printable (`0x80`, null, field panjang) — submit sebagai **hex/URL-encoded** (`--out-data-format=hex`), bukan ASCII mentah. Ini stumbling block klasik.
6. **Submit tiap kandidat.** Kirim pasangan `(forged_data, forged_sig)` untuk setiap panjang yang dicoba; salah satu akan diterima server (panjang `secret` benar) → `data_tambahan` menimpa parameter → **dapat flag**.

## Tools

| Tool | Fungsi singkat |
|---|---|
| **hash_extender** (iagox86) | Tool C standar; mendukung MD4, MD5, RIPEMD-160, SHA-0, SHA-1, SHA-256, SHA-512, WHIRLPOOL. Output siap dengan glue padding ter-encode |
| **HashPump** (bwall) | Alternatif klasik; MD5/SHA-1/SHA-256/SHA-512, antarmuka interaktif |
| **hashpumpy** | Binding Python untuk HashPump — otomatisasi brute-force panjang `secret` dalam skrip solver |
| **hlextend** (python) | Implementasi murni-Python (SHA-1/SHA-256/SHA-512) tanpa kompilasi, mudah diimpor |
| **CyberChef** | Encode/decode glue padding, konversi hex↔URL saat menyusun payload |
| **hashcat / john** | *Pendukung* — bila langkah lain butuh memulihkan `secret` lemah dari digest (bukan jalur utama length extension) |

## Contoh / Payload

Server rentan (pola yang sering muncul di soal):

```python
import hashlib
SECRET = b"s3cr3t_k3y_16byte"   # 17 byte, hanya server yang tahu

def make_token(data: bytes) -> str:
    return hashlib.sha256(SECRET + data).hexdigest()

def verify(data: bytes, sig: str) -> bool:
    return hashlib.sha256(SECRET + data).hexdigest() == sig

# Token sah yang dilihat penyerang:
data = b"user=guest&role=user"
sig  = make_token(data)          # mis. 6f1c...  (64 hex)
```

Menempa dengan `hash_extender` (CLI):

```bash
# Append "&role=admin"; coba panjang secret 17. Output data dalam hex agar
# glue padding (0x80, null, length) tetap utuh saat dikirim.
hash_extender \
  --data 'user=guest&role=user' \
  --secret 17 \
  --append '&role=admin' \
  --signature 6f1c... \
  --format sha256 \
  --out-data-format=hex
# => New signature: <sig_baru>
# => New string:    757365723d...80...&role=admin   (kirim URL-decoded dari hex)
```

Otomatisasi brute-force panjang `secret` dengan `hashpumpy`:

```python
import hashpumpy, requests

orig_data = b"user=guest&role=user"
orig_sig  = "6f1c..."               # signature SHA-256 yang bocor
append    = b"&role=admin"

for klen in range(1, 65):           # tebak panjang secret 1..64
    new_sig, new_msg = hashpumpy.hashpump(orig_sig, orig_data, append, klen)
    # new_msg = orig_data || glue_padding || append  (bytes, ada non-printable)
    r = requests.get("https://lab/api", params={
        "data": new_msg.hex(),      # kirim sebagai hex; server meng-unhex
        "sig":  new_sig,
    })
    if "flag{" in r.text:
        print(f"[+] secret length = {klen}\n{r.text}")
        break
```

> Inti yang sering disalahpahami: `new_msg` **diawali** `secret` di sisi server (`SECRET + new_msg`), tetapi penyerang hanya menempa bagian setelah `secret`. Forgery berhasil karena `orig_sig` adalah *state internal* SHA-256 lengkap setelah memproses `secret || orig_data`.

## Deteksi & Mitigasi

**Perbaikan inti (sisi developer) — ini fix yang sebenarnya:**

- **Pakai HMAC, jangan gulung MAC sendiri.** Ganti `H(secret || data)` dengan **`HMAC-SHA256(key, data)`** (`hmac.new(key, data, sha256)`). Konstruksi nested HMAC (`H(K⊕opad || H(K⊕ipad || msg))`) membungkus state internal dengan hash kedua sehingga **mustahil dilanjutkan** — length extension mati total.
- **Atau pakai hash anti-length-extension** bila memang butuh keyed-hash sederhana: **SHA-3/Keccak** (sponge), **BLAKE2/BLAKE3** (punya keyed mode bawaan), atau varian ter-*truncate* **SHA-512/256** / **SHA-384**.
- **Hindari secret-suffix `H(data || secret)`.** Memang resisten terhadap length extension, tapi memindahkan risiko ke collision pada `H` — **HMAC tetap jawaban yang benar**.
- **Bandingkan MAC dengan `hmac.compare_digest`** (constant-time) untuk menutup timing side-channel saat verifikasi.

**Bridge ke hardening (blue-team — kaitan ke Modul C):**

- **Code review / SAST (kaitan Modul C — Secure Configuration & Code Audit).** Cari pola `hash(secret + ...)`, `md5(key . $data)`, `sha256(SECRET || msg)` di basis kode dan ganti ke HMAC. Inilah akar masalah — bukan sekadar gejala.
- **Deteksi di logging (jembatan ke Modul A — Logging/Auditing & Modul C — Log Forensic).** Request hasil forgery membawa **glue padding**: byte `0x80` diikuti deretan null dan field panjang di tengah parameter. Alarmkan input dengan byte non-printable mencurigakan, panjang parameter yang membengkak tiba-tiba, atau banyak request beda-panjang dengan signature berbeda (tanda brute-force panjang `secret`).
- **Secrets management.** Simpan signing key di secret store/HSM dengan akses terbatas, lakukan **key rotation**, dan jangan pernah menempatkan `secret` di posisi prefix pada konstruksi hash mentah.

> **Insiden nyata:** **Flickr API Signature Forgery** (Thai Duong & Juliano Rizzo, 2009) — Flickr menandatangani panggilan API dengan `MD5(secret || params)`. Length extension memungkinkan penyerang menempa signature API yang valid tanpa tahu shared secret. Banyak layanan dengan arsitektur signature serupa ikut rentan; perbaikannya adalah pindah ke **HMAC**.

## Mini-Lab

**Skenario:** Endpoint `https://lab/api?data=user%3Dguest%26role%3Duser&sig=<sig>` menerima `data` + `sig = SHA256(secret || data)` dan parsing parameternya **last-wins**. Panjang `secret` tidak diketahui. Tugas: tempa request agar `role=admin` dan dapatkan **flag**.

1. Konfirmasi: panjang `sig` = 64 hex → SHA-256; MAC adalah secret-prefix (bukan HMAC).
2. Targetkan `append = "&role=admin"` (akan menimpa `role=user` karena last-wins).
3. Loop panjang `secret` 1–64 dengan `hashpumpy.hashpump(sig, b"user=guest&role=user", b"&role=admin", klen)`.
4. Untuk tiap kandidat, kirim `data` (hex-encoded, berisi glue padding) + `sig` baru.
5. Server menerima saat `klen` benar → `role=admin` aktif → **flag** muncul di respons.

Verifikasi: bandingkan hasil `hashpumpy` dengan `hash_extender --out-data-format=hex` pada panjang yang sama — keduanya harus menghasilkan signature & pesan identik.

## Referensi & Latihan

- **Ron Bowes (iagox86 / SkullSecurity) — "Everything you need to know about hash length extension attacks"** (referensi kanonik + tool `hash_extender`): https://github.com/iagox86/hash_extender
- **Wikipedia — Length extension attack** (ikhtisar konstruksi & daftar hash rentan/aman): https://en.wikipedia.org/wiki/Length_extension_attack
- **Duong & Rizzo — "Flickr's API Signature Forgery Vulnerability" (2009)** untuk studi kasus dunia nyata MD5(secret‖params).
- **root-me — Cryptanalysis** (challenge bertema hash & length extension) dan **CryptoHack — Hashes** untuk drilling solver.
- **pwn.college — Cryptography** dan **HackTheBox** (kategori Crypto): soal MAC buatan sendiri / length extension klasik.
- **HashPump** (bwall) sebagai pembanding tool: https://github.com/bwall/HashPump

> **Etika:** Teknik di sini hanya untuk lab pribadi, platform latihan resmi, target CTF, atau sistem dengan **izin tertulis eksplisit**. Menempa signature atau melewati autentikasi sistem milik orang lain tanpa izin melanggar hukum.
