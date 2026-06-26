# 4. Attack on AES

> AES (Advanced Encryption Standard / Rijndael) sebagai *block cipher* primitif **belum** punya serangan praktis — tidak ada CTF yang menyuruh "memecahkan AES dari nol". Yang diserang adalah **mode of operation** (cara merangkai blok) dan **kesalahan implementasi**: ECB yang deterministik, CBC dengan *padding oracle* atau *bit-flipping*, mode stream (CFB/OFB/CTR) dengan *keystream/nonce reuse*, dan GCM yang nonce-nya dipakai ulang (*forbidden attack*). Tujuan akhirnya tetap: memulihkan plaintext, menempa ciphertext, atau merebut authentication key untuk mendapatkan **flag**.

## Konsep

AES bekerja per **blok 128-bit (16 byte)** dengan kunci 128/192/256-bit. Karena pesan nyata lebih panjang dari satu blok, dipakailah **mode of operation** untuk merangkai banyak blok. Di sinilah letak hampir semua celah CTF — bukan di S-box atau key schedule AES, melainkan di mode dan parameternya (IV/nonce statis, nonce dipakai ulang, padding yang bocor lewat pesan error, kunci/keystream dipakai berulang).

Enam mode yang wajib dikenali beserta sifat & permukaan serangnya:

| Mode | Tipe | Butuh IV/Nonce | Padding | Kelemahan khas di CTF |
|---|---|---|---|---|
| **ECB** | block | tidak | ya | Deterministik: blok plaintext sama → blok ciphertext sama (bocor pola, *cut-and-paste*, *byte-at-a-time oracle*) |
| **CBC** | block | IV | ya | *Padding oracle* (dekripsi penuh) & *bit-flipping* (malleable lewat blok sebelumnya) |
| **CFB** | stream | IV/nonce | tidak | Stream cipher → *keystream reuse*, malleable, tanpa autentikasi |
| **OFB** | stream | IV/nonce | tidak | Keystream murni `E_k` berantai → reuse = *two-time pad* |
| **CTR** | stream | nonce+counter | tidak | Nonce/counter reuse → keystream sama → XOR dua ciphertext bocor plaintext |
| **GCM** | stream + AEAD | nonce (96-bit) | tidak | Nonce reuse → *forbidden attack*: pulihkan authentication key `H`, forge tag |

Inti pembedaannya: **block mode** (ECB, CBC) mengenkripsi blok via `E_k` dan butuh padding (umumnya **PKCS#7**); **stream mode** (CFB, OFB, CTR) memakai AES untuk membangkitkan *keystream* lalu `P ⊕ keystream`, tanpa padding tetapi **malleable** dan rapuh terhadap reuse. **GCM** adalah CTR + autentikasi GHASH (AEAD) — aman selama nonce unik, hancur total saat nonce diulang.

## Cara Kerja

Letak kelemahan tiap mode secara struktural:

- **ECB** — `C_i = E_k(P_i)`. Tidak ada IV, tidak ada chaining. Blok plaintext identik selalu menghasilkan blok ciphertext identik. Inilah "ECB penguin". Jika oracle mengenkripsi `attacker_input || secret`, penyerang menyelaraskan batas blok dan memulihkan `secret` satu byte demi satu (*byte-at-a-time ECB decryption*).
- **CBC** — enkripsi `C_i = E_k(P_i ⊕ C_{i-1})`, dekripsi `P_i = D_k(C_i) ⊕ C_{i-1}`. Karena `C_{i-1}` di-XOR langsung ke hasil dekripsi, mengubah 1 bit di `C_{i-1}` membalik bit yang sama persis di `P_i` (**bit-flipping**, merusak blok `i-1` tetapi mengontrol blok `i`). Jika server membedakan *padding valid* vs *invalid* (lewat pesan error atau timing), penyerang menjalankan **padding oracle** dan mendekripsi ciphertext **tanpa kunci**, blok demi blok dari byte terakhir.
- **CFB / OFB / CTR** — semuanya menghasilkan keystream `KS` dari `E_k` lalu `C = P ⊕ KS` (OFB: `KS` berantai dari `E_k(IV)`; CTR: `KS_i = E_k(nonce‖counter_i)`). Konsekuensinya: (1) **malleable** — flip bit ciphertext = flip bit plaintext tepat di posisi sama; (2) **keystream/nonce reuse** — pasangan (key, nonce/IV) sama dua kali menghasilkan `KS` identik, sehingga `C1 ⊕ C2 = P1 ⊕ P2` (**two-time pad**) yang dipecah dengan *crib-dragging*.
- **GCM** — ciphertext lewat CTR; tag autentikasi `T = GHASH_H(AAD, C) ⊕ E_k(J0)` dengan `H = E_k(0^128)` dan `J0` diturunkan dari nonce. GHASH adalah evaluasi polinomial di **GF(2^128)**. Bila nonce diulang untuk dua pesan, selisih dua persamaan tag menghilangkan `E_k(J0)` dan menyisakan **polinomial yang akarnya adalah `H`** — difaktorkan (Cantor–Zassenhaus) untuk **memulihkan authentication key `H`**, lalu menempa tag valid untuk ciphertext arbitrer (**forbidden attack**, Joux; dipopulerkan Böck–Zauner–Devlin pada TLS).

## Indikator / Cara Mengenali

Tanda-tanda soal melibatkan AES dan mode mana yang rentan:

- **Panjang ciphertext kelipatan 16 byte** → kemungkinan AES block mode (ECB/CBC). Panjang non-kelipatan 16 → kemungkinan stream mode (CTR/CFB/OFB/GCM).
- **Blok 16-byte berulang identik** di dalam satu ciphertext → hampir pasti **ECB** (atau IV/nonce statis). Cek dengan memecah ciphertext per 16 byte dan menghitung duplikat.
- **IV/nonce dikirim bersama ciphertext dan bernilai tetap/0/predictable** → buka jalur CBC bit-flipping atau stream-reuse.
- **Server membalas beda untuk ciphertext rusak** — "padding error" vs "decryption failed", atau perbedaan timing/HTTP status → kandidat **padding oracle (CBC)**.
- **Dua ciphertext berbeda memakai nonce yang sama** (terlihat jika nonce diekspos) → keystream reuse (CTR/OFB/CFB) atau **GCM nonce reuse**.
- **Ada 16 byte "tag" terpisah** selain ciphertext, kadang berlabel `tag`/`mac` → mode AEAD (GCM/EAX/ChaCha20-Poly1305).

## Langkah Eksploitasi

1. **Identifikasi mode.** Ukur panjang ciphertext (kelipatan 16?), deteksi blok berulang (ECB), cek apakah IV/nonce/tag dikirim. Kirim dua plaintext identik panjang dan amati apakah ciphertext-nya sama (deterministik = ECB/static-IV).
2. **ECB.** Jika oracle berbentuk `E_k(attacker || secret)`: lakukan **byte-at-a-time** — kontrol offset agar byte rahasia "tergeser" ke batas blok, lalu cocokkan blok target dengan kamus 256 tebakan per byte. Untuk token terstruktur, lakukan **cut-and-paste** (susun ulang blok ciphertext, mis. `role=user` → `role=admin`).
3. **CBC bit-flipping.** Untuk auth-bypass/cookie: ubah byte di blok `C_{i-1}` agar plaintext blok `i` berubah ke nilai yang diinginkan (`X ⊕ P_lama ⊕ P_baru`), korbankan blok `i-1`.
4. **CBC padding oracle.** Jika ada oracle valid/invalid padding: pulihkan **intermediate state** byte-per-byte dari kanan, lalu `P = intermediate ⊕ C_{i-1}`. Bisa juga *meng-enkripsi* plaintext pilihan sendiri (chosen-plaintext via oracle).
5. **Keystream/nonce reuse (CTR/OFB/CFB).** Kumpulkan dua ciphertext dengan (key, nonce) sama → `C1 ⊕ C2 = P1 ⊕ P2`. Pulihkan dengan *crib-dragging* (tebak kata umum) atau, bila satu plaintext diketahui, `KS = C1 ⊕ P1` lalu dekripsi yang lain.
6. **GCM nonce reuse.** Kumpulkan ≥2 pasang `(nonce, ciphertext, tag)` dengan nonce sama → susun polinomial GHASH di GF(2^128), faktorkan untuk dapat `H`, lalu **forge** tag untuk pesan/AAD pilihan (mis. ubah command terenkripsi menjadi valid).

## Tools

| Tool | Fungsi singkat |
|---|---|
| **pycryptodome** (`Crypto.Cipher.AES`) | Implementasi AES semua mode untuk menulis solver & oracle lokal |
| **pwntools** | Otomatisasi interaksi dengan oracle remote (nc/HTTP), looping byte-at-a-time |
| **PadBuster** / **padding-oracle-attacker** (npm) / `python-paddingoracle` | Otomatisasi padding oracle CBC (dekripsi & enkripsi) |
| **SageMath** / **sympy** / **galois** (PyPI) | Aljabar GF(2^128) untuk *forbidden attack* GCM (faktorisasi polinomial) |
| **nonce-disrespect** (Böck/Devlin) | PoC publik forbidden attack AES-GCM nonce reuse |
| **xortool** / **cribdrag** | Memecah *two-time pad* dari keystream/nonce reuse |
| **CyberChef** / **FeatherDuster** | Deteksi mode cepat, eksperimen XOR/encode-decode, "ECB penguin" |

## Contoh / Payload

```python
# === Deteksi ECB: cari blok 16-byte berulang ===
from Crypto.Cipher import AES

def looks_ecb(ct: bytes, bs: int = 16) -> bool:
    blocks = [ct[i:i+bs] for i in range(0, len(ct), bs)]
    return len(blocks) != len(set(blocks))   # ada duplikat → ECB / static-IV
```

```python
# === Byte-at-a-time ECB decryption (oracle = E_k(prefix_terkontrol || SECRET)) ===
# oracle(data) -> ciphertext AES-ECB dari (data || SECRET)
BS = 16
known = b""
while True:
    pad = b"A" * (BS - 1 - (len(known) % BS))            # geser byte target ke batas blok
    block_index = len(pad) + len(known)                  # offset blok yang diuji
    target = oracle(pad)[: (block_index // BS + 1) * BS]
    for b in range(256):                                  # kamus 256 tebakan
        guess = oracle(pad + known + bytes([b]))[: len(target)]
        if guess == target:
            known += bytes([b]); break
    else:
        break                                             # padding habis → SECRET selesai
print(known)   # biasanya berisi flag
```

```python
# === CBC bit-flipping: ubah satu byte plaintext blok i lewat C_{i-1} ===
# Target: ubah byte ke-j blok plaintext dari old -> new (blok i-1 jadi sampah)
i_prev = (block_i - 1) * 16
ct = bytearray(ciphertext)
ct[i_prev + j] ^= old_byte ^ new_byte   # XOR trick: flip persis bit yang dibutuhkan
```

```python
# === Keystream / nonce reuse (CTR/OFB/CFB) — two-time pad ===
# Jika satu plaintext diketahui (known), pulihkan keystream lalu dekripsi yang lain:
ks  = bytes(a ^ b for a, b in zip(ct1, known))   # KS = C1 XOR P1
pt2 = bytes(a ^ b for a, b in zip(ct2, ks))      # P2 = C2 XOR KS
# Tanpa known plaintext: crib-drag C1 XOR C2 dengan kata umum (" the ", "flag{").
```

```bash
# === CBC padding oracle (otomatis) ===
padbuster http://target/decrypt <CIPHERTEXT_HEX> 16 -encoding 1 -cookies "session=<CT>"
# atau Python: padding-oracle-attacker / python-paddingoracle dengan fungsi oracle(ct)->bool

# === AES-GCM forbidden attack (nonce reuse) ===
# Kumpulkan dua (nonce sama) lalu pulihkan H & forge tag:
python3 gcm_forbidden.py  --nonce <N> \
        --msg1 <C1> --tag1 <T1> --msg2 <C2> --tag2 <T2>   # PoC nonce-disrespect / solver Sage
```

> **Catatan akurasi.** Padding oracle hanya berlaku untuk **CBC** (atau mode ber-padding), **bukan** stream mode. *Bit-flipping* CTR/OFB/CFB tidak merusak blok lain (beda dari CBC yang mengorbankan blok sebelumnya). Forbidden attack GCM **memulihkan authentication key `H`, bukan kunci AES** — cukup untuk *forgery*, tidak untuk mendekripsi pesan lain.

## Deteksi & Mitigasi

**Perbaikan utama (crypto-layer) — fix yang sebenarnya:**

- **Gunakan AEAD dengan nonce unik.** Pilih **AES-GCM** atau **ChaCha20-Poly1305**, dan jamin nonce **tidak pernah** berulang per kunci (counter monotonik atau random 96-bit + key rotation; pertimbangkan **AES-GCM-SIV** yang tahan nonce-misuse). Reuse nonce = celah forbidden attack langsung.
- **Jangan pakai ECB.** Untuk kebutuhan block mode, pakai CBC **acak IV per pesan** *plus* MAC (**encrypt-then-MAC**, mis. HMAC-SHA256) atau langsung AEAD. ECB tidak boleh dipakai untuk data apa pun yang berstruktur.
- **Tutup padding oracle.** Verifikasi MAC **sebelum** dekripsi/cek padding, kembalikan **pesan error & timing seragam** untuk semua kegagalan (constant-time), jangan bedakan "padding error" dari "auth error".
- **Hindari malleability.** Karena CTR/CFB/OFB/CBC tidak ber-autentikasi sendiri, selalu lapisi MAC; jangan andalkan kerahasiaan untuk integritas.

**Bridge ke hardening & blue-team (kaitan nyata ke Modul A/C):**

- **Pakai library kripto teruji, bukan DIY.** Audit kode yang memanggil `AES.new(...)` untuk mode hardcoded `MODE_ECB`, IV/nonce statis (`b"\x00"*16`), atau nonce dari sumber non-unik. Ini bagian dari *secure configuration review* (Modul C — Hardening).
- **Logging & deteksi anomali** (jembatan ke **Modul A — Logging/Auditing** & **Modul C — Log Forensic**): pantau **lonjakan padding/decrypt error** (tanda padding-oracle automation), **nonce/IV berulang**, dan **blok ciphertext identik berulang** (ECB) pada token/cookie. Pola request beda-1-byte beruntun = byte-at-a-time/oracle.
- **Hardening konfigurasi TLS/transport.** Nonaktifkan cipher suite CBC lama & SSLv3 (POODLE adalah padding oracle pada CBC), utamakan suite AEAD (GCM/ChaCha20-Poly1305) dengan TLS 1.2+/1.3. Kelola kunci di secret manager/HSM dan rotasi berkala (bridge ke manajemen kredensial di hardening).

## Mini-Lab

**Skenario A (ECB byte-at-a-time):** diberi oracle `encrypt(input)` yang mengembalikan AES-ECB dari `input || FLAG`. **Lakukan:** deteksi ECB (kirim `"A"*32`, lihat dua blok pertama identik) → pulihkan FLAG satu byte demi satu dengan skrip di atas → **dapatkan flag** lengkap.

**Skenario B (stream nonce reuse):** diberi dua ciphertext CTR dengan nonce sama, salah satunya plaintext-nya diketahui. **Lakukan:** `KS = C1 ⊕ P1`, lalu `P2 = C2 ⊕ KS` → **plaintext kedua berisi flag**.

Kerjakan langsung di **CryptoHack — Symmetric Ciphers** (target legal, gratis):

- **ECB Oracle** — byte-at-a-time ECB decryption.
- **Flipping Cookie** — CBC bit-flipping untuk auth bypass.
- **Symmetry** — properti simetri **OFB** (enkripsi = dekripsi karena keystream hanya bergantung pada IV, bukan plaintext).
- **Forbidden Fruit** — **GCM nonce reuse / forbidden attack** untuk forge tag.

## Referensi & Latihan

- **CryptoHack — Symmetric Cryptography / AES** (kursus + tantangan ECB/CBC/OFB/CTR/GCM): https://cryptohack.org/courses/symmetric/
- **Cryptopals Crypto Challenges** — Set 1–3: deteksi ECB, byte-at-a-time (Set 2), CBC bit-flip (#16) & **padding oracle (#17)**, CTR/keystream reuse (Set 3): https://cryptopals.com
- **Forbidden attack** — *Nonce-Disrespecting Adversaries: Practical Forgery Attacks on GCM in TLS* (Böck, Zauner, Devlin, eprint 2016/475) + writeup elttam "Key Recovery Attacks on GCM" + blog `frereit.de/aes_gcm`.
- **PortSwigger** (untuk konteks padding oracle/CBC di web) & **HackTheBox** Crypto modules; **root-me** kategori *Cryptanalysis*; **pwn.college** modul kriptografi.
- **OWASP Cryptographic Storage Cheat Sheet** & **NIST SP 800-38A/38D** (definisi mode CBC/CTR & GCM) untuk sisi mitigasi.

> **Etika:** Hanya gunakan pada lab pribadi, platform latihan resmi (CryptoHack, Cryptopals, root-me, HTB), target CTF, atau sistem dengan **izin tertulis**. Menyerang kriptografi sistem milik orang lain tanpa izin melanggar hukum.
