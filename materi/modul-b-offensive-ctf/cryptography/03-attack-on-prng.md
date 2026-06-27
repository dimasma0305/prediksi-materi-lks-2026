# 3. Attack on PRNG

> Sebagian besar *random* di software bukan acak sungguhan, melainkan **Pseudo-Random Number Generator (PRNG)**: keluaran deterministik dari sebuah *state* internal. Bila PRNG bersifat **non-cryptographic** (Mersenne Twister, LCG, LFSR), keluarannya yang terlihat cukup untuk **memulihkan state**, lalu **memprediksi seluruh angka berikutnya (dan sebelumnya)**. Di CTF LKSN 2026, ini muncul sebagai soal "tebak angka berikutnya", token/OTP yang bisa ditebak, nonce/kunci yang dibangkitkan dari `random`, atau stream cipher berbasis LFSR — semuanya bermuara pada **dapatkan flag**.

## Konsep

PRNG memetakan *state* `s` ke output via fungsi deterministik, lalu memperbarui state. Tiga keluarga klasik yang wajib dikenali (sesuai kisi-kisi):

- **Mersenne Twister (MT19937)** — PRNG default Python (`random`), PHP `mt_rand`, Ruby, dan banyak lainnya. State = **624 word 32-bit**. Output adalah word state yang sudah di-*temper*; karena tempering **invertible**, 624 output 32-bit beruntun cukup untuk merekonstruksi seluruh state.
- **LCG (Linear Congruential Generator)** — rekurens `s_{n+1} = (a·s_n + c) mod m`. Dipakai `java.util.Random`, MSVC CRT `rand()`, banyak `rand()` C. Linier → parameter dan state bisa dipulihkan dari sedikit output.
- **LFSR (Linear Feedback Shift Register)** — register bit yang di-*shift* dengan umpan balik XOR dari *tap* tertentu (polinomial koneksi). Basis banyak stream cipher klasik (mis. A5/1). Linier di GF(2) → dapat dipecahkan dengan aljabar linier.

Intinya: ketiganya **linier / invertible**, jadi tidak ada "kerja keras kriptografis" — hanya rekonstruksi state dari observasi. Bandingkan dengan **CSPRNG** (`secrets`, `os.urandom`) yang dirancang tahan prediksi.

## Cara Kerja

**MT19937.** Setiap output `y` berasal dari satu word state `x` lewat fungsi tempering (serangkaian shift/AND/XOR). Tempering punya invers (`untemper`), sehingga dari 624 output kita peroleh kembali 624 word state mentah → seed ulang sebuah MT identik → prediksi semua output lanjutan. *State recovery* (prediksi maju) berbeda dari *seed recovery* (memulihkan seed awal, mis. brute-force seed berbasis waktu — lihat CryptoPals 22).

**LCG.** Karena `c` lenyap pada selisih, definisikan `t_n = s_{n+1} − s_n`; maka `t_{n+1} = a·t_n mod m`. Akibatnya `t_{n+2}·t_n − t_{n+1}²` adalah **kelipatan `m`** → `gcd` beberapa sampel memulihkan `m`. Lalu `a = t_1 · inv(t_0) mod m` dan `c = s_1 − a·s_0 mod m`. Dua kasus harus dipisah:

- **Parameter tak diketahui + output state penuh** → metode `gcd`/inverse di atas.
- **Parameter diketahui** (mis. Java: `a=0x5DEECE66D`, `c=0xB`, `m=2^48`) dan output **dipotong** (Java `nextInt` hanya mengembalikan bit atas) → pulihkan state dengan brute-force bit rendah yang sedikit, atau **lattice/LLL** untuk *truncated LCG*.

**LFSR.** Barisan output memenuhi rekurens linier berderajat `L` (panjang register). **Berlekamp–Massey** memulihkan polinomial koneksi (dan `L`) hanya dari **≥ 2L bit** output beruntun; setelah itu register dapat dijalankan maju/mundur.

## Indikator / Cara Mengenali

- Soal memberi **beberapa angka beruntun** lalu meminta menebak angka/seed berikutnya — sinyal kuat PRNG predictable.
- Source memakai `random.` (bukan `secrets`/`SystemRandom`), `mt_rand`, `java.util.Random`, atau implementasi LCG/LFSR buatan sendiri.
- Output 32-bit utuh dalam jumlah banyak (≈624) → MT19937 *full state recovery* mungkin.
- Rekurens terlihat seperti `x = (a*x + c) % m` di handout → LCG.
- Keystream/cipher berbasis shift + XOR tap, atau output **bit demi bit** → LFSR (coba Berlekamp–Massey).
- Token/OTP/nonce/"kunci" diturunkan dari PRNG yang sama dengan output yang bocor.

## Langkah Eksploitasi

*Mulai dari: shell dengan dependency terpasang (`pip install randcrack sympy gmpy2` di virtualenv) dan output PRNG yang sudah dikumpulkan dari soal/koneksi ke list Python.*

1. **Identifikasi PRNG.** Baca source bila ada; jika tidak, fingerprint dari lebar output, jumlah sampel, dan pola rekurens.
2. **Kumpulkan output yang cukup.** MT19937: **624 word 32-bit beruntun**. LCG (parameter tak diketahui): ≥ 6 state berurutan. LFSR: ≥ 2L bit beruntun.
3. **Selesaikan lebar/encoding.** Bila output bukan 32-bit (mis. `getrandbits(64)`, `random()`), **pecah/normalisasi ke word 32-bit** dengan urutan yang benar — verifikasi urutan secara empiris di lab, jangan diasumsikan.
4. **Rekonstruksi state/parameter.** MT19937: untemper → clone (`randcrack`/`mersenne-twister-predictor`). LCG: `gcd` → `a` → `c`. LFSR: Berlekamp–Massey.
5. **Prediksi / mundur.** Hasilkan output target (berikutnya untuk tebakan, atau **backtrack** untuk seed/keystream sebelumnya).
6. **Konversi ke flag.** Pakai angka prediksi untuk menebak token, mendekripsi keystream, atau memenuhi syarat soal.

## Tools

| Tool | Fungsi singkat |
|---|---|
| **`randcrack`** (pip) | Clone MT19937 Python: submit 624 output 32-bit, lalu `predict_getrandbits`/`predict_randint` |
| **`mersenne-twister-predictor`** (pip, `MT19937Predictor`) | Prediktor MT19937; `setrandbits(x,32)` ×624 lalu `getrandbits` memprediksi |
| **`ExtendMT19937Predictor`** | Selain prediksi maju, **backtrack** state ke output sebelumnya |
| **`SageMath`** | `berlekamp_massey` (LFSR), lattice/LLL untuk truncated LCG, aljabar linier GF(2) |
| **`z3-solver`** | Pemulihan state simbolik (MT/LCG/LFSR) saat encoding output rumit |
| **`sympy` / `gmpy2`** | `gcd`, modular inverse, aritmetika besar untuk solver LCG manual |
| **CryptoPals Set 3** | Acuan kanonik latihan MT19937 (clone/untemper/seed) |

## Contoh / Payload

**MT19937 — clone & prediksi (Python `random`).** Diberi 624 output `getrandbits(32)` beruntun:

```python
from randcrack import RandCrack

rc = RandCrack()
for v in leaked_outputs:          # tepat 624 nilai 32-bit, BERURUTAN
    rc.submit(v)

# state ter-rekonstruksi; prediksi output berikutnya seperti random.getrandbits(32)
print(rc.predict_getrandbits(32))
print(rc.predict_randint(0, 2**32 - 1))
```

Alternatif dengan `mersenne-twister-predictor` (drop-in `random.Random`):

```python
from mt19937predictor import MT19937Predictor

p = MT19937Predictor()
for v in leaked_outputs:          # 624 × 32-bit
    p.setrandbits(v, 32)
assert p.getrandbits(32) == target_next   # cocok dengan output korban berikutnya
```

> **Gotcha bit-consumption.** Serangan paling bersih saat sumber memakai `getrandbits(32)` (word penuh). `random.random()` memakai dua word tapi **membuang bit rendah**; `randbelow`/range non-pangkat-2 mengonsumsi bit **bervariasi** — keduanya menyulitkan rekonstruksi state. Untuk output > 32-bit, pecah ke word 32-bit dan **uji urutannya di lab**.

Bila korban memakai `getrandbits(64)`, tiap nilai = dua word (CPython membangkitkan word **rendah lalu tinggi** — word pertama yang ditarik = 32 bit bawah hasil); pecah sebelum di-feed (verifikasi urutan dengan satu nilai pembanding):

```python
def split64(values):                 # 312 nilai 64-bit -> 624 word 32-bit
    words = []
    for v in values:
        words.append(v & 0xffffffff)           # word rendah dibangkitkan dulu
        words.append((v >> 32) & 0xffffffff)   # lalu word tinggi
    return words
```

**LCG — pulihkan `m, a, c` dari output state penuh:**

```python
from math import gcd
from functools import reduce
from sympy import mod_inverse

def recover_modulus(states):
    diffs  = [b - a for a, b in zip(states, states[1:])]
    zeroes = [c*a - b*b for a, b, c in zip(diffs, diffs[1:], diffs[2:])]
    return abs(reduce(gcd, zeroes))           # bisa kelipatan kecil m → pakai banyak sampel

def recover_multiplier(states, m):
    return (states[2] - states[1]) * mod_inverse(states[1] - states[0], m) % m

def recover_increment(states, a, m):
    return (states[1] - a * states[0]) % m

s = [collected, sequential, lcg, outputs, here, ...]  # >= 6 state berurutan
m = recover_modulus(s)
a = recover_multiplier(s, m)
c = recover_increment(s, a, m)
next_state = (a * s[-1] + c) % m
```

> Bila `m` hasil `gcd` ternyata kelipatan kecil dari modulus asli, tambah sampel dan/atau bagi faktor-faktor kecil. Untuk **truncated LCG** (hanya bit atas yang bocor, seperti `java.util.Random.nextInt`) metode di atas tidak cukup — gunakan brute-force bit rendah atau **LLL**.

**LFSR — pulihkan polinomial koneksi (SageMath):**

```python
# SageMath: berlekamp_massey butuh >= 2L bit keystream beruntun
bits = [GF(2)(b) for b in observed_keystream_bits]
conn = berlekamp_massey(bits)        # polinomial koneksi minimal
L    = conn.degree()                 # panjang LFSR ter-deteksi
print("L =", L, " poly =", conn)
# dengan conn + L bit awal, register dapat di-roll maju untuk regenerasi keystream
```

## Deteksi & Mitigasi

PRNG-misuse adalah **cacat desain/kode**, bukan sinyal yang bisa ditangkap IDS di jaringan — jangan klaim mendeteksinya "di kabel". Deteksi nyata = **code review / SAST / grep** pada konteks keamanan:

- **Cari pemakaian RNG non-kripto untuk keperluan rahasia:** `random.` (Python), `Math.random`, `mt_rand`/`rand` (PHP), `java.util.Random`, `srand/rand` (C), atau LCG/LFSR buatan sendiri — bila dipakai membuat **token, session ID, password-reset, OTP, kunci, nonce, salt**. Itu temuan **CRITICAL**.
- **Aturan baku (the real fix):** gunakan **CSPRNG** — `secrets` / `random.SystemRandom` / `os.urandom` (Python), `java.security.SecureRandom`, `crypto.randomBytes` (Node), `random_bytes` (PHP). Jangan pernah seed PRNG dengan waktu/PID untuk nilai keamanan.
- **Hindari kebocoran output state penuh.** Jangan ekspos banyak nilai PRNG mentah ke user; bila tak terhindarkan, pisahkan generator keamanan dari generator non-keamanan.

**Bridge ke hardening (kaitan ke Modul A).** Kelemahan ini berujung pada **account takeover**: token reset password/session yang predictable membuat penyerang menebak token korban tanpa kredensial. Hardening = pastikan semua *secret/token/nonce* berasal dari CSPRNG, audit dependensi yang masih memakai PRNG lemah, dan jadikan "insecure randomness" bagian dari checklist *secure code review* (jembatan ke Modul A — Secure Configuration & Modul C — Log & Forensic untuk mendeteksi pola brute-force token di log aplikasi).

## Mini-Lab

**Skenario:** Service membuka koneksi, mencetak **624 angka** hasil `random.getrandbits(32)`, lalu meminta Anda menebak **angka ke-625** untuk membuka flag.

**Prasyarat (sekali saja):** Python 3.8+ dengan virtualenv (pip sistem sering diblokir PEP 668):

```bash
python3 -m venv venv && source venv/bin/activate
pip install randcrack
```

**Setup lab lokal** (di CTF nyata `leaked_outputs` ditarik dari koneksi `nc`/`pwntools`; di sini kita simulasikan service-nya secara lokal dengan flag tertanam, supaya bisa dijalankan input→flag tanpa server). Simpan sebagai `lab.py`:

```python
import random
from randcrack import RandCrack

# --- sisi "service" (di CTF nyata ini remote) ---
rng = random.Random()                          # MT19937, di-seed acak oleh OS
leaked_outputs = [rng.getrandbits(32) for _ in range(624)]   # 624 angka yang dibocorkan
def unlock(guess):                             # buka flag jika tebakan ke-625 benar
    return "LKSN{mt19937_state_recovered}" if guess == rng.getrandbits(32) else "TEBAKAN SALAH"

# --- sisi penyerang ---
rc = RandCrack()
for v in leaked_outputs:                        # tepat 624 nilai 32-bit, BERURUTAN
    rc.submit(v)
guess = rc.predict_getrandbits(32)              # prediksi angka ke-625
print(unlock(guess))
```

1. Pastikan virtualenv aktif dan `randcrack` terpasang (langkah Prasyarat).
2. Jalankan:
   ```bash
   python3 lab.py
   ```
3. **Hasil:** → output mencetak `LKSN{mt19937_state_recovered}`. Artinya state MT19937 berhasil direkonstruksi dari 624 output dan prediksi angka ke-625 **tepat**, sehingga `unlock()` membuka flag.

> Untuk soal remote sungguhan, ganti blok "service" dengan koneksi: `from pwn import remote; io = remote(host, port)`, lalu `leaked_outputs = [int(io.recvline()) for _ in range(624)]` dan kirim `io.sendline(str(guess).encode())`.

Variasi latihan: (a) ganti sumber ke LCG, kumpulkan ≥6 state, pulihkan `m, a, c` dengan solver LCG di **Contoh / Payload**, lalu prediksi `next_state`; (b) regenerasi keystream LFSR via `berlekamp_massey` (SageMath) lalu XOR untuk mendekripsi pesan.

## Referensi & Latihan

- **CryptoPals — Set 3 (Challenge 21–24):** implement MT19937, **clone dari output (untemper, #23)**, dan crack seed berbasis waktu (#22) — acuan kanonik: https://cryptopals.com/sets/3
- **CryptoHack — kategori Symmetric / CTF Archive:** terdapat tantangan PRNG/Mersenne (mis. arsip *Real Mersenne*) dan kombinasi **LCG**; cek katalog di https://cryptohack.org/challenges/
- **root-me — kategori Cryptanalysis:** soal LFSR/PRNG (rujuk daftar kategori, jangan asumsikan judul).
- **HackTheBox:** challenge crypto bertema PRNG/predictable randomness pada arsip CTF.
- **Tooling & bacaan:** `randcrack`, `mersenne-twister-predictor`, dan `ExtendMT19937Predictor` (PyPI/GitHub `kmyk`, `NonupleBroken`); SageMath `berlekamp_massey` untuk LFSR.

> **Etika:** Teknik ini **hanya** untuk lab pribadi, platform latihan resmi, target CTF, atau sistem dengan **izin tertulis eksplisit**. Memprediksi PRNG pada sistem orang lain (token, sesi, OTP) tanpa izin adalah pelanggaran hukum.
