# 2. Attack on RSA

> RSA aman secara matematis hanya jika **parameternya dipilih benar**. Di CTF, soal RSA hampir tidak pernah meminta memecahkan faktorisasi 2048-bit secara brute force — yang diuji adalah kemampuan mengenali **kesalahan implementasi atau parameter lemah** (eksponen terlalu kecil, prima berdekatan, modulus dipakai ulang, modulus tersusun dari banyak prima) lalu mengeksploitasinya secara terprogram untuk memulihkan plaintext atau private key. Di LKSN 2026 keluarga serangan yang paling sering muncul: **Håstad broadcast**, **common modulus**, **twin/close prime (Fermat)**, dan **multi-prime RSA**.

## Konsep

RSA bekerja di atas modulus `n = p·q` (dua prima besar), eksponen publik `e`, dan eksponen privat `d = e⁻¹ mod φ(n)` dengan `φ(n) = (p-1)(q-1)`. Enkripsi: `c = mᵉ mod n`; dekripsi: `m = cᵈ mod n`. Keamanannya bersandar pada sulitnya **memfaktorkan `n`** dan tidak adanya struktur yang bisa dieksploitasi.

Soal CTF merusak salah satu asumsi itu. Empat kelas yang menjadi fokus halaman ini:

- **Håstad broadcast** — pesan **sama** dikirim ke banyak penerima dengan `e` kecil (sering `e=3`) dan modulus berbeda. Tanpa padding acak, plaintext dapat dipulihkan via CRT + akar pangkat-`e`.
- **Common modulus** — pesan **sama** dienkripsi dengan **modulus `n` sama** tetapi dua eksponen publik berbeda `e₁`, `e₂` yang coprime. Plaintext pulih tanpa memfaktorkan `n`.
- **Twin / close prime** — `p` dan `q` dipilih **terlalu berdekatan** (mis. twin prime `q = p+2`, atau `|p−q|` kecil). Modulus pecah cepat dengan **Fermat factorization**.
- **Multi-prime RSA** — `n = p·q·r·…` (lebih dari dua faktor). Tiap faktor jadi lebih kecil untuk panjang `n` yang sama, sehingga ECM/Pollard menemukannya jauh lebih cepat.

## Cara Kerja

Letak kelemahan tiap kelas:

- **Håstad.** Untuk `e=3` dan tiga ciphertext `cᵢ = m³ mod nᵢ` dengan `nᵢ` pairwise coprime, **CRT** menghasilkan `x ≡ m³ mod (n₁n₂n₃)`. Karena `m < min(nᵢ)`, maka `m³ < n₁n₂n₃`, sehingga `x` adalah `m³` **sebagai integer biasa** — cukup ambil **akar pangkat tiga bulat**. Generalisasinya butuh `≥ e` ciphertext. (Versi Håstad yang lebih kuat juga menangani padding linear lewat Coppersmith.)
- **Common modulus.** Dari `gcd(e₁,e₂)=1`, Extended Euclidean memberi `a·e₁ + b·e₂ = 1`. Maka `c₁ᵃ · c₂ᵇ ≡ m^(a·e₁+b·e₂) ≡ m¹ (mod n)`. Salah satu dari `a`/`b` negatif, jadi dipakai modular inverse dari ciphertext yang bersangkutan.
- **Twin/close prime → Fermat.** Tulis `n = a² − b² = (a−b)(a+b)` dengan `p = a−b`, `q = a+b`. Mulai `a = ⌈√n⌉` dan naik 1 demi 1 sampai `a²−n` menjadi kuadrat sempurna `b²`. Bila `|p−q|` kecil, `a` hanya bergeser sedikit dari `√n`; untuk twin prime (`b=1`) ketemu di iterasi pertama. Fermat efisien selama `(p−q)/2` berada di sekitar `n^(1/4)` atau lebih kecil.
- **Multi-prime.** `φ(n) = ∏(pᵢ−1)`. Begitu **semua** faktor diketahui, `d` dihitung seperti biasa. Kuncinya: dengan 3+ faktor, tiap prima jauh lebih kecil sehingga **integer factorization** (factordb/ECM/yafu) praktis menyelesaikannya.

## Indikator / Cara Mengenali

Baca file soal (`output.txt`, `chall.py`, sertifikat `.pem`) dan cocokkan polanya:

- **`e` sangat kecil (3, 5, 7) + banyak pasangan `(n, c)`** dengan `n` berbeda untuk **pesan yang sama** → kandidat **Håstad broadcast**.
- **`n` identik** muncul dua kali dengan `e₁ ≠ e₂` dan dua ciphertext `c₁`, `c₂` → **common modulus**.
- **`|p−q|` kecil** atau soal menyebut "twin/close primes": uji **Fermat** — `⌈√n⌉²` hanya sedikit di atas `n`, akar kuadrat dari `n` "hampir bulat".
- **`n` punya lebih dari dua faktor** (cek [factordb.com](http://factordb.com) atau panjang bit yang ganjil untuk semiprime) → **multi-prime**.
- Sinyal lain yang sering berdampingan: **`d` kecil** (Wiener, `d < n^0.292` Boneh–Durfee), **`e` besar mendekati `n`** (juga indikasi `d` kecil), prima **shared** antar banyak public key (batch-GCD), atau key buatan **library ROCA** (CVE-2017-15361).

## Langkah Eksploitasi

1. **Parse parameter.** Ambil `n`, `e`, `c` dari teks/`.pem`. Untuk public key: `openssl rsa -pubin -in key.pem -text -noout` membongkar `n` dan `e`.
2. **Fingerprint kelemahan.** Cek `e` (kecil? sama dengan `n`?), jumlah pasangan `(n,c)`, apakah `n` berulang, apakah `√n` hampir bulat, dan apakah `n` semiprime (factordb).
3. **Coba faktorisasi murah dulu.** `factordb` (sudah terfaktor?), **Fermat** (close primes), **Pollard p−1 / ECM** (faktor kecil / smooth, relevan untuk multi-prime).
4. **Pilih serangan struktural** sesuai indikator: Håstad (CRT+root), common modulus (egcd), atau hitung `φ(n)` dari semua faktor (twin prime / multi-prime) lalu `d`.
5. **Pulihkan `m`** lalu decode: `long_to_bytes(m)`. Cari pola flag (`flag{…}`, `picoCTF{…}`, `crypto{…}`).
6. **Verifikasi & otomasi.** Jika ragu, lempar ke **RsaCtfTool** yang mencakup banyak kelas sekaligus.

## Tools

| Tool | Fungsi singkat |
|---|---|
| **pycryptodome** (`Crypto.Util.number`) | `inverse`, `long_to_bytes`, `GCD`, `getPrime` — building block solver |
| **gmpy2** | Aritmetika presisi besar cepat: `iroot` (akar pangkat-`e`), `isqrt`, `is_square` |
| **sympy** | `crt`, `gcdex`, `factorint`, `integer_nthroot` untuk solver murni-Python |
| **SageMath** | `crt`, Coppersmith (`small_roots`), lattice — untuk Håstad berpadding & serangan lanjutan |
| **RsaCtfTool** | Otomasi banyak serangan (Wiener, Håstad, Fermat, common modulus/factor) atas public key/ciphertext |
| **factordb** (`factordb-pycli`) | Lookup faktor `n` yang sudah dikenal publik — sering langsung selesai |
| **yafu / cado-nfs / GMP-ECM** | Integer factorization berat (multi-prime, faktor menengah) di luar jangkauan RsaCtfTool |
| **openssl** | Parsing/inspeksi key & sertifikat (`rsa -text`, `x509 -text`) |

## Contoh / Payload

```python
# ── Common modulus: c1=m^e1, c2=m^e2 mod n yang SAMA, gcd(e1,e2)=1 ──
from Crypto.Util.number import inverse, long_to_bytes
from math import gcd

def common_modulus(c1, c2, e1, e2, n):
    assert gcd(e1, e2) == 1
    g, a, b = _egcd(e1, e2)            # a*e1 + b*e2 = 1
    if a < 0:
        c1, a = inverse(c1, n), -a     # pakai invers untuk eksponen negatif
    if b < 0:
        c2, b = inverse(c2, n), -b
    m = (pow(c1, a, n) * pow(c2, b, n)) % n
    return long_to_bytes(m)

def _egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x, y = _egcd(b, a % b)
    return (g, y, x - (a // b) * y)
```

```python
# ── Håstad broadcast: e ciphertext untuk m yang sama, n berbeda (di sini e=3) ──
from sympy.ntheory.modular import crt
from gmpy2 import iroot, mpz
from Crypto.Util.number import long_to_bytes

def hastad(ns, cs, e=3):
    x, _ = crt(ns, cs)                 # x ≡ m^e mod (∏ ns), ns pairwise coprime
    m, exact = iroot(mpz(int(x)), e)   # m^e < ∏ ns  ⇒  akar bulat tepat
    assert exact, "akar tidak bulat: butuh >= e ciphertext atau ada padding"
    return long_to_bytes(int(m))
# Bonus: jika dua n TIDAK coprime, gcd(ni, nj) > 1 langsung membocorkan faktor!
```

```python
# ── Fermat factorization: efektif saat p dan q berdekatan (twin/close primes) ──
from gmpy2 import isqrt, is_square, mpz
from Crypto.Util.number import inverse, long_to_bytes

def fermat_factor(n):
    a = isqrt(mpz(n))
    if a * a < n:
        a += 1
    while True:
        b2 = a * a - n
        if is_square(b2):
            b = isqrt(b2)
            return int(a - b), int(a + b)   # p, q
        a += 1

def decrypt_two_primes(n, e, c):
    p, q = fermat_factor(n)
    d = inverse(e, (p - 1) * (q - 1))
    return long_to_bytes(pow(c, d, n))
```

```python
# ── Multi-prime: n = p*q*r*... ; faktor dulu, lalu phi = ∏(pi - 1) ──
from sympy import factorint
from Crypto.Util.number import inverse, long_to_bytes

def decrypt_multiprime(n, e, c):
    factors = factorint(n)                       # {p:1, q:1, r:1, ...} (kecil/medium)
    phi = 1
    for prime, mult in factors.items():
        phi *= (prime - 1) * prime ** (mult - 1) # umumnya mult=1 ⇒ (prime-1)
    d = inverse(e, phi)
    return long_to_bytes(pow(c, d, n))
# Untuk faktor besar gunakan yafu / cado-nfs / GMP-ECM, lalu masukkan faktornya manual.
```

```bash
# ── Otomasi cepat dengan RsaCtfTool (mencakup Fermat, Håstad, Wiener, common modulus) ──
RsaCtfTool --publickey key.pem --decryptfile flag.enc      # serang satu key
RsaCtfTool -n <N> -e <E> --decrypt <C> --attack fermat     # paksa satu attack
RsaCtfTool --publickey "key*.pem" --private                # common factor antar banyak key
```

## Deteksi & Mitigasi

**Perbaikan inti (sisi pembuat kunci) — ini fix yang sebenarnya:**

- **Gunakan key generation standar dan teruji.** OpenSSL/`cryptography`/`pycryptodome` dengan **`e = 65537`** dan **dua prima acak independen** ≥ 2048-bit. Jangan gulung generator prima sendiri.
- **Padding wajib.** Pakai **OAEP** untuk enkripsi dan **PSS** untuk tanda tangan. OAEP/PSS mematikan Håstad, low-exponent root, dan kelas malleability lain karena pesan tidak lagi `mᵉ` mentah.
- **Jangan pernah pakai ulang modulus** untuk pengguna/keperluan berbeda → memutus **common modulus**. Satu key = satu `n`, satu peran.
- **Pastikan `|p − q|` besar** (prima diundi independen, bukan `q = nextprime(p)`) → mematikan **Fermat/twin prime**. Hindari **multi-prime** kecuali memang dibutuhkan dan tiap faktor tetap besar (≥ 1024-bit per faktor).
- **Hindari `d` kecil** (jangan optimasi dekripsi dengan `d` mungil) → menutup **Wiener/Boneh–Durfee**.

**Bridge ke hardening infrastruktur (blue-team — kaitan nyata ke Modul C):**

- **Audit & rotasi key pada layanan TLS/SSH (PKI hardening, Modul C).** Sertifikat/host key yang dipakai produksi harus berasal dari RNG yang sehat. Insiden nyata: **CVE-2008-0166** (Debian OpenSSL, entropi prediktabel) menyusutkan ruang kunci ke hanya puluhan ribu kemungkinan sehingga seluruh key bisa dienumerasi lebih dulu (blacklist) — pertahanannya adalah regenerasi key + audit berkala.
- **Deteksi key lemah secara aktif.** Jalankan **batch-GCD** atas korpus public key (cari `gcd` antar modulus > 1 = prima dipakai bersama), dan pindai key produk **ROCA** (**CVE-2017-15361**, RSALib Infineon) dengan detektor `roca-detect`. Ganti dan revoke yang positif.
- **Logging & inventory kunci** (jembatan ke Modul A — Logging/Auditing & Modul C — Log Forensic): catat algoritma, panjang, dan umur tiap key; alarmkan key < 2048-bit, `e=3`, atau sertifikat kedaluwarsa. Terapkan **key rotation policy** dan simpan private key di penyimpanan terbatas (file permission ketat / HSM).

## Mini-Lab

**Skenario A (common modulus):** Diberikan satu `n`, dua eksponen `e1=17`, `e2=65537`, dan dua ciphertext `c1`, `c2` untuk pesan sama. Buktikan `gcd(e1,e2)=1`, jalankan solver `common_modulus()` di atas, dan pulihkan plaintext → **flag**.

**Skenario B (twin prime):** Diberikan `n` dan `c` dengan `e=65537`, dan petunjuk "primanya kembar". Hitung `⌈√n⌉` (perhatikan `√n` nyaris bulat), jalankan `fermat_factor(n)` → dapat `p,q` dalam hitungan iterasi → susun `d` → dekripsi `c` menjadi **flag**.

Verifikasi cepat: kedua skenario juga harus selesai dengan `RsaCtfTool --attack common_modulus_related_message` dan `--attack fermat`. Bila hasil solver manual dan RsaCtfTool cocok, jawaban valid.

## Referensi & Latihan

- **CryptoHack — RSA** (jalur lengkap: factoring, low exponent, **Håstad broadcast**, common modulus, Wiener): https://cryptohack.org/courses/
- **pwn.college — Cryptography** modul kunci-publik untuk drilling solver bertahap.
- **root-me — Cryptanalysis / Crypto** (challenge RSA: faktorisasi, multi-prime, common modulus).
- **HackTheBox** dan **picoCTF** (kategori Crypto: banyak RSA "weak parameters" klasik).
- **RsaCtfTool** (referensi attack + caveat: hanya semiprime, multi-prime pakai yafu/cado-nfs): https://github.com/RsaCtfTool/RsaCtfTool
- **FactHacks / "Mining your Ps and Qs" (Heninger et al.)** untuk Fermat & batch-GCD; **ROCA paper** (CRoCS, CVE-2017-15361) untuk weak key generation di dunia nyata.

> **Etika:** Teknik di sini hanya untuk lab pribadi, platform latihan resmi, target CTF, atau sistem dengan izin tertulis eksplisit. Memfaktorkan atau mendekripsi kunci milik orang lain tanpa izin melanggar hukum.
