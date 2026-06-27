# 6. Attack on DSA

> DSA dan turunannya **ECDSA** aman hanya jika **nonce `k` benar-benar acak, rahasia, dan tidak pernah dipakai ulang**. Di CTF, soal tanda tangan digital nyaris tidak pernah menuntut memecahkan diskret logaritma — yang diuji adalah mengenali **kebocoran nonce** (dipakai ulang, sebagian diketahui, atau dari RNG lemah) untuk **memulihkan private key**, lalu menempa tanda tangan baru. Halaman ini juga menyinggung **attack on RSA signature** yang bekerja berbeda: bukan pemulihan kunci lewat nonce, melainkan **forgery** memanfaatkan malleability RSA mentah dan verifikasi padding yang longgar (Bleichenbacher `e=3`). Benang merahnya: **nonce bocor → DSA/ECDSA jebol**; **padding/verifikasi longgar → RSA signature dipalsukan**.

## Konsep

**DSA** bekerja di grup `Z_p*`: prima `p`, prima `q | (p-1)`, generator `g` berorde `q`. Private key `x`, public key `y = g^x mod p`. Untuk menandatangani hash `H(m)`:

```
k  = nonce acak ∈ [1, q-1]
r  = (g^k mod p) mod q
s  = k⁻¹ · (H(m) + x·r) mod q      → signature = (r, s)
```

**ECDSA** adalah DSA **yang dipindah ke grup kurva eliptik**: base point `G` berorde `n`, private key `d`, public key `Q = d·G`. Strukturnya **identik**, hanya grupnya yang berbeda (titik kurva menggantikan `g^k mod p`, orde `n` menggantikan `q`):

```
k  = nonce acak ∈ [1, n-1]
r  = (k·G).x mod n
s  = k⁻¹ · (H(m) + d·r) mod n      → signature = (r, s)
```

Karena keduanya satu keluarga, **serangan nonce yang sama berlaku untuk DSA maupun ECDSA** — yang berubah hanya modulus orde grup (`q` vs `n`). **RSA signature** adalah skema yang **berbeda total**: `s = m^d mod n`, verifikasi `m ≟ s^e mod n`. Tidak ada nonce; kelemahannya adalah **malleability** (sifat perkalian) dan **verifikasi padding yang tidak ketat**.

> Halaman [02-attack-on-rsa.md](02-attack-on-rsa.md) membahas pemulihan kunci/plaintext RSA lewat parameter lemah. Di sini RSA dibahas **khusus untuk pemalsuan tanda tangan**.

## Cara Kerja

Letak kelemahan tiap kelas:

- **Nonce reuse (DSA/ECDSA).** Dua tanda tangan dari **key yang sama** dengan **`k` yang sama** menghasilkan **`r` yang sama**. Dari `s₁ = k⁻¹(H₁ + x·r)` dan `s₂ = k⁻¹(H₂ + x·r)`:
  - `s₁ − s₂ = k⁻¹(H₁ − H₂)` ⇒ `k = (H₁ − H₂)·(s₁ − s₂)⁻¹ mod q`
  - lalu `x = (s₁·k − H₁)·r⁻¹ mod q`. Untuk ECDSA, semua mod `n`.
- **Known nonce.** Jika `k` satu tanda tangan diketahui (mis. bocor lewat soal), langsung `x = (s·k − H(m))·r⁻¹ mod q`.
- **Biased / partial nonce (lattice / HNP).** Bila `k` punya bias sistematis (mis. beberapa bit teratas selalu 0, atau `k` dari RNG sempit), banyak tanda tangan diubah menjadi **Hidden Number Problem (HNP)** dan diselesaikan dengan reduksi lattice **LLL/BKZ** untuk memulihkan `x`/`d`. Inilah inti **Minerva** (2019, kebocoran *bit-length* nonce via timing) dan **LadderLeak** (2020), yang menjebol ECDSA bahkan dari **< 1 bit** kebocoran nonce per tanda tangan (klaim **< 1 bit** spesifik milik LadderLeak).
- **RSA — existential forgery (multiplicative).** RSA mentah bersifat homomorfik perkalian: `s(m₁·m₂) ≡ s₁·s₂ (mod n)`. Tanpa private key, penyerang bisa **memilih `s` lebih dulu** lalu menghitung `m = s^e mod n` sebagai pesan yang "sah ditandatangani", atau menggabungkan dua tanda tangan sah menjadi tanda tangan untuk `m₁·m₂`.
- **RSA — Bleichenbacher `e=3`.** Pada PKCS#1 v1.5, verifier yang **tidak memaksa blok hash rata-kanan** (right-justified) dapat ditipu: penyerang menyusun bilangan yang **merupakan kubus sempurna**, lalu **akar pangkat tiga bulatnya** menjadi tanda tangan palsu — tanpa private key. Akar penyebabnya **bug verifikasi**, bukan matematika RSA.

## Indikator / Cara Mengenali

Baca file soal (`output.txt`, `chall.py`, `signatures.txt`, kumpulan `(r, s, H)`) dan cocokkan polanya:

- **Dua atau lebih tanda tangan dengan nilai `r` (atau `r` ECDSA) IDENTIK** dari kunci yang sama → **nonce reuse**. Ini sinyal paling kuat dan paling sering muncul.
- **Nonce dibangkitkan dari sumber mencurigakan** di kode soal: `random.randint` ber-seed, `k = LCG()`, `k` kecil/konstan, atau `k` diturunkan dari `H(m)` secara naif → **known/biased nonce**.
- **Banyak tanda tangan (ratusan+) tanpa `r` berulang**, tetapi nonce punya pola (mis. selalu `k < 2^(L−b)`) → kandidat **lattice/HNP**.
- **Verifier RSA dengan `e=3`** dan parsing padding yang membaca "dari kiri" / mengabaikan byte sisa → **Bleichenbacher forgery**.
- **Endpoint yang menandatangani input pilihan kita** lalu memverifikasinya mentah (tanpa OAEP/PSS) → **multiplicative forgery**.
- **Verifier menerima `r=0`/`s=0`** atau tidak mengecek `0 < r,s < n` → bug kelas **CVE-2022-21449 ("Psychic Signatures")**: tanda tangan `(0,0)` diterima untuk pesan apa pun.

## Langkah Eksploitasi

*Mulai dari: shell dengan dependency terpasang (`pip install pycryptodome ecdsa gmpy2` di virtualenv) dan file soal (`signatures.txt`/`chall.py` berisi kumpulan `(r, s, H)`) di tangan.*

1. **Parse semua tanda tangan.** Kumpulkan `(r, s, H(m))`, orde grup (`q` untuk DSA, `n` untuk ECDSA — biasanya dari nama kurva seperti `secp256k1`/`P-256`), dan public key.
2. **Cari `r` duplikat.** Urutkan/`Counter` nilai `r`; bila ada dua tanda tangan ber-`r` sama → langsung ke solver nonce reuse.
3. **Periksa generator nonce** di kode: konstan, kecil, LCG/Mersenne, atau bias bit → tentukan known-nonce vs lattice.
4. **Pulihkan private key** `x`/`d` dengan persamaan pada *Cara Kerja* (mod `q`/`n`). Untuk bias, susun lattice HNP lalu jalankan LLL/BKZ.
5. **Tempa tanda tangan baru.** Dengan `x`/`d` di tangan, tandatangani pesan target (mis. token admin / `{"user":"admin"}`) untuk mendapat **flag**.
6. **Jalur RSA.** Bila soal RSA signature: coba **existential forgery** (`m = s^e mod n`) atau **Bleichenbacher `e=3`**; uji juga tanda tangan `(0,0)` bila verifier ECDSA.
7. **Verifikasi** tanda tangan hasil dengan rutin verify resmi (`ecdsa`/`cryptography`) sebelum submit.

## Tools

| Tool | Fungsi singkat |
|---|---|
| **pycryptodome** (`Crypto.Util.number`) | `inverse`, `long_to_bytes`, `bytes_to_long` — building block solver nonce |
| **python-ecdsa** (`ecdsa`) | Objek kurva, `SigningKey`/`VerifyingKey`, orde `n`, tempa & verifikasi ECDSA |
| **cryptography** | Verifikasi/penandatanganan resmi (ECDSA, RSA-PSS, PKCS#1) untuk cek hasil |
| **SageMath** | Aritmetika kurva, konstruksi lattice, `matrix(...).LLL()`/BKZ untuk HNP |
| **fpylll** | LLL/BKZ cepat di Python murni untuk serangan biased-nonce |
| **lattice-attack** (bitlogik) | Skrip siap-pakai serangan ECDSA biased-nonce berbasis lattice |
| **gmpy2** | `iroot` (akar pangkat tiga) untuk Bleichenbacher `e=3`, presisi besar |
| **openssl** | Inspeksi kunci/sertifikat & cek `e` (`rsa -text`, `x509 -text`) |

## Contoh / Payload

```python
# ── DSA/ECDSA nonce reuse: dua signature ber-r SAMA, key sama, pesan beda ──
# Berlaku DSA (mod q) maupun ECDSA (mod n) — cukup ganti 'order'.
from Crypto.Util.number import inverse, long_to_bytes

def recover_key_reused_nonce(r, s1, s2, h1, h2, order):
    # k = (h1 - h2) / (s1 - s2)  mod order
    k = ((h1 - h2) * inverse((s1 - s2) % order, order)) % order
    # x = (s1*k - h1) / r        mod order
    x = ((s1 * k - h1) * inverse(r, order)) % order
    return k, x

# Contoh ECDSA secp256k1 (order n):
n  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
k, d = recover_key_reused_nonce(r, s1, s2, h1, h2, n)
print("private key d =", hex(d))
```

```python
# ── Known nonce: satu signature dengan k diketahui ⇒ private key langsung ──
def recover_key_known_nonce(r, s, h, k, order):
    return ((s * k - h) * inverse(r, order)) % order
```

```python
# ── RSA existential forgery (RSA mentah, tanpa hash/padding): pilih s dulu ──
# verifier menghitung m' = s^e mod n dan menerima apa pun yang keluar.
def forge_raw_rsa(e, n, s_chosen=2):
    m_forged = pow(s_chosen, e, n)     # pasangan (m_forged, s_chosen) selalu valid
    return m_forged, s_chosen
# Gabungan: jika punya sig s1=m1^d, s2=m2^d  ⇒  sig(m1*m2 mod n) = s1*s2 mod n
```

```python
# ── Bleichenbacher e=3 forgery: BANGUN blok PKCS#1 v1.5 lalu ambil cube root ──
import hashlib
from gmpy2 import iroot, mpz
ASN1_SHA256 = bytes.fromhex("3031300d060960864801650304020105000420")  # DigestInfo SHA-256 (RFC 8017)

def forge_pkcs1_e3(message: bytes, keysize_bits: int) -> int:
    k = keysize_bits // 8                           # panjang modulus dalam byte (mis. 256)
    h = hashlib.sha256(message).digest()
    suffix = b"\x00" + ASN1_SHA256 + h              # 00 || DigestInfo || hash
    # Blok yang BENAR = 00 01 FF..FF || suffix (rata-kanan). Verifier LONGGAR tak memeriksa
    # bahwa FF mengisi penuh sampai suffix -> taruh struktur di KIRI, sisanya jadi garbage.
    prefix = b"\x00\x01" + b"\xff" * 8 + suffix
    D = int.from_bytes(prefix + b"\x00" * (k - len(prefix)), "big")
    s, exact = iroot(mpz(D), 3)                      # akar pangkat tiga
    if not exact:
        s += 1                                      # ceil: s^3 >= D, byte rendah = garbage bebas
    return int(s)                                   # signature palsu; verifier longgar menerimanya
# Verifikasi (sisi verifier longgar): em = pow(s, 3, n).to_bytes(k, "big"); parse dari KIRI
# "00 01 FF+ 00 DigestInfo hash" dan ABAIKAN byte sisa. Syarat sukses: ruang garbage cukup,
# yaitu 3*s^2 < 2^(8*(k - len(prefix))) sehinga increment ceil tak merusak byte struktur atas.
```

```python
# ── Tempa signature setelah private key didapat (python-ecdsa) ──
from ecdsa import SigningKey, SECP256k1
sk = SigningKey.from_secret_exponent(d, curve=SECP256k1)
forged = sk.sign(b'{"user":"admin"}')   # kirim ke endpoint ⇒ flag
```

```python
# ── ECDSA biased nonce (HNP) -> konstruksi lattice konkret (SageMath) ──
# Asumsi b bit teratas tiap nonce = 0  =>  k_i < n / 2^b. Hubungan kunci:
#   k_i = u_i + d*t_i (mod n),  t_i = r_i / s_i,  u_i = h_i / s_i  (semua mod n).
# k_i kecil -> vektor pendek di lattice memuat d. Basis (m+2) x (m+2):
from sage.all import Matrix, QQ

def hnp_recover_d(sigs, n, bias_bits, G, Q):
    # sigs = list (r, s, h); G = generator, Q = d*G public key (untuk verifikasi).
    m = len(sigs)
    B = 2 ** (n.bit_length() - bias_bits)            # batas atas |k_i|
    t = [(r * pow(s, -1, n)) % n for r, s, h in sigs]
    u = [(h * pow(s, -1, n)) % n for r, s, h in sigs]
    M = Matrix(QQ, m + 2, m + 2)
    for i in range(m):
        M[i, i] = n                                  # baris kelipatan n (kongruensi mod n)
        M[m, i] = t[i]                               # baris koefisien d
        M[m + 1, i] = u[i]                           # baris konstanta
    M[m, m] = QQ(B) / n                              # skala agar komponen-d ikut tereduksi
    M[m + 1, m + 1] = B                              # penanda baris konstanta
    for row in M.LLL():                              # reduksi LLL (opsional BKZ utk bias tipis)
        if row[m + 1] != 0:                          # baris pembawa konstanta B
            for cand in [(row[m] * n / B) % n, (-row[m] * n / B) % n]:
                d = int(cand) % n
                if d * G == Q:                       # verifikasi langsung ke public key
                    return d
    return None
# N >= ceil(L / b) tanda tangan biasanya cukup (L = bit-length n). Inti Minerva/LadderLeak.
```

> **Catatan lattice (biased nonce).** Konstruksi di atas adalah Hidden Number Problem standar; untuk bias sangat tipis (mis. **< 2 bit**) ganti `LLL()` dengan `BKZ(block_size=20..40)` dan/atau tambah tanda tangan. Selalu **verifikasi `d·G == Q`** karena vektor LLL bisa memuat tanda/normalisasi berbeda. Alternatif siap-pakai: **fpylll** atau skrip **lattice-attack** (bitlogik).

## Deteksi & Mitigasi

**Perbaikan inti (sisi penandatangan) — ini fix yang sebenarnya:**

- **Nonce deterministik RFC 6979.** Turunkan `k` dari `private key + H(m)` via HMAC. Ini **mematikan nonce reuse DAN bias sekaligus** karena `k` tak lagi bergantung pada kualitas RNG. Ini fix nomor satu untuk DSA/ECDSA.
- **EdDSA / Ed25519** sebagai alternatif modern: nonce deterministik **by construction**, sehingga kelas serangan nonce hilang.
- **CSPRNG sehat** bila tetap memakai nonce acak: ambil dari `getrandom`/`/dev/urandom`, jangan dari `random` ber-seed, LCG, atau Mersenne Twister.
- **Sisi RSA:** gunakan **RSA-PSS**, bukan tanda tangan mentah atau PKCS#1 v1.5 yang diverifikasi longgar; pakai **`e = 65537`** (bukan `e=3`); dan **verifikasi padding secara ketat** (blok hash wajib rata-kanan, byte sisa diperiksa) → menutup multiplicative & Bleichenbacher forgery.
- **Verifikasi yang benar:** tolak `r=0`/`s=0`, paksa `0 < r,s < n`, dan cek titik publik valid → menutup kelas **CVE-2022-21449**.

**Bridge ke hardening infrastruktur (blue-team — kaitan nyata ke Modul A):**

- **Entropi & RNG hardening pada layanan TLS/SSH/blockchain (Modul A — PKI/Crypto hardening).** Nonce/kunci produksi harus dari RNG yang sehat. War story nyata yang wajib dikenal: **PS3 ECDSA static `k`** (fail0verflow, 27C3 2010) membocorkan master key Sony; **bug Android `SecureRandom` 2013** menyebabkan pencurian Bitcoin lewat nonce ECDSA yang berulang; **Debian OpenSSL CVE-2008-0166** (entropi prediktabel) merusak kunci massal. Pertahanannya: patch RNG + **regenerasi/rotasi kunci**.
- **Audit tanda tangan secara aktif.** Pindai korpus tanda tangan produksi untuk **`r` duplikat** (indikasi nonce reuse) dan kunci buatan RNG cacat; revoke + reissue yang positif.
- **Logging & auditing** (jembatan ke Modul A — Logging/Auditing & Modul C — Log Forensic): catat algoritma, kurva, dan versi library penandatangan; alarmkan penggunaan `e=3`, ECDSA tanpa RFC 6979, atau library yang rentan `(0,0)`. Terapkan **key rotation policy** dan simpan private key di file ber-permission ketat / HSM.

## Mini-Lab

**Prasyarat (sekali saja):** Python 3.8+ dengan virtualenv (pip sistem sering diblokir PEP 668):

```bash
python3 -m venv venv && source venv/bin/activate
pip install pycryptodome ecdsa gmpy2
```

Lalu **satukan fungsi solver** dari **Contoh / Payload** (`recover_key_reused_nonce`, `forge_pkcs1_e3` + konstanta `ASN1_SHA256`, dan baris `import`-nya) ke dalam satu file `dsa_solvers.py`.

**Skenario A (ECDSA nonce reuse):** Diberikan dua tanda tangan `(r, s₁)` dan `(r, s₂)` ber-`r` **sama** pada `secp256k1` beserta `h₁, h₂` → `recover_key_reused_nonce()` memulihkan `d`.
**Skenario B (RSA signature forgery `e=3`):** Diberikan verifier RSA mentah/PKCS#1 longgar dengan `e=3` → `forge_pkcs1_e3()` membangun tanda tangan palsu tanpa private key.

**Setup lab lokal** (di CTF nyata signature/verifier datang dari soal; di sini kita bangun keduanya secara lokal dengan flag tertanam, supaya bisa dijalankan input→flag). Simpan sebagai `lab.py` di folder yang sama dengan `dsa_solvers.py`:

```python
import hashlib
from Crypto.Util.number import bytes_to_long, getPrime, inverse
from ecdsa import SigningKey, SECP256k1
from ecdsa.ecdsa import generator_secp256k1 as g
from dsa_solvers import recover_key_reused_nonce, forge_pkcs1_e3, ASN1_SHA256

# ====== Skenario A: ECDSA nonce reuse ======
curve = SECP256k1; n = curve.order
sk = SigningKey.generate(curve=curve)
d_real = sk.privkey.secret_multiplier
k = 0xC0FFEE1234567890ABCDEF                  # nonce DIPAKAI ULANG (bug penandatangan)
def sign(msg):
    h = bytes_to_long(hashlib.sha256(msg).digest())
    r = (k * g).x() % n
    s = (inverse(k, n) * (h + d_real * r)) % n
    return r, s, h
r1, s1, h1 = sign(b"transfer 10 to alice")
r2, s2, h2 = sign(b"transfer 10 to bob")
assert r1 == r2, "nonce reuse -> r identik"
_, d = recover_key_reused_nonce(r1, s1, s2, h1, h2, n)
print("A:", "LKSN{ecdsa_nonce_reuse}" if d == d_real else "GAGAL")

# ====== Skenario B: Bleichenbacher e=3 (verifier longgar) ======
e = 3; keybits = 3072
while True:
    p, q = getPrime(keybits // 2), getPrime(keybits // 2)
    if (p - 1) % 3 and (q - 1) % 3:           # pastikan e=3 invertible (key valid)
        break
N = p * q
msg = b"admin=true"
s = forge_pkcs1_e3(msg, keybits)              # tanda tangan palsu TANPA private key
def loose_verify(msg, s, N, keybits):         # verifier yang TIDAK memeriksa byte sisa
    em = pow(s, 3, N).to_bytes(keybits // 8, "big")
    target = ASN1_SHA256 + hashlib.sha256(msg).digest()
    idx = em.find(b"\x00", 2)                  # lewati 00 01, cari 00 pemisah lalu baca dari KIRI
    return em[idx + 1: idx + 1 + len(target)] == target
print("B:", "LKSN{bleichenbacher_e3}" if loose_verify(msg, s, N, keybits) else "GAGAL")
```

Jalankan: `python3 lab.py` → keluaran:

```
A: LKSN{ecdsa_nonce_reuse}
B: LKSN{bleichenbacher_e3}
```

→ Skenario A memulihkan private key `d` dari dua tanda tangan ber-`r` sama (cocok dengan key asli); Skenario B menempa tanda tangan `e=3` yang lolos verifier longgar. Di soal nyata, langkah berikutnya: pakai `d` untuk menandatangani `{"user":"admin"}` dengan `python-ecdsa` lalu kirim ke endpoint.

Verifikasi cepat: semua hasil harus lolos rutin `verify` resmi (`ecdsa`/`cryptography`). Bila lolos, jawaban valid.

## Referensi & Latihan

- **Cryptopals Set 6** — challenge **43** (DSA: pulihkan key dari nonce), **44** (DSA: nonce dipakai ulang dari banyak signature), **42** (Bleichenbacher `e=3` RSA forgery): https://cryptopals.com/sets/6
- **CryptoHack — Elliptic Curves / Digital Signatures** (jalur ECDSA nonce reuse, biased nonce, dan DSA): https://cryptohack.org/courses/
- **pwn.college — Cryptography** untuk drilling solver tanda tangan bertahap.
- **root-me — Cryptanalysis** dan **HackTheBox** (kategori Crypto: banyak soal "ECDSA nonce reuse" & "RSA signature forgery").
- **Trail of Bits — "ECDSA: Handle with Care"** (nonce reuse & biased nonce), paper **Minerva** dan **LadderLeak** (lattice/HNP), serta **RFC 6979** (deterministic nonce) untuk sisi pertahanan.
- **CVE-2022-21449 "Psychic Signatures"** (Neil Madden) untuk bug verifikasi ECDSA `(0,0)`.

> **Etika:** Teknik di sini hanya untuk lab pribadi, platform latihan resmi, target CTF, atau sistem dengan izin tertulis eksplisit. Memalsukan tanda tangan atau memulihkan kunci milik orang lain tanpa izin melanggar hukum.
