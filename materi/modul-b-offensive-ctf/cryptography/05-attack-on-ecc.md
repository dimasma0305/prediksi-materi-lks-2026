# 5. Attack on ECC

> Elliptic Curve Cryptography (ECC) aman selama **kurva dan titiknya dipilih benar**. Sama seperti RSA, soal ECC di CTF hampir tidak pernah meminta memecahkan ECDLP pada kurva standar (`secp256k1`, `P-256`, `Curve25519`) secara brute force — yang diuji adalah kemampuan mengenali **kurva atau parameter lemah** (kurva anomalous, supersingular, order yang smooth, kurva singular) lalu menyelesaikan ECDLP secara terprogram untuk memulihkan **private key** `d`. Di LKSN 2026 bintang utamanya adalah **Smart's attack** pada *anomalous curve*, berdampingan dengan **MOV/pairing attack**, **Pohlig–Hellman**, dan **singular curve attack**.

## Konsep

Sebuah elliptic curve atas prime field `F_p` adalah himpunan titik `(x, y)` yang memenuhi `y² = x³ + ax + b (mod p)` ditambah titik tak-hingga `O`. Titik-titik ini membentuk grup abelian dengan operasi **point addition**; perkalian skalar `Q = d·P` (jumlahkan `P` sebanyak `d` kali) adalah operasi inti. Keamanan ECC bersandar pada **ECDLP**: diberi `P` dan `Q = d·P`, sulit memulihkan `d`. Pada kurva sehat, serangan terbaik bersifat generik — **Pollard's rho** / **BSGS** dengan biaya `O(√n)` terhadap order titik `n` — sehingga 256-bit aman.

Soal CTF sengaja memilih kurva yang **memecah** asumsi itu. Empat kelas yang menjadi fokus halaman ini:

- **Smart's attack (anomalous curve)** — jumlah titik kurva tepat sama dengan karakteristik field, `#E(F_p) = p` (ekuivalen *trace of Frobenius* `t = 1`). ECDLP runtuh ke **waktu linear** lewat *p-adic lift*.
- **MOV / pairing attack** — *embedding degree* `k` kecil (khas **supersingular curve**). Weil/Tate pairing memetakan ECDLP ke **DLP biasa** di `F_{p^k}*`, yang bisa diserang dengan index calculus.
- **Pohlig–Hellman** — order grup `n` bersifat **smooth** (terfaktor jadi prima-prima kecil). ECDLP dipecah per subgrup kecil lalu disatukan dengan CRT.
- **Singular curve** — diskriminan nol (`4a³ + 27b² ≡ 0`). Grup "kurva" sebenarnya isomorfik ke grup aditif atau multiplikatif `F_p`, sehingga ECDLP menjadi DLP/pembagian mudah.

## Cara Kerja

Letak kelemahan tiap kelas:

- **Smart's attack.** `#E = p` membuat ada homomorfisme dari grup titik ke grup aditif `(F_p, +)`. Titik `P, Q` di-*lift* ke kurva atas **p-adic numbers** `Q_p` (Hensel lifting), lalu dikalikan `p` agar jatuh ke *kernel of reduction* (formal group). Di sana **p-adic elliptic logarithm** `φ(R) = −x(R)/y(R)` adalah homomorfisme grup, sehingga `d = φ(Q)/φ(P) (mod p)` — cukup **satu pembagian**, tanpa akar kuadrat. (Caveat: lift harus diacak; bila kurva hasil lift kebetulan isomorfik ke `E` atas `F_p`, serangan gagal — karena itu koefisien dirandom dengan `+ randint·p`.)
- **MOV.** Untuk titik order `n`, **embedding degree** `k` = bilangan terkecil dengan `n | p^k − 1`. Weil pairing `e(·,·)` memetakan `P, Q` ke `F_{p^k}*` sehingga `e(Q, T) = e(P, T)^d`. ECDLP berubah menjadi **DLP di finite field** yang bisa diserang **index calculus** (sub-eksponensial). Pada **supersingular curve** `k ≤ 6`, jadi `p^k` tetap kecil dan praktis.
- **Pohlig–Hellman.** Bila `n = ∏ pᵢ^eᵢ`, ECDLP diselesaikan **modulo tiap** `pᵢ^eᵢ` (di subgrup kecil, biaya `≈ √pᵢ`) lalu digabung dengan **CRT**. Total biaya didominasi `√(faktor prima terbesar)` — murah saat order smooth atau cofactor besar.
- **Singular curve.** `4a³ + 27b² ≡ 0 (mod p)` berarti kurva punya titik singular (node/cusp). Lewat substitusi, grup non-singular dipetakan ke `(F_p, +)` (cusp) atau ke `F_p*` / `F_{p²}*` (node, tergantung apakah `x³+ax+b` punya akar di `F_p`). ECDLP lalu jadi pembagian atau DLP biasa.

## Indikator / Cara Mengenali

Baca file soal (`chall.py`, `output.txt`) dan periksa parameter `p, a, b, G, P/Q`. Sinyal kurva lemah:

- **Kurva custom**, bukan named curve. Jika soal menuliskan `p, a, b` sendiri (alih-alih `secp256k1`/`P-256`), curigai ada *backdoor* parameter.
- `#E(F_p) == p` (hitung `E.order()`) → **anomalous → Smart's attack**.
- `E.order()` **terfaktor jadi prima-prima kecil** (smooth) atau **cofactor besar** → **Pohlig–Hellman**.
- `E.is_supersingular() == True`, atau embedding degree `k` kecil (`n | p^k − 1` untuk `k` mungil) → **MOV**.
- **Diskriminan nol** / `4a³ + 27b² ≡ 0 (mod p)` → **singular curve**.
- Order titik basis **bukan prima besar**, `p` berukuran ganjil/mencurigakan, atau soal tak pernah memvalidasi titik di-kurva (**invalid-curve / small-subgroup** saat ECDH).

## Langkah Eksploitasi

1. **Parse parameter.** Ambil `p, a, b`, generator `G`, dan titik publik `Q` (atau pasangan `P, Q`). Bangun `E = EllipticCurve(GF(p), [a, b])` di SageMath.
2. **Hitung order & faktor.** `N = E.order()`; `factor(N)`. Catat order titik `n = P.order()`.
3. **Triage berdasarkan indikator:**
   - `N == p` → **Smart's attack**.
   - `N`/`n` smooth → **Pohlig–Hellman** (`P.discrete_log(Q)` sudah otomatis memakainya).
   - supersingular / embedding degree kecil → **MOV**.
   - diskriminan nol → **singular curve mapping**.
4. **Jalankan serangan** terpilih untuk memulihkan `d` (skalar dengan `Q = d·P`).
5. **Pakai `d`** sesuai skema soal: turunkan **ECDH shared secret** `d·(titik lawan)`, derive kunci AES, lalu dekripsi → **flag**. Jika ECDSA, lihat halaman *06 — Attack on DSA*.

## Tools

| Tool | Fungsi singkat |
|---|---|
| **SageMath** | Inti solver ECC: `EllipticCurve`, `.order()`, `.discrete_log()` (auto Pohlig–Hellman+BSGS), `weil_pairing`/`tate_pairing` (MOV), `Qp`/`lift_x` (Smart) |
| **jvdsn/crypto-attacks** | Koleksi siap-pakai serangan ECC (`smart_attack`, `mov_attack`, `frey_ruck_attack`, `singular_curve`) dalam Python/Sage. Pohlig–Hellman tak punya modul khusus — pakai `discrete_log` Sage langsung |
| **pycryptodome** (`Crypto.Util.number`) | `long_to_bytes`, `inverse` — decode `m` & aritmetika modular pada tahap pemulihan flag |
| **tinyec / fastecdsa / ecpy** | Memodelkan kurva & titik di Python murni saat Sage tak tersedia |
| **factordb** (`factordb-pycli`) / **sympy** `factorint` | Faktor `E.order()` untuk cek smoothness (Pohlig–Hellman) |
| **gmpy2** | Aritmetika presisi besar cepat (`iroot`, `isqrt`) untuk solver pendukung |

## Contoh / Payload

```python
# ── Triage: tentukan kelas kelemahan kurva sebelum memilih serangan ──
from sage.all import EllipticCurve, GF, factor, gcd

E = EllipticCurve(GF(p), [a, b])
N = E.order()
n = P.order()                                   # order titik basis
print("N == p ?      ", N == p)                 # True -> anomalous -> Smart
print("faktor N:     ", factor(N))              # smooth? -> Pohlig-Hellman
print("supersingular?", E.is_supersingular())   # True -> MOV
print("singular?     ", (4*a**3 + 27*b**2) % p == 0)
k = 1                                            # embedding degree utk MOV
while (p**k - 1) % n != 0:
    k += 1
print("embedding degree k =", k)                # kecil (<= 6) -> MOV layak
```

```python
# ── Smart's attack: hanya jika #E(F_p) == p (anomalous, trace 1) ──
# d dipulihkan dalam waktu linear lewat p-adic elliptic logarithm.
def smart_attack(P, Q, p):
    E = P.curve()
    # lift kurva ke Q_p; koefisien dirandom (+ randint*p) agar lift TIDAK
    # isomorfik ke E atas F_p (kalau isomorfik, serangan gagal).
    Eqp = EllipticCurve(Qp(p, 2), [ZZ(t) + randint(0, p) * p for t in E.a_invariants()])

    P_lift = next(Pp for Pp in Eqp.lift_x(ZZ(P.xy()[0]), all=True)
                  if GF(p)(Pp.xy()[1]) == P.xy()[1])
    Q_lift = next(Qp_ for Qp_ in Eqp.lift_x(ZZ(Q.xy()[0]), all=True)
                  if GF(p)(Qp_.xy()[1]) == Q.xy()[1])

    pP, pQ = p * P_lift, p * Q_lift              # masuk kernel of reduction
    xP, yP = pP.xy()
    xQ, yQ = pQ.xy()
    phi_P = -(xP / yP)                           # p-adic elliptic logarithm
    phi_Q = -(xQ / yQ)
    return ZZ(phi_Q / phi_P) % p                 # d = phi_Q / phi_P (mod p)

# assert #E == p sebelum memakai; verifikasi: d*P == Q
```

```python
# ── Pohlig-Hellman: order smooth. discrete_log Sage sudah memakainya. ──
d = P.discrete_log(Q)                            # Q = d*P ; otomatis PH + BSGS
assert d * P == Q
# Versi eksplisit bila perlu kontrol order:
# from sage.all import discrete_log
# d = discrete_log(Q, P, P.order(), operation='+')
```

```python
# ── MOV (kerangka): reduksi ECDLP -> DLP di F_{p^k}* via Weil pairing ──
def mov_attack(E, P, Q, n):
    p = E.base_field().order()
    k = 1
    while (p**k - 1) % n != 0:                    # embedding degree
        k += 1
    Ek = E.change_ring(GF(p**k))
    Pk, Qk = Ek(P), Ek(Q)
    while True:                                   # cari T agar pairing non-degenerate
        T = Ek.random_point()
        T = (T.order() // gcd(T.order(), n)) * T  # paksa order T | n
        alpha = Pk.weil_pairing(T, n)
        if alpha.multiplicative_order() == n:
            break
    beta = Qk.weil_pairing(T, n)
    return beta.log(alpha)                        # DLP di finite field (index calculus)
```

```python
# ── Singular curve: 4a^3 + 27b^2 ≡ 0 (mod p). Map titik -> F_p* (node split) ──
# ECDLP runtuh ke DLP biasa di F_p*: instan bila p-1 smooth.
from sympy import sqrt_mod
from sympy.ntheory.residue_ntheory import discrete_log

def singular_curve_node(p, a, b, P, Q):
    # akar ganda alpha (node): alpha = -3b / (2a) mod p ; akar tunggal beta = -2*alpha
    alpha = (-3 * b * pow(2 * a, -1, p)) % p
    t = sqrt_mod((3 * alpha) % p, p)             # t^2 = alpha - beta = 3*alpha (slope tangen node)
    assert t is not None, "node non-split -> kerjakan di F_{p^2}*"
    def to_mult(R):                              # (x,y) -> (y + t(x-alpha)) / (y - t(x-alpha))
        x, y = R
        num = (y + t * (x - alpha)) % p
        den = (y - t * (x - alpha)) % p
        return num * pow(den, -1, p) % p
    u, v = to_mult(P), to_mult(Q)                # v = u^d di F_p*
    return discrete_log(p, v, u)                 # d = log_u(v) (Pohlig-Hellman jika p-1 smooth)

# P, Q = (x, y) titik di kurva singular; hasil d memenuhi Q = d*P. Untuk CUSP (akar tripel)
# pemetaan ke grup aditif (F_p, +): phi(x,y) = (x - x0) / (y), lalu d = phi(Q) / phi(P) mod p.
```

```python
# ── Dari d ke flag: contoh skema ECDH + AES yang lazim di soal ──
from Crypto.Cipher import AES
from hashlib import sha256
S = d * Q_peer                                   # shared secret = titik
key = sha256(str(S.xy()[0]).encode()).digest()   # KDF sederhana (sesuaikan ke soal)
flag = AES.new(key, AES.MODE_ECB).decrypt(ct)
print(flag)
```

## Deteksi & Mitigasi

**Perbaikan inti (sisi pemilih kurva) — ini fix yang sebenarnya:**

- **Gunakan named curve standar & teruji.** `X25519`/`Ed25519` (Curve25519), `P-256`/`secp256r1`, atau `secp256k1`. Jangan menggulung parameter kurva sendiri — semua serangan di atas berakar pada parameter custom yang lemah.
- **Penuhi kriteria kurva aman** (rujuk **SafeCurves**, Bernstein–Lange): order titik **prima besar** (cofactor kecil) → mematikan **Pohlig–Hellman**; `#E ≠ p` → mematikan **Smart's attack**; **embedding degree besar** (bukan supersingular) → mematikan **MOV**; diskriminan `≠ 0` → bukan **singular curve**; plus *twist security* dan *rigidity*.
- **Validasi titik masuk.** Selalu cek titik benar-benar **berada di kurva** dan **bukan order kecil** sebelum dipakai di ECDH → menutup **invalid-curve / small-subgroup attack** yang membocorkan `d` bertahap.

**Bridge ke hardening infrastruktur (blue-team — kaitan nyata ke Modul A):**

- **TLS/SSH curve hardening (PKI/crypto config, Modul A).** Nonaktifkan kurva legacy/lemah pada konfigurasi cipher (mis. di OpenSSL/`sshd_config`), paksa hanya `X25519`/`secp256r1`. Pastikan library yang dipakai melakukan **on-curve & subgroup validation** secara default.
- **Inventory & rotasi kunci** (jembatan ke Modul A — Logging/Auditing & Modul C — Log Forensic): catat algoritma & kurva tiap key; alarmkan key yang memakai kurva non-standar atau parameter mencurigakan, dan terapkan **key rotation policy**.
- **Deteksi pasif:** audit handshake/log untuk negosiasi kurva tak-standar atau lonjakan titik yang **ditolak validasi** — pola khas percobaan invalid-curve attack.

## Mini-Lab

**Skenario A (Smart's attack):** Diberikan `chall.py` berisi `p, a, b`, generator `G`, dan `P = d·G`. Bangun `E` di Sage, buktikan `E.order() == p` (anomalous), jalankan `smart_attack(G, P, p)` untuk memulihkan `d`. Verifikasi `d·G == P`, lalu derive shared secret dan dekripsi ciphertext → **flag**.

**Skenario B (Pohlig–Hellman):** Diberikan kurva dengan `E.order()` yang **smooth** (cek `factor(E.order())` → semua faktor kecil) serta pasangan `P, Q = d·P`. Jalankan `d = P.discrete_log(Q)`; ECDLP selesai dalam detik karena order smooth → susun `d` jadi **flag**.

Verifikasi cepat: kedua skenario juga harus selesai dengan modul terkait di **jvdsn/crypto-attacks** (`ecc/smart_attack`, `ecc/singular_curve`, dll). Bila solver manual cocok dengan hasilnya, jawaban valid.

## Referensi & Latihan

- **CryptoHack — Elliptic Curves** (jalur lengkap: aritmetika kurva, ECDH, **Smart's attack**, MOV, singular curve): https://cryptohack.org/courses/
- **jvdsn/crypto-attacks** (implementasi siap pakai Smart, MOV, Frey–Ruck, singular curve — modul di `attacks/ecc/`): https://github.com/jvdsn/crypto-attacks
- **SafeCurves — choosing safe curves for ECC** (Bernstein & Lange; kriteria anti-anomalous/MOV/twist): https://safecurves.cr.yp.to/
- **N. Smart, "The Discrete Logarithm Problem on Elliptic Curves of Trace One"** (J. Cryptology, 1999) — paper asli anomalous attack; **Menezes–Okamoto–Vanstone (1993)** untuk MOV.
- **CTF Wiki — ECC** dan **PayloadsAllTheThings / HackTricks** (payload & checklist per-kelas serangan kurva).
- **Platform latihan:** pwn.college (Cryptography), root-me (Cryptanalysis/ECC), HackTheBox & picoCTF (kategori Crypto: "weak curve" klasik).

> **Etika:** Teknik di sini hanya untuk lab pribadi, platform latihan resmi, target CTF, atau sistem dengan izin tertulis eksplisit. Memulihkan private key atau mendekripsi data milik orang lain tanpa izin melanggar hukum.
