# 1. Classical ciphers

> Classical ciphers adalah skema enkripsi pra-komputer yang bekerja dengan **menggeser, membalik, atau memetakan ulang** simbol (huruf atau byte). Di CTF LKSN 2026 ini biasanya soal *warm-up* kategori Cryptography: yang dinilai bukan "memecahkan" matematika berat, melainkan kecepatan **mengenali skema** lalu **memulihkan plaintext** sampai dapat **flag**. Cakupan halaman ini: Caesar, Atbash, Affine, Substitution, Vigenere, dan XOR.

## Konsep

Semua cipher di sini tidak menawarkan kerahasiaan nyata terhadap kriptanalisis modern — ruang kunci kecil atau struktur statistik plaintext bocor ke ciphertext. Kelompokkan menjadi tiga keluarga:

- **Monoalphabetic substitution** — satu huruf plaintext selalu dipetakan ke satu huruf ciphertext yang sama.
  - **Caesar** — geser alfabet sebesar `k` (ROT13 = Caesar `k=13`). Hanya 25 kunci non-trivial.
  - **Atbash** — pembalikan alfabet `A↔Z, B↔Y, …`. Tanpa kunci (tetap), ekuivalen Affine `(a=25, b=25)`.
  - **Affine** — pemetaan linear `E(x) = (a·x + b) mod 26`. Hanya 312 kunci.
  - **Substitution** (umum) — permutasi alfabet sembarang, ruang kunci `26! ≈ 4×10²⁶` (tak bisa brute-force, harus analisis frekuensi).
- **Polyalphabetic substitution** — pemetaan berubah per posisi.
  - **Vigenere** — Caesar dengan kunci berulang: `E(xᵢ) = (xᵢ + k₍ᵢ mod m₎) mod 26`.
- **Byte-level XOR** — operasi `cᵢ = pᵢ ⊕ k₍ᵢ mod n₎` pada byte mentah (bukan hanya A–Z). Single-byte, repeating-key, atau *many-time pad* (kunci dipakai ulang).

## Cara Kerja

Letak kelemahan tiap keluarga:

| Cipher | Rumus enkripsi | Ruang kunci | Titik lemah yang diserang |
|---|---|---|---|
| **Caesar** | `(x + k) mod 26` | 25 | Brute-force total 25 geseran |
| **Atbash** | `25 − x mod 26` | 1 (tetap) | Tidak ada kunci — langsung dekode |
| **Affine** | `(a·x + b) mod 26`, `gcd(a,26)=1` | 312 | Brute-force; dekripsi butuh `a⁻¹ mod 26` |
| **Substitution** | permutasi `σ(x)` | `26!` | Frekuensi huruf/bigram, hill-climbing, kamus |
| **Vigenere** | `(xᵢ + k₍ᵢ mod m₎) mod 26` | `26^m` | Cari panjang kunci `m`, lalu pecah per kolom |
| **XOR** | `pᵢ ⊕ k₍ᵢ mod n₎` | `256^n` | Brute single-byte; cari `n` lalu per kolom |

Detail yang sering diuji:

- **Affine** valid hanya untuk `a ∈ {1,3,5,7,9,11,15,17,19,21,23,25}` (12 nilai, harus coprime dengan 26; `13` **tidak** valid karena `gcd(13,26)=13`). Dekripsi: `D(y) = a⁻¹·(y − b) mod 26`.
- **Vigenere** dipecah dua tahap: (1) tentukan panjang kunci `m` lewat **Kasiski examination** (jarak antar substring berulang) atau **Index of Coincidence (IC)**; (2) tiap kolom ke-`i` kini menjadi Caesar tunggal → selesaikan dengan analisis frekuensi.
- **XOR repeating-key** dipecah sama seperti Vigenere: tebak panjang kunci `n` lewat **normalized Hamming distance** (panjang dengan jarak terkecil ≈ kunci), transpose jadi `n` kolom, lalu tiap kolom = single-byte XOR.

## Indikator / Cara Mengenali

- **Charset.** Hanya `A–Z` (mungkin huruf besar) → cipher alfabet klasik. Hex/Base64 → **dekode dulu**, kemungkinan XOR/byte-level di baliknya. Ingat: encoding (Base64/hex) **bukan** enkripsi.
- **Index of Coincidence.** IC ≈ **0.066** (mendekati Bahasa Inggris) → monoalphabetic (Caesar/Atbash/Affine/Substitution), karena IC invarian terhadap substitusi. IC ≈ **0.038** (datar) → polyalphabetic (Vigenere) atau XOR.
- **Pola Atbash.** Huruf awal alfabet bertukar dengan huruf akhir (`A↔Z`) — coba Atbash lebih dulu jika frekuensi tampak "terbalik".
- **Frekuensi tergeser utuh.** Distribusi huruf identik Bahasa Inggris tapi bergeser seragam → Caesar/ROT.
- **Substring berulang** pada ciphertext panjang → Kasiski → Vigenere, jaraknya kelipatan panjang kunci.
- **Crib.** Format flag diketahui (mis. `LKSN{` atau `flag{`) → pakai sebagai *known plaintext* untuk XOR (`key = cipher ⊕ crib`).

## Langkah Eksploitasi

*Mulai dari: shell biasa dengan Python 3 terpasang dan `solver.py` (blok di **Contoh / Payload**) sudah disiapkan; ciphertext soal sudah disalin ke sebuah variabel/file. Alur ini adalah pohon keputusan — ikuti cabang sesuai hasil tiap langkah, bukan semua langkah berurutan.*

1. **Identifikasi charset & encoding.** Hex/Base64 → dekode ke byte mentah dulu.
2. **Ukur IC** untuk memisahkan monoalphabetic vs polyalphabetic/XOR.
3. **Jika monoalphabetic:** brute Caesar (25 geseran), coba Atbash, brute Affine (312 kunci). Jika masih *gibberish* → perlakukan sebagai Substitution penuh dan serahkan ke **quipqiup** / hill-climbing frekuensi.
4. **Jika polyalphabetic (Vigenere):** estimasi panjang kunci `m` (Kasiski/IC), lalu frekuensi-solve tiap kolom, atau gunakan dCode/CyberChef.
5. **Jika XOR (byte):** coba single-byte brute (256 kunci, skor dengan kemiripan Bahasa Inggris/printable). Gagal → repeating-key XOR (`xortool`/metode Cryptopals). Tetap gagal & kunci dipakai ulang antar pesan → *crib dragging* (many-time pad).
6. **Konfirmasi** dengan format flag, lalu rapikan output.

## Tools

| Tool | Fungsi singkat |
|---|---|
| **CyberChef** | "Magic" detector + operasi `ROT13 Brute Force`, `XOR Brute Force`, `Vigenère Decode`, `Affine Cipher Decode` |
| **dCode (dcode.fr)** | Cipher Identifier + solver per-cipher (Vigenere, Affine, Substitution, dll.) |
| **quipqiup** | Solver otomatis monoalphabetic substitution (cryptogram), efektif walau tanpa batas kata |
| **xortool** (`hellman/xortool`) | Tebak panjang kunci & pulihkan kunci pada multi-byte/repeating XOR |
| **Ciphey / Ares** (`bee-san`) | Dekode/dekripsi otomatis tanpa tahu kunci/cipher (Ares = penerus Rust) |
| **featherduster** | Toolkit kriptanalisis modular (XOR analysis, dsb.) untuk pipeline solver |
| **Python** (`pycipher`, `sympy`/`pow(a,-1,26)`) | Solver kustom; `modinv` untuk Affine, scoring frekuensi untuk XOR |

## Contoh / Payload

```python
# solver.py — toolkit ringkas classical ciphers (Python 3.8+)
from math import gcd
from itertools import product

def caesar(s, k):                                   # Caesar / ROT
    return ''.join(chr((ord(c)-65+k)%26+65) if c.isalpha() else c for c in s.upper())

def atbash(s):                                      # Atbash = reverse alfabet
    return ''.join(chr(65+(25-(ord(c)-65))) if c.isalpha() else c for c in s.upper())

def affine_dec(s, a, b):                            # Affine, butuh a^-1 mod 26
    ai = pow(a, -1, 26)
    return ''.join(chr((ai*((ord(c)-65)-b))%26+65) if c.isalpha() else c for c in s.upper())

def vigenere_dec(s, key):                           # Vigenere = Caesar berulang
    out, ki = [], 0
    for c in s.upper():
        if c.isalpha():
            out.append(chr((ord(c)-65-(ord(key[ki%len(key)].upper())-65))%26+65)); ki += 1
        else:
            out.append(c)
    return ''.join(out)

def score(bs):                                      # skor kasar "ke-Inggris-an"
    return sum(bs.count(c) for c in b"ETAOIN SHRDLUetaoin shrdlu")

def xor_single_brute(ct: bytes):                    # single-byte XOR, 256 kunci
    best = None
    for k in range(256):
        cand = bytes(b ^ k for b in ct)
        if all(32 <= c < 127 for c in cand):
            s = score(cand)
            if best is None or s > best[0]:
                best = (s, k, cand)
    return best                                     # (skor, kunci, plaintext)

# --- contoh nyata (semua nilai sudah diverifikasi) ---
print(caesar("HAAHJR HA KHDU", 19))                 # -> ATTACK AT DAWN  (Caesar k=7, dekode 26-7=19)
print(atbash("SVOOL"))                              # -> HELLO
print(affine_dec("HLIMIHHWVC", 5, 8))               # -> FLAGAFFINE      (a=5, b=8)
print(vigenere_dec("LXFOPVEFRNHR", "LEMON"))        # -> ATTACKATDAWN
print(xor_single_brute(bytes.fromhex(
    "1611091421226a280538282f2e3f053329052e28332c333b3627")))  # key 0x5a -> LKSN{x0r_brute_is_trivial}
```

```python
# === Substitution (monoalphabetic): pecah via analisis frekuensi + crib/quipqiup ===
from collections import Counter
ENG_FREQ = "ETAOINSHRDLCUMWFGYPBVKJXQZ"          # huruf Inggris tersering -> terjarang

def sub_decode(ct, keystr):                       # keystr[i] = plaintext utk ciphertext 'A'+i
    table = {chr(65 + i): keystr[i] for i in range(26)}
    return ''.join(table.get(c, c) for c in ct.upper())

CT = ("ZQ WLEGRJQJXEDZD YLHVCHQWE JQJXEDZD ZD RTH DRCIE AY RTH YLHVCHQWE AY "
      "XHRRHLD ZQ J WZGTHLRHMR ZR ZD CDHI JD JQ JZI RA FLHJNZQO WXJDDZWJX "
      "DCFDRZRCRZAQ WZGTHLD RTH YXJO ZD XNDQYLHVCHQWEUZQD")

# 1) Tebakan AWAL otomatis: samakan urutan frekuensi huruf ciphertext ke ENG_FREQ.
order = [c for c, _ in Counter(c for c in CT if c.isalpha()).most_common()]
guess = ''.join(ENG_FREQ[order.index(chr(65 + i))] if chr(65 + i) in order
                else chr(65 + i) for i in range(26))
print(sub_decode(CT, guess))   # ~30% benar -> pola "THE/FREQUENCY/ANALYSIS" muncul utk dipoles

# 2) Sempurnakan via crib (kata umum / format flag) ATAU serahkan CT ke quipqiup
#    (https://quipqiup.com, hill-climbing otomatis). Peta lengkap hasil refinement:
KEY = "OVUSYBPEDAZRXKGMNTJHWQCLFI"   # ciphertext 'A'..'Z' -> plaintext
print(sub_decode(CT, KEY))     # -> "...THE FLAG IS LKSNFREQUENCYWINS" (flag)
```

```python
# === Repeating-key XOR: pecah ala Cryptopals (Hamming distance + per-kolom) ===
COMMON = b"ETAOINSHRDLU etaoinshrdlu"

def hamming(a, b):                                  # jarak Hamming (jumlah bit beda)
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))

def guess_keysizes(ct, lo=2, hi=16, top=4):
    res = []
    for ks in range(lo, min(hi, len(ct) // 4) + 1):
        blk = [ct[i*ks:(i+1)*ks] for i in range(len(ct) // ks)]
        dist = [hamming(x, y) / ks for x, y in zip(blk, blk[1:])]   # ternormalisasi
        res.append((sum(dist) / len(dist), ks))
    return [ks for _, ks in sorted(res)[:top]]      # jarak terkecil = kandidat panjang kunci

def break_single(block):                            # single-byte XOR untuk satu kolom
    best = (0, -1)
    for k in range(256):
        cand = bytes(b ^ k for b in block)
        if any(c < 9 or (13 < c < 32) or c > 126 for c in cand):
            continue                                # buang kunci yang hasilkan non-printable
        score = sum(c in COMMON for c in cand)      # maksimalkan huruf umum Inggris + spasi
        if score > best[1]:
            best = (k, score)
    return best[0]

def break_repeating_xor(ct, ks):
    cols = [ct[i::ks] for i in range(ks)]           # transpose: kolom ke-i = single-byte XOR
    key = bytes(break_single(col) for col in cols)
    return key, bytes(b ^ key[i % ks] for i, b in enumerate(ct))

def solve_repeating_xor(ct):
    best = None
    for ks in sorted(guess_keysizes(ct)):           # kandidat sering KELIPATAN -> utamakan terkecil
        key, pt = break_repeating_xor(ct, ks)
        if any(c < 9 or (13 < c < 32) or c > 126 for c in pt):
            continue
        score = sum(c in COMMON for c in pt) / len(pt)
        if best is None or score > best[0] + 0.01:  # margin: tie-break ke keysize terkecil
            best = (score, key, pt)
    return best[1], best[2]                          # (key, plaintext)

# --- demo: enkripsi paragraf lalu pulihkan TANPA tahu kunci (butuh ciphertext cukup panjang) ---
PARA = (b"The Magic Words are Squeamish Ossifrage. In cryptography a classical cipher is a "
        b"type of cipher that was used historically but has now mostly fallen out of use. "
        b"Frequency analysis and the index of coincidence guide the attack on a repeating key. "
        b"Most classical ciphers can be broken with enough ciphertext and patient analysis. ")
PT = PARA * 4 + b"The secret flag is LKSN{repeating_key_xor_broken_with_hamming_distance}"
ct = bytes(b ^ b"CRYPTO"[i % 6] for i, b in enumerate(PT))   # ciphertext yang dilihat penyerang
key, pt = solve_repeating_xor(ct)
print(key)                                          # -> b'CRYPTO'
print(b"LKSN" + pt.split(b"LKSN")[1][:40])          # -> LKSN{repeating_key_xor_broken_with_hammin...
```

```bash
# Affine brute-force tanpa tahu (a,b): coba 12 multiplier valid x 26 shift
python3 - <<'PY'
from math import gcd
ct = "HLIMIHHWVC"
for a in [x for x in range(1,26) if gcd(x,26)==1]:
    for b in range(26):
        ai = pow(a,-1,26)
        pt = ''.join(chr((ai*((ord(c)-65)-b))%26+65) for c in ct)
        if "FLAG" in pt: print(a,b,pt)
PY

# repeating-key XOR: tebak panjang kunci & pulihkan kunci dari file mentah
xortool cipher.bin -c 20            # -c = byte plaintext paling sering (mis. 0x20 spasi)
xortool cipher.bin -l 5 -c 00       # paksa panjang kunci 5, char freq 0x00

# CyberChef recipe (chaining): From Hex -> XOR Brute Force, atau ROT13 Brute Force
# dCode: tempel ciphertext ke "Cipher Identifier" lalu ikuti solver yang disarankan
```

> **Jebakan umum.** (1) Affine sering gagal karena `a` tidak coprime 26 — pastikan iterasi hanya 12 multiplier valid. (2) Pada XOR, **Base64/hex harus didekode ke byte dulu**; mengXOR string ASCII hex menghasilkan sampah. (3) Vigenere: salah memperkirakan panjang kunci membuat per-kolom Caesar gagal total — verifikasi `m` dengan IC sebelum lanjut.

## Deteksi & Mitigasi

Karena classical ciphers bukan permukaan serang produksi nyata, nilai pertahanannya justru di **mengenali penyalahgunaannya**:

- **Jangan pernah pakai untuk kerahasiaan.** Caesar/ROT13/Atbash/Affine/XOR sederhana **bukan** enkripsi — jangan dipakai melindungi kredensial, token, atau config. Gunakan kriptografi terautentikasi modern: **AES-GCM** atau **libsodium/`secretbox`**, dengan kunci dari secret manager.
- **Encoding ≠ encryption.** Base64/hex hanya representasi; menyimpan rahasia "ter-encode" sama dengan plaintext. Audit repo & config untuk pola ini.
- **Deteksi obfuscation di malware/artefak (hook blue-team paling nyata).** Banyak malware menyembunyikan string C2/payload dengan **single-byte XOR atau ROT13**. Untuk Modul C — Log/Binary Forensic, gunakan:
  - **FLOSS** (FLARE) — ekstrak *stacked/encoded strings* otomatis dari binary.
  - **capa** — kenali kapabilitas termasuk rutin "encode data using XOR".
  - **YARA** — aturan untuk string yang ter-XOR (modifier `xor` pada string YARA) atau konstanta kunci.
  - **CyberChef / xortool** pada sampel untuk memulihkan string tersembunyi saat triase.
- **Bridge ke hardening Windows (Modul A).** Jangan simpan secret yang sekadar di-obfuscate di registry/file aplikasi; gunakan **DPAPI** (`CryptProtectData`) atau Credential Manager / vault terkelola, dan deteksi indikator obfuscation (entropi byte yang seragam-rendah, blob hex/base64 di log) sebagai sinyal tooling jahat.

## Mini-Lab

**Skenario:** Sebuah file `cipher.txt` berisi satu baris hex:
`1611091421226a280538282f2e3f053329052e28332c333b3627`. Pulihkan flag-nya.

**Prasyarat:** Python 3.8+ (lab ini **tanpa** dependency eksternal). Kerjakan dari shell biasa. "Solver" = blok kode pertama di **Contoh / Payload** (fungsi `caesar`/`atbash`/`affine_dec`/`vigenere_dec`/`xor_single_brute` + baris `print(...)` di bawahnya yang sudah memuat hex soal ini).

1. **Siapkan solver.** Salin blok kode pertama dari **Contoh / Payload** persis apa adanya ke sebuah file `solver.py`. Di bagian bawah blok itu sudah ada `print(xor_single_brute(bytes.fromhex("1611091421226a280538282f2e3f053329052e28332c333b3627")))` — yaitu hex dari `cipher.txt`, jadi tidak perlu mengetik ulang input.
2. **Identifikasi.** Hex (52 karakter) → dekode ke 26 byte mentah; Index of Coincidence datar dan charset bukan `A–Z` → curigai **XOR**, bukan cipher alfabet.
3. **Jalankan solver:**
   ```bash
   python3 solver.py
   ```
4. **Baca hasil.** → baris terakhir output mencetak `(16, 90, b'LKSN{x0r_brute_is_trivial}')`. Artinya skor 16, kunci `90` desimal = `0x5a`, dan plaintext **`LKSN{x0r_brute_is_trivial}`** ← inilah flag.

> Latihan tambahan (juga sudah ada di `solver.py`, lihat output `print` lainnya): `LXFOPVEFRNHR` (Vigenere, kunci `LEMON`) → `ATTACKATDAWN`; serta `HLIMIHHWVC` (Affine `a=5,b=8`) → `FLAGAFFINE`. Untuk substitution penuh & repeating-key XOR, jalankan dua blok kode terakhir di **Contoh / Payload** sebagai file terpisah (`python3 nama.py`): blok substitution mencetak kalimat berakhir `...THE FLAG IS LKSNFREQUENCYWINS`, dan blok repeating-key XOR memulihkan kunci `b'CRYPTO'` lalu mencetak flag `LKSN{repeating_key_xor_broken_with_hammin...` (baris `print` menampilkan 40 karakter pertama; flag utuh `LKSN{repeating_key_xor_broken_with_hamming_distance}` ada di variabel `pt`).

## Referensi & Latihan

- **CryptoHack** — jalur *Introduction to CTF* & *General/`XOR`* (single-byte, repeating-key, many-time pad): https://cryptohack.org/
- **Cryptopals — Set 1** (challenge 3/5/6: single-byte XOR, repeating-key XOR, "Break repeating-key XOR" — kanonik untuk Hamming-distance): https://cryptopals.com/
- **root-me** — kategori *Cryptanalysis* (Vigenere, monoalphabetic substitution, XOR).
- **picoCTF** — soal `substitution`, `Mind your Ps and Qs`, `Vigenere`, `caesar` (latihan bertingkat, target legal).
- **pwn.college** — modul *Cryptography* intro untuk fundamen XOR & substitusi.
- **HackTheBox** — *Challenges → Crypto* untuk variasi cipher klasik bercampur encoding.
- **dCode** (referensi rumus & solver) + **CyberChef** (recipe `Magic`) sebagai pisau-Swiss saat lomba.

> **Etika:** Teknik di sini hanya untuk lab pribadi, platform latihan resmi, target CTF, atau sistem dengan izin tertulis. Membongkar atau menyerang data terenkripsi milik pihak lain tanpa izin melanggar hukum.
