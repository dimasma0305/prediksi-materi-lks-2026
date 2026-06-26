# Cryptography — Modul B (Offensive / CTF)

> Indeks & **MANIFEST** kategori **Cryptography** pada Modul B (offensive / Capture The Flag). Di lomba, soal crypto jarang menuntut "memecahkan" algoritma dari nol — yang dinilai adalah kemampuan **mengenali skema** (cipher klasik, RSA, AES, ECC, DSA, PRNG, hash), **menemukan kesalahan implementasi** (parameter lemah, nonce dipakai ulang, mode salah, padding bocor), lalu **mengeksploitasinya secara terprogram** untuk memulihkan plaintext, kunci, atau menempa tanda tangan. Tujuan akhirnya selalu sama: **dapatkan flag**.

## Peta ke Kisi-kisi LKSN 2026

Kategori ini adalah bagian dari **Modul B — Offensive / CTF** pada kisi-kisi **LKSN (Lomba Kompetensi Siswa Nasional) bidang Cyber Security 2026**, berdampingan dengan kategori CTF lain di Modul B: **Web Exploitation**, **Binary Exploitation**, dan **Boot2Root**. Fokus kategori **Cryptography**: analisis & serangan terhadap kriptografi yang salah implementasi atau berparameter lemah, dikerjakan dengan tooling (umumnya **Python** + `pycryptodome`/`gmpy2`/`SageMath`) dalam batas **lingkungan lomba / lab berizin**.

---

## Daftar Topik

Tujuh halaman berikut adalah cakupan tetap kategori ini. Kerjakan **berurutan 01 → 07**: cipher klasik membangun intuisi dasar, lalu naik ke kriptografi kunci-publik (RSA, ECC, DSA), kriptografi simetris modern (AES), pembangkit bilangan acak (PRNG), dan ditutup dengan hashing.

| No | Topik | File | Cakupan/Contoh | Status |
|---|---|---|---|---|
| 1 | Classical ciphers | [01-classical-ciphers.md](01-classical-ciphers.md) | Vigenere, Caesar, Atbash, Affine, Substitution, XOR | ✅ selesai |
| 2 | Attack on RSA | [02-attack-on-rsa.md](02-attack-on-rsa.md) | Hastad, common modulus, twin prime, multiprimes | ✅ selesai |
| 3 | Attack on PRNG | [03-attack-on-prng.md](03-attack-on-prng.md) | Mersenne Twister, LCG, LFSR | ✅ selesai |
| 4 | Attack on AES | [04-attack-on-aes.md](04-attack-on-aes.md) | mode ECB, CBC, OFB, CFB, CTR, GCM | ✅ selesai |
| 5 | Attack on ECC | [05-attack-on-ecc.md](05-attack-on-ecc.md) | Smart's attack | ✅ selesai |
| 6 | Attack on DSA | [06-attack-on-dsa.md](06-attack-on-dsa.md) | attack on ECDSA, attack on RSA signature | ✅ selesai |
| 7 | Hashing | [07-hashing.md](07-hashing.md) | length extension attack | ✅ selesai |

---

## Catatan Format

Setiap topik di atas adalah **satu halaman** yang ditulis dengan **template seragam** berikut, agar mudah dipakai sebagai referensi cepat saat lomba:

1. **Konsep** — apa skema/algoritma ini dan kenapa relevan di CTF.
2. **Cara Kerja** — mekanisme matematis/struktural yang diserang (di mana letak kelemahannya).
3. **Langkah** — alur eksploitasi langkah demi langkah, dari mengenali soal sampai memulihkan flag.
4. **Tools** — pustaka & alat yang dipakai (mis. `pycryptodome`, `gmpy2`, `sympy`, `SageMath`, `RsaCtfTool`, `hashpump`).
5. **Contoh/Payload** — skrip solver / contoh nyata yang bisa langsung diadaptasi.
6. **Deteksi & Mitigasi** — bagaimana sisi defender mengenali & menutup celah ini (parameter aman, nonce unik, mode ber-autentikasi).
7. **Mini-Lab** — latihan mandiri untuk menguji pemahaman.
8. **Referensi** — sumber rujukan (paper, writeup, dokumentasi).

> Materi ini **hanya** untuk lab pribadi, lingkungan kompetisi, atau sistem dengan **izin tertulis eksplisit**. Teknik serangan di sini dipakai untuk belajar memecahkan tantangan CTF dan menguji kriptografi sendiri, **bukan** untuk menyerang sistem orang lain.
