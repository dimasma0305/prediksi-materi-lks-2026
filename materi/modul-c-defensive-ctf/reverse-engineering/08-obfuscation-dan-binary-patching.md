# 8. Obfuscation & Binary Patching

> Obfuscation adalah transformasi yang sengaja dipasang agar logika program **tersembunyi** — di-pack, di-enkripsi, atau dikaburkan alur kontrolnya — sehingga analis tak bisa langsung membaca semantiknya. **Binary patching** adalah lawannya dari sisi tindakan: mengubah byte program untuk **menetralkan** proteksi atau memaksa jalur eksekusi yang diinginkan. Di CTF LKSN 2026 (Modul C — Reverse Engineering), soal kategori ini biasanya berupa biner ter-pack atau crackme yang memvalidasi flag lewat rutin **enkripsi**, dan peserta harus mengenali transformasinya lalu **membaliknya** atau **mem-patch**-nya untuk memperoleh flag. Spine yang menyatukan halaman ini: *transformasi menyembunyikan logika → kenali transformasinya → balikkan atau netralkan*. Pusat dari semuanya adalah cakupan wajib kisi-kisi: **Known/Custom Encryption** — membedakan kripto baku yang bisa dikenali dari signature versus kripto buatan sendiri yang harus dibaca dan di-reimplement.

Halaman [04-anti-re.md](04-anti-re.md) sudah membahas dasar patching (NOP-kan cek, balik cabang, `r2 wa/wx`). Di sini fokusnya berbeda: **memulihkan transformasi** (unpack, deobfuscate, dekripsi) dan **mempersistenkan** patch ke file, bukan mengulang trik anti-debug.

## Konsep

Tiga keluarga transformasi yang menyembunyikan logika, masing-masing dengan cara pemulihan berbeda:

- **Obfuscation struktural** — *packing* (kode asli dikompresi/enkripsi, hanya stub yang terlihat), *string encryption* (string baru ada saat runtime), dan *control-flow obfuscation* (control-flow flattening, opaque predicate, instruction substitution/MBA ala **OLLVM**). Tujuannya membuat statis tampak kacau.
- **Encryption (cakupan wajib)** — flag/data divalidasi lewat rutin kripto. Inilah hinge halaman ini, dengan dua cabang:
  - **Known encryption** — algoritma baku (AES, DES, RC4, TEA/XTEA, ChaCha, base64, CRC). Dikenali dari **konstanta/signature** dan langsung bisa didekripsi dengan library standar.
  - **Custom encryption** — kripto buatan sendiri (rangkaian XOR/rotate/add/sub homebrew, ARX). **Tak punya signature**, jadi dikenali dari **struktur** lalu di-**reimplement & dibalik** secara manual.
- **Binary patching** — bukan transformasi, melainkan *alat pemulihan*: mengubah byte untuk membuka gerbang (gate). Keterampilan khasnya bukan sekadar mengubah byte di memori, tapi **mempersistenkannya ke file** dan **memvalidasi** bahwa logika asli tetap utuh.

Keputusan inti yang membedakan analis matang: **patch vs solve**. Patch dipakai untuk melewati gerbang (mis. cek lisensi). Tapi bila **flag justru diturunkan dari** input yang benar (flag = hasil dekripsi input), mem-patch cek hanya menghasilkan `Correct!` tanpa flag — di situ wajib **solve/keygen**, bukan patch.

## Cara Kerja

**Packing.** Packer (UPX, ASPack, MPRESS, dan protektor kelas berat Themida/VMProtect) membungkus seksi kode asli menjadi blob terkompresi/terenkripsi plus *stub* kecil. Saat dijalankan, stub men-decompress payload ke memori, merekonstruksi **IAT** (Import Address Table), lalu melompat ke **OEP** (Original Entry Point) — alamat `main` asli. Sebelum OEP, disassembly hanya memperlihatkan stub; logika sebenarnya belum ada di disk.

**String & code obfuscation.** String disimpan terenkripsi (XOR/RC4) dan didekripsi runtime, atau dibangun byte demi byte di stack (*stack strings*) sehingga `strings` polos buta. **OLLVM** menyumbang tiga teknik: *control-flow flattening* (semua basic block diratakan ke satu `while(1){ switch(state) }` dengan **state variable** sebagai dispatcher), *bogus control flow* (opaque predicate yang selalu bernilai sama menambah cabang palsu), dan *instruction substitution* yang mengubah aritmetika sederhana menjadi **MBA** (Mixed Boolean-Arithmetic) yang setara tapi tak terbaca.

**Known vs custom encryption.** Kripto baku menanam **konstanta khas** di biner: S-box AES, delta TEA, initial value SHA/MD5, alfabet base64. Konstanta inilah yang dideteksi FindCrypt/signsrch/capa. Kripto custom tak punya konstanta yang dikenal — ia dikenali dari **pola operasi**: loop permutasi 256-byte (mirip RC4), atau rangkaian `xor`+`rol/ror`+`add`+`sub` per byte/word (ARX homebrew). Karena tak ada library yang cocok, satu-satunya jalan adalah **menyalin algoritmanya ke Python dan membalik tiap langkah**.

## Indikator / Cara Mengenali

- **Ter-pack**: entropi seksi tinggi (~7.9/8), impor sangat sedikit (hanya `LoadLibrary`/`GetProcAddress`), nama seksi `UPX0`/`UPX1`/`.aspack`/`.vmp`, dan `Detect It Easy (DIE)`/`PEiD` menandai packer.
- **String encryption**: nyaris tak ada string bermakna di `strings`, tapi ada loop dekripsi kecil sebelum string dipakai → jalankan **FLOSS**.
- **Control-flow flattening**: satu fungsi dengan dispatcher `while(true){ switch(state_var) }` raksasa, CFG berbentuk "kipas" datar, banyak blok mendaftar ke satu state.
- **MBA**: decompiler memuntahkan aritmetika absurd seperti `(x ^ y) + 2*(x & y)` (itu sebenarnya `x + y`) → kandidat **gooMBA**/**D-810**.
- **Enkripsi baku**: konstanta magic terbaca di data. Hafalkan yang paling sering muncul di CTF:

| Algoritma | Tanda pengenal | Catatan |
|---|---|---|
| AES | S-box `63 7c 77 7b f2 6b 6f c5 …`, Rcon, T-table | 256-byte S-box paling khas |
| TEA / XTEA | delta `0x9E3779B9`; sum `0xC6EF3720` setelah 32 round | delta = golden ratio 32-bit — **petunjuk**, bukan bukti |
| SHA-256 | IV `0x6a09e667 0xbb67ae85 …` + 64 round constant | — |
| MD5 | IV `0x67452301 0xefcdab89 …` | — |
| RC4 | tak ada konstanta; KSA isi `S[256]=0..255` lalu swap | dikenali dari **struktur** 256-byte |
| base64 | alfabet `ABC…XYZabc…xyz0123456789+/` | sering varian custom (alfabet diacak) |
| ChaCha/Salsa | `"expand 32-byte k"` → `0x61707865 0x3320646e 0x79622d32 0x6b206574` (little-endian) | `32-byte` = key 256-bit; `16-byte` = 128-bit |
| CRC32 | polinomial `0xEDB88320` (reversed) | tabel 256 entri |

- **Enkripsi custom**: tak ada satupun konstanta di atas, tapi ada loop ketat berisi `xor`/`rol`/`ror`/`add`/`sub` per byte yang membandingkan hasil dengan blob ciphertext tertanam.

## Langkah Analisis/Investigasi

1. **Triage & deteksi** — `file`, `diec`/`DIE`, ukur entropi (`ent`/`binwalk -E`), jalankan `capa` dan FindCrypt untuk memetakan packer & kapabilitas kripto sebelum menjalankan apa pun.
2. **Unpack bila ter-pack** — coba `upx -d` dulu. Bila packer custom: jalankan di debugger sampai **OEP** (set breakpoint pada lompatan besar dari stub / `tail jump`), **dump** image, lalu **rebuild IAT** dengan **Scylla** (atau plugin Scylla di x64dbg).
3. **Pulihkan string** — `FLOSS` untuk mengekstrak string terenkripsi & stack string yang `strings` lewatkan.
4. **Deobfuscate decompiler** — untuk OLLVM/MBA pakai **gooMBA** atau **D-810** (menyederhanakan microcode Hex-Rays); untuk control-flow flattening yang membandel pakai symbolic/emulation (**angr**, **miasm**, **Triton**).
5. **Identifikasi kripto** — known (FindCrypt/signsrch menandai konstanta) vs custom (baca rutinnya langsung di Ghidra/IDA).
6. **Pulihkan plaintext/flag** — *known*: dekripsi dengan library standar (`pycryptodome`). *custom*: **reimplement & balik** di Python; bila tak invertibel bersih pakai `z3`; bila keyspace kecil **brute-force**; bila rutin rumit jalankan terisolasi dengan **Unicorn**.
7. **Putuskan patch vs solve** — patch hanya untuk melewati gerbang; bila flag diturunkan dari input, **solve/keygen**.
8. **Persist & validasi** — terapkan patch ke file (bukan hanya memori), verifikasi panjang instruksi, jalankan ulang, lalu dokumentasikan indikator → pemulihan → flag sebagai POC.

## Tools

| Tool / Plugin | Fungsi singkat |
|---|---|
| `Detect It Easy (DIE)` / `PEiD` | Deteksi packer, compiler, entropi seksi |
| `upx -d` | Unpack otomatis biner UPX |
| `x64dbg` + **Scylla** | Cari OEP, dump proses, rebuild IAT untuk packer manual |
| `capa` (Mandiant FLARE) | Identifikasi kapabilitas termasuk rutin kripto |
| `FindCrypt` (Ghidra/IDA) / `signsrch` | Cari konstanta kripto baku (AES, TEA, dll.) |
| `FLOSS` (Mandiant FLARE) | Ekstrak string ter-obfuscate / stack string |
| `gooMBA` (Hex-Rays) | Sederhanakan ekspresi MBA di decompiler (SMT-backed) |
| `D-810` (IDA) | Deobfuscate OLLVM via microcode (CFF, instruction substitution) |
| `angr` / `miasm` / `Triton` | Symbolic/concolic execution untuk membongkar flattening |
| `Unicorn` engine | Emulasi rutin kripto custom terisolasi tanpa run penuh |
| `keystone` / `Keypatch` (IDA) | Assemble instruksi pengganti saat patching |
| `radare2`/`rizin`, `IDA`, `Ghidra` | Patch & persist ke file (lihat Contoh) |
| `z3` / `pycryptodome` | Solver constraint & library dekripsi baku |

## Contoh / Payload

**Triage, deteksi packer & kripto, unpack.**

```bash
diec ./chal              # diec = DIE versi konsol (CLI); GUI: die / detect-it-easy; PEiD di Windows
binwalk -E ./chal        # grafik entropi: dataran ~8.0 = ter-pack/enkripsi
upx -d ./chal -o chal.unpacked      # coba unpack UPX otomatis
capa -v ./chal           # "encrypt data using RC4 / AES" dst.
# FindCrypt (Ghidra): Analysis > FindCrypt ; signsrch:
signsrch ./chal | grep -iE 'AES|TEA|RC4|base64|CRC'
```

**Pulihkan string yang di-obfuscate.**

```bash
floss ./chal             # decoded + stack strings yang dilewatkan `strings`
floss --only stack -- ./chal | grep -iE 'flag|LKSN|key'   # nilai stackstrings = "stack"; "--" wajib karena --only nargs='+'
```

**Custom encryption — kenali rutin, reimplement, lalu balik.** Misal Ghidra menampilkan loop per byte: `x = (in[i] + 0x37) & 0xff; x = rol8(x,3); out[i] = x ^ key[i%4]`, dibandingkan dengan ciphertext tertanam. Karena tak ada signature (custom), balik tiap langkah dalam urutan terbalik:

```python
# enc : p -> +0x37 -> ROL3 -> XOR key   (dibaca dari disassembly)
# dec : c -> XOR key -> ROR3 -> -0x37
def ror8(v, n): return ((v >> n) | (v << (8 - n))) & 0xff

ct  = bytes.fromhex("c3 5a 9e 7f 22 b1 ...".replace(" ", ""))
key = bytes([0x12, 0x34, 0x56, 0x78])           # konstanta key dari biner

flag = bytes(((ror8(c ^ key[i % 4], 3) - 0x37) & 0xff)
             for i, c in enumerate(ct))
print(flag)            # b'LKSN{cu5t0m_4rx_r3v3rs3d}'
```

Bila rutin terlalu berbelit untuk dibalik tangan, jalankan rutin aslinya terisolasi (**Unicorn**) atau modelkan dengan **z3** dan biarkan solver mencari input yang menghasilkan ciphertext target.

**Persist patch ke file (lanjutan dari 04 yang hanya mem-patch di memori).**

```text
# IDA      : Edit > Patch Program > Apply patches to input file
# x64dbg   : (assemble di disasm) -> Patches (Ctrl+P) > Patch File
# Ghidra   : ubah byte (Patch Instruction) -> File > Export Program (format Binary
#            / gunakan skrip savepatch) ; export bukan otomatis seperti IDA
# radare2  : r2 -w ./chal ; s <addr> ; wa "jmp 0x401234" ; wx 90 ; q
```

## Anti-Forensik & Pitfall

**Teknik evasion penyerang (mempersulit analis):**

- **Pack berlapis & protektor VM** — Themida/VMProtect mem-*virtualize* kode ke bytecode custom; devirtualisasi penuh **mahal dan sering di luar lingkup CTF**. Akui jujur: targetkan OEP/dump dan data hasil, bukan men-devirt seluruhnya.
- **Anti-dump** — stub merusak PE header / menghapus IAT setelah unpack agar dump mentah tak bisa dijalankan; perlu rebuild IAT (Scylla) dan perbaikan header.
- **Kripto baku yang "ditweak"** — S-box AES atau delta TEA **sengaja diubah satu byte** agar FindCrypt/signsrch gagal mencocokkan; tampak custom padahal turunan baku. Curigai struktur yang mirip tapi konstanta meleset.
- **String + control-flow obfuscation gabungan** — string terenkripsi *plus* control-flow flattening *plus* MBA agar decompiler tak berguna tanpa deobfuscator.
- **Tamper/checksum self-check** — biner menghitung hash dirinya sendiri; patch byte memicu deteksi yang **mengubah kunci dekripsi** sehingga keluar **flag palsu** alih-alih error.

**Pitfall analis (kesalahan yang membuat flag terlewat):**

- **Patch padahal flag diturunkan dari cek.** Mem-NOP perbandingan menghasilkan `Correct!` tanpa flag karena flag = hasil dekripsi input yang benar. Saat flag *adalah* input → **solve/keygen**, jangan patch.
- **Percaya buta FindCrypt.** Konstanta yang ditweak lolos deteksi; bila "AES" tapi hasil tak cocok, periksa S-box/round-constant byte demi byte — mungkin sudah dimodifikasi.
- **Lupa rebuild IAT setelah dump.** Image OEP yang di-dump tanpa IAT yang benar akan crash; selalu rekonstruksi impor.
- **Patch di memori, lupa persist.** Mengubah byte di debugger tak menulis ke file; gunakan *Apply patches*/*Patch File*/`r2 -w`.
- **Salah endianness / ukuran word saat reimplement.** TEA/XTEA beroperasi pada **word 32-bit big/little-endian**; salah baca byte order membuat hasil dekripsi sampah meski algoritma benar.
- **Menebak "ini AES standar".** Banyak soal memakai mode/IV/urutan operasi non-standar; verifikasi dari disassembly, jangan asumsikan.

## Mini-Lab

**Skenario:** Diberikan `chal` (Linux x86_64) ter-pack UPX. Setelah unpack, `main` membaca input, melewatkannya ke rutin enkripsi custom (XOR + rotate + add per byte), lalu membandingkannya dengan blob ciphertext tertanam. Bila cocok dicetak `Correct!`; flag adalah input yang benar (bukan string literal).

1. **Lakukan:** `die ./chal` lalu `upx -d ./chal -o chal.u` → **Dapatkan:** biner unpacked dengan `main` & rutin enkripsi yang terbaca.
2. **Lakukan:** impor `chal.u` ke Ghidra (auto-analyze), lalu jalankan FindCrypt dari menu *Analysis > FindCrypt* (atau *Window > Script Manager* → cari `FindCrypt`) → **Dapatkan:** konfirmasi **tak ada** kripto baku (ini custom), lalu baca rutin per byte dan blob ciphertext.
3. **Lakukan:** salin urutan operasi ke Python dan **balik** tiap langkah (rotate balik arah, add → sub), atau modelkan dengan `z3` bila tak invertibel bersih.
4. **Dapatkan:** jalankan inverse atas ciphertext → **`flag{...}`** (= input benar). Catat: di sini **solve**, bukan patch — mem-patch cek hanya memberi `Correct!` tanpa flag. Tulis timeline unpack → kenali custom crypto → reimplement & balik → flag sebagai POC (Judgement).

## Referensi & Latihan

- **Practical Malware Analysis** (Sikorski & Honig) — bab *Packers and Unpacking* & *Encoding Algorithms*: identifikasi kripto dan unpacking manual.
- **Hex-Rays Blog — "Hands-Free Binary Deobfuscation with gooMBA"** (`hex-rays.com/blog`) — penyederhanaan MBA terintegrasi decompiler.
- **D-810** (`eshard.com` / GitHub) — deobfuscation OLLVM via microcode IDA; dokumentasi teknik CFF & instruction substitution.
- **mandiant/flare-floss** & **mandiant/capa** (GitHub) — ekstraksi string ter-obfuscate & deteksi kapabilitas kripto.
- **TorgoTorgo/ghidra-findcrypt** & **signsrch** — deteksi konstanta kripto baku.
- **angr** / **miasm** / **Triton** docs — symbolic execution untuk membongkar control-flow flattening.
- **Latihan:** **crackmes.one** (tag *unpacking*, *crypto*, *obfuscation*), **FlareOn Challenge** (kanonik untuk unpacking + custom crypto), **pwn.college** (Reverse Engineering), **HackTheBox** Reversing, **picoCTF** kategori Reverse, serta **CyberDefenders**, **BlueTeam Labs Online (BTLO)**, dan **HackTheBox Sherlocks** untuk konteks analisis malware ter-pack.

> Materi ini **hanya** untuk lab pribadi, VM terisolasi, lingkungan kompetisi, atau binari dengan **izin tertulis eksplisit**. Teknik unpacking, deobfuscation, dan patching di sini dipakai untuk belajar memecahkan tantangan CTF dan menganalisis sampel di lab — **bukan** untuk membongkar proteksi lisensi, membajak, atau merekayasa balik perangkat lunak orang lain tanpa izin.
