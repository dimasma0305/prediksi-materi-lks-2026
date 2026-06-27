# 1. Static Analysis

> Static analysis adalah membongkar program **tanpa menjalankannya** — membaca header, string, import, disassembly, dan dekompilasi untuk memahami logikanya dari teks kode itu sendiri. Di CTF LKSN 2026 (Modul C — Reverse Engineering), soal kategori ini biasanya memberi sebuah biner (`crackme`, ELF/PE) yang memvalidasi sebuah input/flag; tugas peserta adalah **merekonstruksi algoritma** validasi dari decompiler lalu **membaliknya** — secara manual, brute-force, atau dengan SMT solver **z3** — untuk memperoleh input yang membuat program mencetak "Correct". Lawannya, *dynamic analysis* (menjalankan & men-debug), dibahas terpisah di [02-dynamic-analysis.md](02-dynamic-analysis.md); halaman ini fokus pada apa yang bisa dipetik tanpa eksekusi.

## Konsep

Sebuah biner adalah *ground truth* dari logikanya: meskipun source code hilang, instruksi mesin tetap menjelaskan persis apa yang dilakukan program. Static analysis mengangkat semantik itu kembali ke level yang bisa dibaca manusia — dari byte mentah → disassembly (assembly) → dekompilasi (pseudo-C). Keunggulannya: **aman** (kode jahat tidak pernah dijalankan), **menyeluruh** (semua cabang terlihat, termuk yang jarang dipicu runtime), dan **deterministik** (tidak terganggu anti-debug/timing). Keterbatasannya: kode yang ter-pack, ter-enkripsi, atau dibentuk runtime tidak tampak sampai program berjalan.

Inti tugas RE di CTF adalah **Reconstruct Algorithm**: temukan rutin pengecek (mis. `check`, `validate`, `verify`), pahami transformasi yang dikenakan ke input, dan simpulkan input apa yang memenuhi semua kendalanya. Untuk pengecek sederhana (`strcmp` ke konstanta) flag langsung terlihat. Untuk transformasi per-karakter (XOR, rotate, aritmetika) yang dibandingkan ke sebuah tabel konstanta, persoalannya menjadi **constraint satisfaction** — di sinilah **z3** (SMT solver dari Microsoft Research) bersinar: cukup modelkan tiap byte input sebagai variabel dan deklarasikan kendalanya, biarkan solver mencari jawabannya.

## Cara Kerja

Disassembler menerjemahkan opcode menjadi mnemonic assembly. Ada dua strategi yang penting dipahami karena menjadi akar banyak jebakan:

- **Linear sweep** (`objdump -d`) — mendekode byte berurutan dari awal ke akhir section. Cepat, tapi **mudah tertipu data-in-code**: byte data yang diselipkan di tengah kode dibaca sebagai instruksi palsu.
- **Recursive descent** (Ghidra, IDA, radare2 dengan `aaa`) — mengikuti alur kontrol (call/jmp) sehingga lebih akurat memisahkan kode dari data, tapi bisa dikelabui *indirect jump* dan opaque predicate.

Decompiler (Ghidra, atau Hex-Rays decompiler di IDA via `F5`) melangkah lebih jauh: ia mengangkat assembly ke representasi-antara (Ghidra memakai **P-Code**), melakukan analisis aliran data, lalu menghasilkan pseudo-C. Output ini **rekonstruksi, bukan source asli** — nama variabel dibuat-buat, tipe sering salah ditebak, dan calling convention bisa keliru; tetap silang-periksa dengan disassembly saat ragu.

Untuk merekonstruksi algoritma, alur baku: identifikasi fungsi pengecek → baca pseudo-C-nya → terjemahkan transformasi ke pseudocode/Python → balik secara matematis (jika invertible) atau serahkan kendalanya ke z3. z3 bekerja pada **BitVec** (vektor bit lebar tetap, mis. 8-bit untuk satu byte) sehingga semantik overflow, wrap-around, shift, dan rotate dimodelkan persis seperti CPU — selama operator yang dipilih benar (lihat Pitfall: signed vs unsigned).

## Indikator / Cara Mengenali

Sebelum menyelam, kenali *jenis* soalnya dari triase statis — ini menentukan jalan tercepat ke flag:

- **`strcmp`/`memcmp` ke buffer tetap** → flag kemungkinan plaintext; cukup `strings` atau baca konstanta.
- **Loop transform per-karakter** lalu dibandingkan ke sebuah tabel (`xor`, `add`, `rol/ror`, `* / %`) → kandidat kuat **z3** atau brute-force per byte.
- **Banyak kendala/sistem persamaan** antar byte (mis. `a+b==X`, `a^c==Y`) → z3 sangat diunggulkan dibanding brute manual.
- **Biner ter-pack** (entropi tinggi, section bernama `UPX0`/`UPX1`, import table nyaris kosong) → static murni buntu sampai di-unpack.
- **String hilang dari `strings`** padahal program jelas mencetak teks → string ter-obfuscate/encoded (stack strings) → butuh **FLOSS**.
- **`ptrace`/`IsDebuggerPresent`/RDTSC** terlihat di import/disassembly → ada anti-debug; mendeteksinya statis itu mudah, *membungkamnya* urusan halaman dinamis.

Identifikasi awal yang wajib (ekuivalen "kenali target dulu"):

| Pertanyaan | Tool / cara |
|---|---|
| Format & arsitektur? | `file`, `rabin2 -I ./bin` |
| Dikompilasi dari bahasa apa? | **Detect It Easy (DIE)**, string runtime (`Go build`, `rustc`) |
| Ter-pack / di-strip? | DIE, entropi per-section, `nm` (gagal bila stripped) |
| String & konstanta apa yang ada? | `strings`, `strings -e l` (UTF-16LE/PE), `rabin2 -z` |
| Import/symbol apa yang dipakai? | `readelf -d`, `rabin2 -i`, IDA Imports window |

## Langkah Analisis/Investigasi

1. **Identifikasi biner** — `file` + DIE untuk format, arsitektur, compiler, dan status pack/strip. Tanpa ini, langkah berat berikutnya bisa sia-sia (mis. mendisassemble stub UPX).
2. **Panen permukaan** — `strings`/`rabin2 -z` untuk pesan "Correct/Wrong", format flag, atau kunci yang bocor; `readelf`/`rabin2 -i` untuk import yang menyiratkan perilaku (crypto, file, network).
3. **Petakan fungsi** — buka di Ghidra/IDA/radare2; cari `main` dan rutin yang dirujuk pesan keberhasilan/kegagalan. Di radare2: `aaa` lalu `afl`.
4. **Temukan pengecek** — lacak cross-reference (`axt` di r2, `X` di IDA) dari string "Wrong"/`strcmp` ke fungsi pemanggilnya.
5. **Rekonstruksi algoritma** — dekompilasi (`F5` / `pdg`), baca transformasi input, dan **tulis ulang ke Python** sebagai model yang bisa diuji.
6. **Ekstrak konstanta** — angkat tabel pembanding/kunci dari listing (`px` di r2, atau langsung dari Ghidra Listing) sebagai array byte.
7. **Balikkan** — jika transformasi invertible, balik manual; jika tidak/kompleks, encode kendala ke **z3** dan selesaikan; alternatif eksekusi-simbolik dengan **angr**.
8. **Verifikasi & dokumentasi** — uji kandidat flag ke biner asli, lalu tulis langkah (decompile → algoritma → solver) sebagai POC untuk nilai Judgement.

## Tools

| Tool / Plugin | Fungsi singkat |
|---|---|
| `file` / `rabin2 -I` | Identifikasi format, arsitektur, bit, endianness |
| **Detect It Easy (DIE)** | Deteksi compiler & packer (UPX, Themida, dll.) |
| `strings` / `strings -e l` | Tarik string ASCII / UTF-16LE (wide, khas PE) |
| **FLOSS** (Mandiant) | Decode stack strings & string ter-obfuscate yang luput dari `strings` |
| **Ghidra** | Disassembler + decompiler (P-Code), gratis; headless via `analyzeHeadless` |
| **IDA** (Hex-Rays) | Disassembler + decompiler interaktif (`F5`), standar industri |
| **Binary Ninja** | Disassembler + IL (LLIL/MLIL/HLIL) + decompiler |
| **radare2 / rizin** + **Cutter** | CLI RE & GUI (Cutter kini berbasis rizin); decompiler via `r2ghidra`/`rz-ghidra` (`pdg`) |
| `objdump` / `readelf` / `nm` | Disassembly linear, header/section/symbol ELF |
| **z3** (`z3-solver`) | SMT solver: selesaikan kendala byte hasil rekonstruksi |
| **angr** | Eksekusi simbolik (backend z3/claripy) untuk auto-solve tanpa run native |
| **Ghidrathon** / **PyGhidra** | Skripting Ghidra dengan CPython 3 |

## Contoh / Payload

**Triase statis** (langkah 1–4) pada sebuah crackme ELF:

```bash
file ./crackme                       # ELF 64-bit, dynamically linked, stripped?
rabin2 -I ./crackme                  # arch, bits, lang, canary, pic
rabin2 -z ./crackme | grep -i flag   # string permukaan ("Wrong", "Correct")
r2 -A ./crackme                      # buka + analisis (sama dgn aaa)
[0x000010a0]> afl                    # daftar fungsi
[0x000010a0]> axt @ str.Wrong        # siapa yg merujuk pesan gagal -> fungsi check
[0x000010a0]> s sym.check ; pdg      # seek + decompile (r2ghidra)
[0x000010a0]> px 32 @ obj.enc        # dump 32 byte tabel pembanding -> konstanta
```

**Reconstruct Algorithm** — misal Ghidra/`pdg` mengungkap pengecek seperti ini:

```c
int check(char *in) {
  for (int i = 0; i < 31; i++) {
    unsigned char c = in[i];
    c = (c << 3 | c >> 5) & 0xff;   // rotate-left 3
    c ^= key[i & 3];               // key = {0xDE,0xAD,0xBE,0xEF}
    if (c != enc[i]) return 0;     // enc[] = tabel konstanta yg di-dump
  }
  return 1;
}
```

**Solver z3** — modelkan tiap byte flag, deklarasikan kendalanya, biarkan solver yang membalik:

```python
from z3 import *

# konstanta diangkat dari biner (langkah ekstraksi di atas) -> tabel `enc` (31 byte)
enc = [0xbc,0xf7,0x24,0x9d,0x05,0x3e,0x3f,0x4c,0x7f,0x0e,0x27,0x15,0x7d,0xee,0x27,
       0x9c,0x24,0x6e,0x3f,0x7c,0x24,0x7e,0x27,0x15,0x45,0x2c,0xdd,0x5c,0x47,0x8e,0x55]
key = [0xDE, 0xAD, 0xBE, 0xEF]
N   = len(enc)                                   # 31

s = Solver()
flag = [BitVec(f"f{i}", 8) for i in range(N)]    # tiap byte = BitVec 8-bit

for i, f in enumerate(flag):
    s.add(f >= 0x20, f <= 0x7e)                  # batasi ke ASCII printable
    r = RotateLeft(f, 3)                         # cocokkan rotate-left 3 di kode
    s.add((r ^ key[i & 3]) == enc[i])            # XOR lalu samakan ke tabel

assert s.check() == sat
m = s.model()
sol = bytes(m[f].as_long() for f in flag)
print(sol)                                       # b"LKSN{r0t4t3_th3n_x0r_z3_s0lv3d}"

# Cek keunikan: kunci jawaban harus tunggal
s.add(Or([f != b for f, b in zip(flag, sol)]))
print("unik" if s.check() == unsat else "ADA solusi lain — kendala kurang ketat")
```

**Alternatif angr** (eksekusi simbolik — tetap tanpa menjalankan kode native secara nyata). Kunci memakai angr dengan benar adalah **menentukan `find`/`avoid` lewat XREF string**, bukan menebak alamat, lalu **meredam *state explosion*** agar tidak meledak di loop/`strlen`:

```python
import angr, claripy

proj = angr.Project("./crackme", auto_load_libs=False)

# 1) find/avoid via XREF string -> lebih tahan-ASLR & lebih jujur daripada hardcode alamat.
#    Dapatkan alamat blok pencetak "Correct"/"Wrong" dari decompiler / radare2:
#       r2: 'axt @ str.Correct'  -> alamat call/blok yang merujuknya
#    ATAU pakai PREDIKAT atas output stdout, sehingga tak perlu alamat sama sekali:
def is_win(state):  return b"Correct" in state.posix.dumps(1)
def is_fail(state): return b"Wrong"   in state.posix.dumps(1)

# 2) Input simbolik DENGAN BATAS: panjang tetap + ASCII printable.
#    Mempersempit ruang = paling efektif menahan state explosion.
flag_len = 31
sym = claripy.BVS("flag", flag_len * 8)
state = proj.factory.full_init_state(stdin=sym)
for byte in sym.chop(8):
    state.solver.add(byte >= 0x20, byte <= 0x7e)

simgr = proj.factory.simgr(state)

# 3) Redam state explosion:
#    - Veritesting menggabungkan cabang (static symbolic execution) -> ledakan path ditekan.
#    - 'avoid' yang agresif membuang state gagal lebih dini.
#    - Untuk fungsi mahal (mis. printf/strlen), biarkan angr memakai SimProcedure bawaan
#      (default auto_load_libs=False sudah meng-hook banyak fungsi libc).
simgr.use_technique(angr.exploration_techniques.Veritesting())
simgr.explore(find=is_win, avoid=is_fail)

found = simgr.found[0]
print(found.solver.eval(sym, cast_to=bytes))     # rekonstruksi flag dari constraint
print(found.posix.dumps(0))                       # alternatif: input stdin yang memicu sukses
```

> Bila masih meledak: kurangi `flag_len`, tambah `avoid` ke blok error, pakai `angr.exploration_techniques.DFS()` agar memori hemat, hook fungsi berat secara manual (`proj.hook_symbol("strlen", angr.SIM_PROCEDURES['libc']['strlen']())`), atau aktifkan `angr.options.LAZY_SOLVES`. Kalau kendalanya murni aljabar per-byte (seperti contoh ini), **z3 di atas jauh lebih cepat** daripada angr — pakai angr saat alur kontrol kompleks/berantai, bukan untuk transform per-byte sederhana.

## Anti-Forensik & Pitfall

**Teknik anti-static-analysis yang dipasang penyusun soal/malware** (mempersulit pembacaan statis):

- **Packing/enkripsi** (UPX, Themida, VMProtect) — disassembly hanya menampilkan stub unpacker; kode asli baru muncul di memori saat run. UPX standar dibalik dengan `upx -d`; packer kustom butuh dump runtime (ranah dinamis).
- **String obfuscation / stack strings** — string dibangun byte-per-byte atau di-XOR sehingga `strings` buta. Lawan dengan **FLOSS**, atau rekonstruksi rutin decode-nya.
- **Anti-disassembly** — junk bytes, instruksi tumpang-tindih (*overlapping*), dan opaque predicate menyesatkan linear sweep; pakai recursive descent dan perbaiki batas fungsi secara manual.
- **Control-flow flattening / obfuscation (OLLVM)** — alur asli disembunyikan di balik dispatcher `switch`; perlu deobfuscation/scripting decompiler untuk dipulihkan.
- **API hashing / dynamic import** — fungsi sistem dipanggil lewat hash, bukan nama, sehingga import table kosong dan niat program kabur secara statis.
- **Symbol stripping & nama palsu** — `main` tak bernama, atau simbol menyesatkan; sandarkan analisis pada xref dan string, bukan nama.

**Pitfall analis** (kesalahan yang membuat flag terlewat):

- **z3 — signed vs unsigned (paling sering bikin flag sampah).** Pada BitVec, `>>` adalah *arithmetic* (signed) shift; untuk logical shift pakai **`LShR`**. Gunakan **`UDiv`/`URem`/`UGT`/`ULT`** untuk operasi unsigned, dan perhatikan lebar **`ZeroExt`/`SignExt`** saat memperluas byte. Salah satu saja → model `sat` tapi hasilnya bukan flag.
- **Lupa membatasi ruang & keunikan.** Tanpa `0x20..0x7e` solver bisa memberi byte tak-printable; tanpa cek "ada solusi lain", kamu bisa menyerahkan jawaban yang tidak diterima biner.
- **Endianness saat memuat konstanta.** Tabel `dword`/`qword` yang dibaca terbalik membuat seluruh kendala salah. Konfirmasi urutan byte (`px` vs `pxw`).
- **Percaya decompiler mentah-mentah.** Tipe/cast salah, variabel digabung keliru, calling convention meleset — silang-periksa pseudo-C dengan disassembly pada bagian kritis.
- **Tak sadar biner ter-pack.** Mendisassemble stub UPX lalu bingung "kok logikanya tidak ada"; cek entropi/section lebih dulu.
- **Memaksa static pada masalah dinamis.** Self-modifying code, anti-debug, dan kunci yang dibentuk runtime tak akan terbaca statis — pindah ke [02-dynamic-analysis.md](02-dynamic-analysis.md).

## Mini-Lab

**Skenario:** Diberikan `crackme01` (ELF x86-64, stripped). Program meminta sebuah string, mengenakan transformasi per-karakter, lalu membandingkannya dengan tabel internal dan mencetak "Correct" hanya bila cocok. Flag = input yang benar.

1. **Lakukan:** `file ./crackme01` lalu DIE → pastikan tidak ter-pack; `rabin2 -z` → catat pesan "Correct/Wrong".
2. **Lakukan:** buka di Ghidra/radare2, lacak xref dari string "Wrong" → temukan fungsi `check`, lalu `F5`/`pdg` untuk dekompilasi.
3. **Lakukan:** rekonstruksi transformasi ke Python dan **ekstrak tabel konstanta** (`px @ obj...` atau Ghidra Listing) sebagai array byte.
4. **Dapatkan:** tulis solver **z3** (BitVec per byte, batasi printable, samakan ke tabel, cek keunikan) → peroleh **`flag{...}`**, uji balik ke biner, dan dokumentasikan rantai decompile → algoritma → solver sebagai POC (Judgement).

## Referensi & Latihan

- **Ghidra** — dokumentasi resmi (`ghidra-sre.org`) & *The Ghidra Book* (Eagle & Nance) untuk decompiler, P-Code, dan headless scripting.
- **z3** — *Programming Z3* (Bjørner et al.) dan z3 Python API guide untuk BitVec, `LShR`/`URem`, dan modeling kendala.
- **angr** — dokumentasi & repo `angr/angr-examples` (banyak solver crackme berbasis eksekusi simbolik).
- **crackmes.one** — ratusan crackme bertingkat untuk latihan reconstruct + solve, lengkap dengan writeup.
- **picoCTF** & **HackTheBox** (track Reversing) — koleksi soal RE bergaya CTF dengan pembahasan komunitas.
- **Malware Unicorn — RE101 / RE102** — kursus gratis fondasi reverse engineering biner.
- ***Practical Malware Analysis*** (Sikorski & Honig) — kanon analisis statis & dinamis untuk biner Windows/PE.

> Materi ini **hanya** untuk lab pribadi, lingkungan kompetisi LKSN, atau biner/aplikasi dengan **izin tertulis eksplisit**. Teknik static analysis di sini untuk belajar memecahkan tantangan CTF, menganalisis sampel di VM terisolasi, dan menguji program milik sendiri — **bukan** untuk membongkar proteksi atau merekayasa balik perangkat lunak orang lain tanpa izin.
