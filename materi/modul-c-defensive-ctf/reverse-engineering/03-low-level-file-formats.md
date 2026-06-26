# 3. Low Level File Formats

> Sebelum membaca satu baris assembly pun, seorang reverser harus tahu **format file** yang dipegangnya: di mana kode berada, untuk CPU/VM apa, dan bagaimana byte mentah diterjemahkan jadi instruksi yang bisa dibaca. Topik ini adalah jembatan **Assembly & Bytecodes Translation** — keterampilan menerjemahkan byte ↔ instruksi human-readable, baik untuk biner native (ELF/PE/Mach-O) maupun bytecode VM (`.pyc`, `.class`, .NET CIL, DEX, WASM, Lua). Di CTF LKSN 2026 (Modul C — Reverse Engineering), salah mengenali format = jam terbuang membongkar dengan tool yang salah. Mengenali format dengan benar sering memangkas soal dari "baca disassembly ratusan baris" menjadi "satu perintah decompile lalu baca source-nya".

## Konsep

Kode yang bisa dieksekusi tidak pernah berupa byte telanjang — ia dibungkus **container format** yang memberi tahu loader cara memetakannya ke memori. Ada dua keluarga besar:

- **Native executable** — kode mesin (assembly) untuk arsitektur CPU tertentu. Format utama: **ELF** (Linux), **PE** (Windows `.exe`/`.dll`), **Mach-O** (macOS). Isinya machine code yang harus di-**disassemble** (byte → mnemonic).
- **Managed / bytecode** — instruksi untuk *virtual machine*, bukan CPU fisik. Contoh: CPython **`.pyc`**, Java **`.class`/JAR** (JVM), **.NET** PE (CIL/MSIL), Android **DEX** (Dalvik), **WebAssembly** `.wasm`, **Lua** `.luac`. Bytecode menyimpan banyak metadata (nama method, tipe, kadang nama variabel), sehingga bisa di-**decompile** kembali nyaris ke source asli.

Inti topik ini adalah **translation dua arah**: byte → instruksi (disassembly/decompilation) dan instruksi → byte (assembling/patching). Native code "kehilangan" hampir semua informasi tingkat tinggi saat kompilasi, jadi hasil terjemahannya kasar (butuh decompiler heuristik seperti Ghidra). Bytecode mempertahankan struktur, jadi terjemahannya jauh lebih utuh. Mengenali keluarga format adalah keputusan pertama yang menentukan seluruh strategi.

## Cara Kerja

**Struktur container.** Setiap format punya header tetap di awal file:

- **ELF** — magic `7f 45 4c 46` (`\x7fELF`), lalu `e_machine` (arsitektur), `e_entry` (entry point). Punya dua "tampilan": *program headers* (segment, dipakai loader saat runtime) dan *section headers* (`.text`, `.data`, `.rodata`, dipakai linker/analis). Section header bisa di-strip tanpa mengganggu eksekusi.
- **PE** — diawali DOS header `MZ`, lalu signature `PE\0\0`, COFF header, *Optional Header* (`AddressOfEntryPoint`, `ImageBase`), dan *section table* (`.text`, `.rdata`, `.idata`).
- **Mach-O** — magic `0xFEEDFACE` (32-bit) / `0xFEEDFACF` (64-bit); fat/universal binary pakai `0xCAFEBABE`.

**Native: byte → assembly.** Disassembler mendekode *instruction encoding*. x86/x86-64 berukuran variabel (1–15 byte), sedangkan ARM/MIPS umumnya fixed-width 4 byte (ARM Thumb 2/4 byte). Ada dua strategi: **linear sweep** (`objdump` — dekode berurutan dari awal section, mudah desync oleh data-in-code) dan **recursive descent / recursive traversal** (Ghidra, IDA — mengikuti control flow). Perbedaan ini jadi akar banyak trik anti-disassembly (dibahas tuntas di topik 04).

**Bytecode: byte → instruksi VM.** VM dibedakan jadi **stack-based** (JVM, CPython, .NET CLR, WASM — operand ditaruh di operand stack) dan **register-based** (Dalvik/DEX, Lua — pakai virtual register). Contoh layout: `.pyc` modern = header 16 byte (PEP 552: magic 4B + bitfield 4B + 8B berisi mtime+size *atau* 64-bit source hash) lalu *marshalled code object*. JVM `.class` diawali `0xCAFEBABE`, berisi constant pool + method. DEX diawali `dex\n035`.

**Pipeline terjemahan:** byte → parser (`readelf`/`pefile`/`dis`) → disassembler (`objdump`/capstone) → opsional decompiler (Ghidra/Hex-Rays/jadx/dnSpy). Arah balik untuk patching: keystone (asm → byte), `smali` (teks → DEX), `wat2wasm` (WAT → WASM).

## Indikator / Cara Mengenali

Langkah identifikasi selalu mulai dari **magic bytes** (4–8 byte pertama):

| Format | Magic (hex) | Catatan |
|---|---|---|
| ELF | `7f 45 4c 46` | cek `e_machine` untuk arsitektur |
| PE / .NET | `4d 5a` (`MZ`) … `50 45 00 00` | .NET = PE + CLR header (COR20) |
| Mach-O | `fe ed fa ce` / `fe ed fa cf` / `ca fe ba be` (fat) | — |
| Java `.class` | `ca fe ba be` | **bentrok** dengan Mach-O fat — bedakan via konteks/ekstensi |
| CPython `.pyc` | magic 2 byte + `0d 0a` (per versi) | header 16 byte (3.7+) |
| Android DEX | `64 65 78 0a 30 33 35` (`dex\n035`) | versi `035`/`037`/`038`/`039` sesuai API level |
| WebAssembly | `00 61 73 6d` (`\0asm`) | sering disajikan di browser |
| Lua | `1b 4c 75 61` (`\x1bLua`) | byte berikutnya = versi |

Petunjuk lanjutan:

- **`file`**, **`binwalk`**, atau **`rabin2 -I`** mengonfirmasi format; entropy tinggi → packed/terenkripsi.
- **.NET**: PE yang import-nya praktis cuma `mscoree.dll!_CorExeMain` + ada COR20 header → biner managed; pakai **dnSpy**, *bukan* IDA.
- **PyInstaller/py2exe**: PE dengan string `MEI`/`pyi` dan `.pyc` ter-embed → ekstrak dulu sebelum diterjemahkan.
- **Stack vs register**: pola push/pop operand → VM stack-based; akses `v0,v1,...` → Dalvik register-based.

## Langkah Analisis/Investigasi

1. **Identifikasi format** — `file target`, `xxd target | head`, atau `rabin2 -I target`. Tentukan keluarga: native vs bytecode, arsitektur/VM.
2. **Parse header** — `readelf -h/-S/-l` (ELF), `pe-bear`/`pefile`/`rabin2` (PE). Catat entry point, arsitektur, daftar section/segment.
3. **Lokasi kode** — temukan section kode (`.text`), entry point, dan export/method yang relevan.
4. **Terjemahkan** — native: `objdump -d`, Ghidra, IDA. Bytecode: disassemble (`dis`, `javap -c`, `ildasm`, `wasm2wat`, `baksmali`) lalu decompile (pycdc, jadx, dnSpy).
5. **Pulihkan simbol & string** — `strings`, `nm`; pada bytecode angkat nama dari metadata.
6. **Rekonstruksi logika** — baca instruksi hasil terjemahan, susun ulang algoritma; untuk bytecode sering sudah mendekati source penuh.
7. **Assemble/patch bila perlu** — keystone / `smali` / `wat2wasm` untuk round-trip dan verifikasi.

## Tools

| Tool / Plugin | Fungsi singkat |
|---|---|
| `file` / `binwalk` | Identifikasi format & magic bytes |
| `readelf` / `rabin2` | Parse header & section ELF/PE |
| `objdump -d` | Disassembly linear-sweep cepat |
| **Ghidra** / **IDA** / **Binary Ninja** | Disassembly recursive + decompiler native |
| **radare2** / **rizin** | Framework RE berbasis CLI |
| **capstone** | Engine disassembly (library multi-arch) |
| **keystone** | Engine assembler (asm → byte, untuk patch) |
| **pe-bear** / **CFF Explorer** / `pefile` | Parsing struktur PE |
| Python `dis` / `xdis` | Disassembly bytecode `.pyc` |
| **pycdc**/`pycdas` (Decompyle++), `uncompyle6`, `decompyle3` | Decompiler Python |
| `javap -c` / **CFR** / **Procyon** / **Fernflower** | Disassembly & decompile Java |
| `ildasm` / **dnSpy** / **ILSpy** / `monodis` | Disassembly & decompile .NET CIL |
| `baksmali`/`smali` / **jadx** | DEX/Dalvik ↔ smali, decompile ke Java |
| **wabt** (`wasm2wat`, `wasm-objdump`, `wasm-decompile`) | Terjemahan WebAssembly |
| `luac -l` / `unluac` | Bytecode Lua |

## Contoh / Payload

**Identifikasi & header (native ELF):**

```bash
file ./crackme                 # ELF 64-bit LSB pie executable, x86-64 ...
xxd ./crackme | head -1        # 7f45 4c46 ... -> konfirmasi magic ELF
readelf -h ./crackme           # lihat Machine (x86-64/ARM), Entry point
readelf -S ./crackme           # daftar section (.text, .rodata, ...)
objdump -d -M intel ./crackme | less   # disassembly linear-sweep
rabin2 -I sample.exe           # ringkasan format PE (arch, bintype, lang)
```

**Bytecode Python — disassemble lalu decompile:**

```bash
# Disassemble bytecode mentah (lewati header 16 byte di Python 3.7+)
python3 -c "import dis, marshal; f=open('mod.pyc','rb'); f.read(16); \
            code=marshal.load(f); dis.dis(code)"

pycdas mod.pyc        # Decompyle++ : disassembler bytecode
pycdc  mod.pyc        # Decompyle++ : decompile ke source (terbaik utk 3.9+)
uncompyle6 mod.pyc    # alternatif untuk Python <= 3.8
```

**Bytecode lain (Java / .NET / DEX / WASM):**

```bash
javap -c -p Secret.class                 # disassembly JVM bytecode
ildasm /text app.exe                     # disassembly CIL (.NET); atau pakai dnSpy/ILSpy
baksmali d classes.dex -o smali_out/     # DEX -> smali
jadx -d out_src/ app.apk                 # DEX -> Java (decompile)
wasm2wat chal.wasm -o chal.wat           # WASM biner -> WAT (text)
wasm-objdump -d chal.wasm                # disassembly WASM
```

**Disassembly cepat dengan capstone (saat hanya punya potongan byte):**

```python
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
md = Cs(CS_ARCH_X86, CS_MODE_64)
for i in md.disasm(b"\x48\x83\xec\x10\xc3", 0x1000):
    print(f"{i.address:#x}\t{i.mnemonic}\t{i.op_str}")
# 0x1000  sub  rsp, 0x10
# 0x1004  ret
```

## Anti-Forensik & Pitfall

**Teknik evasion attacker di level format** (mempersulit terjemahan; trik anti-debug/anti-disassembly murni dibahas di topik 04):

- **Header rusak tapi tetap loadable** — field yang diabaikan loader sengaja dikotori: `e_shoff` di-nol-kan atau section header palsu ditanam. OS tetap menjalankan biner (cukup dari program header), tapi Ghidra/parser bingung. Andalkan program/segment view, bukan section.
- **Section header di-strip** (`strip`, biner stripped) — Ghidra/IDA kehilangan nama fungsi & batas simbol; harus rekonstruksi manual atau lewat FLIRT/signature.
- **Custom-opcode CPython** — opcode map di-remap (opcode di-shuffle) atau magic `.pyc` dipalsukan, sehingga `dis`/pycdc standar menghasilkan sampah; perlu membangun ulang `opmap` atau memakai interpreter yang dimodifikasi.
- **Packer & bundler** — UPX, PyInstaller/py2exe, atau .NET packer (ConfuserEx) membungkus kode asli. Wajib **unpack/ekstrak dulu** (`upx -d`, `pyinstxtractor.py`) sebelum format sebenarnya bisa diterjemahkan.
- **Names section dibuang** (WASM) atau identifier di-mangle (Java/Android via obfuscator) — terjemahan tetap jalan, tapi semantik nama hilang.

**Pitfall analis** (kesalahan yang membuat flag terlewat):

- **Salah arsitektur/mode** — mendisassemble ARM sebagai x86, keliru Thumb vs ARM, atau salah endianness → output sampah. Selalu konfirmasi `e_machine` dulu.
- **Percaya linear-sweep di sekitar data** — `objdump` desync saat ada data-in-code, memunculkan instruksi hantu. Silang-cek dengan Ghidra (recursive).
- **Tool decompiler tak cocok versi** — `uncompyle6` pada `.pyc` 3.11 akan gagal; cocokkan tool dengan versi Python (pycdc untuk yang baru).
- **Lupa offset header `.pyc`** — `marshal.load` tanpa melewati header (16 byte di 3.7+, 12 byte di 3.3–3.6, 8 byte di ≤3.2) memunculkan error "bad marshal data".
- **Memperlakukan biner managed sebagai native** — mendisassemble stub PE .NET hanya memperlihatkan `_CorExeMain`; pakai dnSpy/ILSpy.
- **Over-reverse** — membaca bytecode instruksi demi instruksi padahal satu perintah `jadx`/`pycdc`/`dnSpy` sudah mengembalikan source mendekati utuh.

## Mini-Lab

**Skenario:** Diberikan dua file tanpa ekstensi jelas: `checker` dan `validator`. Satu adalah ELF stripped yang memvalidasi serial, satu lagi bytecode Python yang menyembunyikan flag. Tugas: kenali format, terjemahkan, pulihkan logika.

1. **Lakukan:** `file checker validator` dan `xxd validator | head -1` → **Dapatkan** identifikasi format (magic ELF vs `.pyc`/marshal) dan versi Python target.
2. **Lakukan:** untuk `.pyc` jalankan `pycdas` lalu `pycdc` (atau `dis` setelah `f.read(16)`) → **Dapatkan** source/disasm fungsi validasi dan konstanta pembanding flag.
3. **Lakukan:** untuk ELF stripped jalankan `readelf -h`, `objdump -d -M intel`, lalu buka di Ghidra → **Dapatkan** algoritma pengecekan serial dari hasil dekompilasi.
4. **Dapatkan:** rekonstruksi input/serial yang benar dari kedua jalur, peroleh **`flag{...}`**, dan tulis ringkas langkah identifikasi→terjemahan→rekonstruksi sebagai POC.

## Referensi & Latihan

- **System V ABI (ELF) spec** & **Microsoft PE/COFF Specification** — rujukan kanonik struktur header native.
- **Practical Binary Analysis** (Dennis Andriesse) — ELF/PE, linear vs recursive disassembly, tooling.
- **CPython `dis` documentation** & **PEP 552 (Deterministic pycs)** — layout bytecode & header `.pyc`.
- **zrax/pycdc (Decompyle++)** dan **rocky/python-uncompyle6** — repo & catatan dukungan versi decompiler.
- **WABT** (WebAssembly Binary Toolkit) docs — `wasm2wat`/`wasm-objdump`/`wasm-decompile`.
- **crackmes.one**, **pwn.college (Reverse Engineering)**, **picoCTF (Reversing)** — latihan terjemahan native & bytecode bertahap.
- **HackTheBox Reversing challenges**, **CyberDefenders** & **BlueTeam Labs Online** — triase format malware (PE/.NET/packed) berbasis kasus nyata.

> Materi ini **hanya** untuk lab pribadi, lingkungan kompetisi (CTF), atau biner/aplikasi dengan **izin tertulis eksplisit**. Teknik mengenali format & menerjemahkan assembly/bytecode di sini dipakai untuk belajar CTF, menganalisis sampel di lab, dan menguji program milik sendiri — **bukan** untuk membongkar proteksi atau merekayasa balik perangkat lunak orang lain tanpa izin.
