# 6. Arsitektur

> Sebelum membaca satu baris disassembly pun, seorang reverser harus tahu **arsitektur (ISA — Instruction Set Architecture)** yang menjadi target biner. Arsitektur menentukan **register**, **calling convention**, **endianness**, dan **encoding instruksi** — salah menebak arsitektur berarti disassembler menampilkan sampah dan analisis berhenti sebelum dimulai. Di CTF LKSN 2026 (Modul C — Reverse Engineering), tidak semua soal berupa `x86_64` ELF/PE biasa: firmware router dan IoT umumnya **MIPS** atau **ARM**, aplikasi mobile hampir selalu **ARM/ARM64**, dan sampel embedded bisa MIPS big-endian. Halaman ini membahas cara mengenali, memuat, mengemulasi, dan men-debug biner lintas arsitektur: **x86_64 / x64**, **ARM**, dan **MIPS**.

## Konsep

Arsitektur prosesor adalah "bahasa mesin" yang dieksekusi CPU. Dua keluarga besar relevan di CTF:

- **CISC** — `x86` (32-bit / IA-32) dan `x86_64`. Instruksi **panjang variabel (1–15 byte)**, banyak mode pengalamatan, register sedikit. Dominan di desktop/server.
- **RISC** — `ARM` dan `MIPS`. Instruksi **panjang tetap** (umumnya 4 byte), load/store architecture (operasi aritmetik hanya antar-register), banyak register. Dominan di mobile, router, IoT, embedded.

Catatan penting soal penamaan di kisi-kisi: **`x86_64` = `x64` = `AMD64` = `EM64T` = `Intel 64`** — semuanya **nama untuk arsitektur yang sama** (ekstensi 64-bit dari x86 yang dirancang AMD). Jangan bingung menganggapnya dua arsitektur berbeda; "x64" hanyalah istilah Microsoft/umum untuk x86_64. Sebaliknya, **ARM** dan **MIPS** masing-masing punya varian 32-bit dan 64-bit yang benar-benar berbeda dan harus dipilih dengan benar di tool.

Mengapa ini relevan di RE pertahanan: analis malware menerima sampel dari firmware perangkat jaringan (MIPS/ARM), payload Android (ARM64), atau dropper Windows (x86/x64). Memilih processor yang salah di Ghidra/IDA membuat fungsi crypto yang ingin Anda baca berubah jadi instruksi tak bermakna.

## Cara Kerja

Setiap arsitektur punya **register**, **calling convention**, dan **endianness** sendiri. Inilah yang harus ada di kepala saat membaca disassembly:

| Aspek | x86 (32-bit) | x86_64 / x64 | ARM32 (AArch32) | ARM64 (AArch64) | MIPS (o32) |
|---|---|---|---|---|---|
| Register umum | `eax,ebx,ecx,edx,esi,edi` | `rax–rdx,rsi,rdi,r8–r15` | `r0–r12,sp(r13),lr(r14),pc(r15)` | `x0–x30,sp` (`w0–w30` 32-bit) | `$v0–$v1,$a0–$a3,$t0–$t9,$s0–$s7,$ra,$sp` |
| Arg ke fungsi | stack (cdecl) | **SysV:** `rdi,rsi,rdx,rcx,r8,r9` · **MS x64:** `rcx,rdx,r8,r9` | `r0–r3` lalu stack | `x0–x7` lalu stack | `$a0–$a3` lalu stack |
| Return value | `eax` | `rax` | `r0` | `x0` | `$v0` (`$v1`) |
| Return address | stack | stack | `lr` (`bl`/`bx lr`) | `x30=lr` (`bl`/`ret`) | `$ra` (`jal`/`jr $ra`) |
| Panjang instruksi | variabel 1–15B | variabel 1–15B | 4B (ARM) / 2–4B (Thumb) | 4B tetap | 4B tetap |
| Endianness | little | little | bi-endian (umumnya **LE**) | bi-endian (umumnya **LE**) | **BE atau LE** (MIPSel) |

Detail yang sering jadi jebakan:

- **Windows x64 shadow space.** Microsoft x64 mewajibkan caller menyediakan 32 byte "shadow store" di stack untuk 4 argumen register pertama — terlihat sebagai `sub rsp, 0x28` di prolog. SysV (Linux/macOS) tidak punya ini, tapi punya **red zone** 128 byte di bawah `rsp`.
- **ARM vs Thumb.** ARM32 punya dua mode encoding: **ARM** (instruksi 4 byte) dan **Thumb/Thumb-2** (2 atau 4 byte). Mode ditandai oleh **bit ke-0 alamat fungsi** (LSB=1 → Thumb). Salah mode = disassembly kacau total.
- **MIPS branch delay slot.** Instruksi **tepat setelah** branch/jump (`beq`, `j`, `jal`, `jr`) **selalu dieksekusi** sebelum lompatan benar-benar terjadi, karena pipeline. Membaca MIPS tanpa memperhitungkan delay slot menghasilkan urutan logika yang salah.
- **Endianness.** `x86/x64` selalu little-endian. ARM bi-endian tapi di Linux/Android/iOS hampir selalu LE. MIPS legendaris **big-endian**, tetapi banyak router (Broadcom/Atheros) memakai **little-endian (MIPSel)** — wajib dipastikan.

## Indikator / Cara Mengenali

Mengidentifikasi arsitektur biner tak dikenal — langkah pertama mutlak:

- **`file <binary>`** — membaca header ELF/PE/Mach-O dan langsung menyebut arsitektur, bit, endianness, statis/dinamis. Contoh: `ELF 32-bit LSB executable, MIPS, MIPS32`.
- **`readelf -h`** / **field `e_machine`** pada ELF — angka pasti arsitektur.
- **PE: field `Machine`** di IMAGE_FILE_HEADER (lihat di CFF Explorer/PE-bear/`pefile`).
- **Mnemonik khas** saat melihat disassembly: `push/pop/mov rax` → x86/x64; `ldr/str x0`, `bl`, `ret` → ARM; `lw/sw $a0`, `jal`, `jr $ra` → MIPS.

Nilai konstanta yang berguna dihafal:

| Arsitektur | ELF `e_machine` | PE `Machine` |
|---|---|---|
| x86 (32-bit) | `EM_386` = **3** | `IMAGE_FILE_MACHINE_I386` = **0x14C** |
| x86_64 / x64 | `EM_X86_64` = **62** | `IMAGE_FILE_MACHINE_AMD64` = **0x8664** |
| ARM (32-bit) | `EM_ARM` = **40** | `IMAGE_FILE_MACHINE_ARMNT` = **0x1C4** (Thumb-2) |
| ARM64 | `EM_AARCH64` = **183** | `IMAGE_FILE_MACHINE_ARM64` = **0xAA64** |
| MIPS | `EM_MIPS` = **8** | — (PE MIPS langka) |

Catatan: pada ELF, byte `EI_DATA` (`readelf -h` → "Data") menyatakan endianness — `2's complement, little endian` vs `big endian`. Untuk MIPS ini penentu apakah Anda butuh `qemu-mipsel` atau `qemu-mips`.

## Langkah Analisis/Investigasi

1. **Identifikasi arsitektur** — `file` + `readelf -h` (atau cek `Machine` PE). Catat: arsitektur, **bit** (32/64), **endianness**, dan statis vs dinamis.
2. **Pilih processor yang benar di disassembler** — di Ghidra pilih Language ID yang cocok (mis. `MIPS:BE:32:default`, `ARM:LE:32:v8`, `AARCH64:LE:64:v8A`, `x86:LE:64:default`); di radare2/rizin set `-a`/`-b`/endianness.
3. **Petakan kode dengan calling convention yang tepat** — baca argumen dari register yang benar (mis. `$a0–$a3` untuk MIPS, `x0–x7` untuk ARM64), bukan asumsi gaya x86.
4. **Emulasi bila non-native** — jalankan biner asing dengan `qemu-user` (`qemu-mipsel`, `qemu-arm`, `qemu-aarch64`) untuk dynamic analysis di mesin x86_64 Anda.
5. **Cross-debug** — pasang gdbstub via `qemu-... -g <port>` lalu sambung dengan `gdb-multiarch` (`set architecture`, `target remote`), atau pakai `pwndbg`/`gef` yang mendukung multi-arch.
6. **Korelasi & dokumentasi** — rekonstruksi algoritma (mis. routine cek password) dan susun solver; flag muncul setelah logika dipahami pada arsitektur yang benar.

## Tools

| Tool | Fungsi singkat |
|---|---|
| `file` | Deteksi cepat arsitektur, bit, endianness dari header |
| `readelf -h` / `objdump -f` | Baca `e_machine`/endianness ELF secara presisi |
| **Ghidra** | Decompiler multi-arch (SLEIGH): x86/x64, ARM, AArch64, MIPS, PPC, RISC-V, dll. |
| **IDA Pro** / **Binary Ninja** | Disassembler/decompiler dengan banyak processor module |
| **radare2 / rizin** | Analisis multi-arch berbasis Capstone (`-a`, `-b`, `cfg.bigendian`) |
| **Capstone** | Library disassembly multi-arch untuk scripting Python |
| **qemu-user** (`qemu-mips(el)`, `qemu-arm`, `qemu-aarch64`) | Menjalankan biner arsitektur asing di host x86_64 |
| **gdb-multiarch** + `pwndbg`/`gef` | Debug lintas arsitektur via gdbstub |
| cross binutils (`mips-linux-gnu-objdump`, `arm-linux-gnueabi-*`) | Disassembly/toolchain spesifik arsitektur |
| **binwalk** | Ekstraksi firmware (router MIPS/ARM) sebelum analisis |
| **Unicorn Engine** | Emulasi potongan kode (CPU emulator framework) untuk brute/solve |
| **frida** (`frida-stalker`) | Instrumentasi dinamis; mendukung arm/arm64/x86/x64 |

## Contoh / Payload

**1) Identifikasi arsitektur target:**

```bash
file ./challenge
# ELF 32-bit MSB executable, MIPS, MIPS32 ... statically linked   <-- MIPS big-endian!

readelf -h ./challenge | grep -E 'Class|Data|Machine'
#   Class:   ELF32
#   Data:    2's complement, big endian        <-- butuh qemu-mips (BUKAN mipsel)
#   Machine: MIPS R3000
```

**2) Muat dengan processor yang benar (radare2 / rizin):**

```bash
# MIPS 32-bit big-endian
r2 -a mips -b 32 ./challenge
# di dalam r2: atur endianness lalu analisis
[0x...]> e cfg.bigendian=true
[0x...]> aaa
[0x...]> pdf @ main          # baca delay slot setelah setiap branch!

# ARM64 contoh:  r2 -a arm -b 64 ./app
```

**3) Disassembly cross-arch dengan binutils spesifik arsitektur:**

```bash
mips-linux-gnu-objdump -d ./challenge | less     # otomatis hormati endianness ELF
# objdump generik juga bisa: objdump -d -m mips ./challenge
```

**4) Jalankan biner MIPS BE di host x86_64 (emulasi qemu-user):**

```bash
# sediakan sysroot lib MIPS via -L; gunakan qemu-mips untuk big-endian
qemu-mips -L /usr/mips-linux-gnu ./challenge
# big-endian -> qemu-mips ; little-endian (MIPSel) -> qemu-mipsel
```

**5) Cross-debugging (qemu gdbstub + gdb-multiarch):**

```bash
# terminal 1: buka gdbstub di port 1234, eksekusi tertahan di entry
qemu-mips -L /usr/mips-linux-gnu -g 1234 ./challenge

# terminal 2:
gdb-multiarch ./challenge
(gdb) set architecture mips
(gdb) set endian big
(gdb) target remote :1234
(gdb) break main
(gdb) continue
(gdb) info registers $a0 $a1 $v0      # baca argumen via register MIPS
```

**6) Disassembly programatik lintas arsitektur (Capstone):**

```python
from capstone import *
code = open('shellcode.bin','rb').read()

# MIPS32 big-endian
md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN)
# ARM Thumb:  Cs(CS_ARCH_ARM,   CS_MODE_THUMB)
# ARM64:      Cs(CS_ARCH_ARM64, CS_MODE_ARM)
# x86_64:     Cs(CS_ARCH_X86,   CS_MODE_64)
for ins in md.disasm(code, 0x400000):
    print(f"0x{ins.address:x}\t{ins.mnemonic}\t{ins.op_str}")
```

## Anti-Forensik & Pitfall

**Teknik evasion attacker (mempersulit identifikasi/analisis arsitektur):**

- **Header arsitektur dipalsukan/dirusak** — `e_machine` atau `Machine` PE diubah agar `file` salah tebak; biner tetap berjalan jika loader target mengabaikan field itu, tapi disassembler Anda salah memuat. Lawan dengan menebak dari pola mnemonik / entropy.
- **Pencampuran ARM ↔ Thumb** — fungsi berpindah mode di tengah jalan (via `bx`/bit LSB) untuk membingungkan linear disassembly; potongan kode yang sama terbaca berbeda di kedua mode.
- **Penyalahgunaan delay slot MIPS** — instruksi berguna disembunyikan di delay slot setelah branch, sehingga pembaca yang mengabaikannya salah memahami alur dan nilai register.
- **Anti-disassembly x86 panjang-variabel** — menyisipkan byte sampah agar disassembler linear "tergelincir" dan salah menyelaraskan batas instruksi (overlapping instructions). Khas hanya pada CISC.
- **Fat / universal binary** — Mach-O universal (atau bundel multi-arch) memuat beberapa slice; menganalisis slice yang salah membuang waktu. Pisahkan dengan `lipo -thin`.
- **Arsitektur tak lazim / dipacking untuk target asing** — sampel dikompilasi untuk MIPS/ARM eksotis agar analis yang hanya siap x86_64 tersendat.

**Pitfall analis (kesalahan yang membuat flag terlewat):**

- **Lupa set endianness/bit.** Memuat MIPS BE sebagai LE (atau ARM 32 sebagai 64) menghasilkan disassembly omong kosong. Selalu konfirmasi `Data:` di `readelf -h` lebih dulu.
- **Mengabaikan delay slot MIPS.** Urutan eksekusi yang Anda kira salah; nilai argumen di `$a0` bisa di-set justru di delay slot.
- **Bingung mode ARM/Thumb.** Lupa bahwa LSB alamat=1 berarti Thumb; fungsi terbaca rusak. Set mode eksplisit di disassembler.
- **Membaca argumen dengan convention salah.** Memperlakukan ARM64/MIPS seperti x86 (mencari arg di stack) padahal ada di `x0–x7` / `$a0–$a3`. Di Windows, lupa shadow space → salah hitung offset stack.
- **Menjalankan biner asing tanpa sysroot.** `qemu-user` butuh `-L <lib path>`; tanpa itu binary dinamis gagal load dan Anda salah menyimpulkan "binary rusak".
- **Salah varian qemu.** `qemu-mips` (BE) vs `qemu-mipsel` (LE) — pilih sesuai endianness, kalau tidak proses langsung crash.

## Mini-Lab

**Skenario:** Diberikan `fw_check` hasil ekstraksi firmware router. Biner memverifikasi sebuah serial/password dan mencetak flag bila benar. Arsitektur belum diketahui.

1. **Lakukan:** `binwalk -e firmware.bin` (bila masih berupa image), lalu `file fw_check` dan `readelf -h fw_check` → **dapatkan** arsitektur, bit, dan endianness (mis. *MIPS32, big-endian*).
2. **Lakukan:** muat di Ghidra dengan Language ID yang sesuai (`MIPS:BE:32:default`) atau `r2 -a mips -b 32` + `e cfg.bigendian=true` → **dapatkan** dekompilasi fungsi `main`/`check`, dengan memperhatikan **delay slot** di tiap branch.
3. **Lakukan:** jalankan dinamis: `qemu-mips -L /usr/mips-linux-gnu -g 1234 ./fw_check` lalu `gdb-multiarch` (`set architecture mips`, `set endian big`, `target remote :1234`) → **dapatkan** nilai register `$a0/$v0` saat fungsi pembanding dipanggil.
4. **Dapatkan:** rekonstruksi algoritma cek (atau set breakpoint dan patch hasil perbandingan) untuk memperoleh input yang benar dan **`flag{...}`**; dokumentasikan arsitektur → tool → langkah sebagai POC.

## Referensi & Latihan

- **MIPS Run / MIPS Architecture Reference** dan **ARM Architecture Reference Manual (ARMv7-A, ARMv8-A)** — rujukan kanonik register, encoding, dan calling convention.
- **System V AMD64 ABI** dan **Microsoft x64 calling convention** — perbedaan SysV vs MS x64 (shadow space, red zone).
- **Ghidra docs** (daftar processor/SLEIGH) & **radare2/rizin book** — memuat biner dengan arsitektur yang tepat.
- **crackmes.one** — filter berdasarkan arsitektur (ARM/MIPS) untuk latihan lintas-arch.
- **CyberDefenders** & **Blue Team Labs Online (BTLO)** — challenge analisis firmware/malware embedded (sering MIPS/ARM).
- **HackTheBox Sherlocks** & **HTB RE challenges** — investigasi DFIR/RE termasuk biner non-x86.
- **SANS FOR710 / malware analysis posters** — referensi cepat arsitektur & ABI saat lomba.

> **Etika:** Materi ini hanya untuk lab pribadi, lingkungan kompetisi (CTF), atau biner dengan **izin tertulis eksplisit**. Mengidentifikasi dan menganalisis arsitektur dipakai untuk belajar membongkar tantangan, menganalisis sampel di lab, dan menguji program milik sendiri — **bukan** untuk merekayasa balik perangkat lunak orang lain tanpa izin.
