# 4. Anti RE

> Anti-RE adalah kumpulan teknik yang sengaja dipasang pembuat program agar **proses reverse engineering jadi sulit, lambat, atau menyesatkan** — bukan untuk mengubah fungsi program, melainkan untuk menghalangi analis memahaminya. Di CTF LKSN 2026 (Modul C — Reverse Engineering), soal berproteksi anti-RE biasanya berupa binari (ELF/PE) yang "menolak" di-debug, atau yang disassembly/decompile-nya tampak kacau, sehingga peserta harus **mengenali jebakan**, **menetralkannya**, lalu baru memulihkan logika asli untuk mendapatkan flag. Tiga keluarga yang wajib dikuasai sesuai kisi-kisi: **Anti-Debug (PTRACE)**, **Anti-Disassembly**, dan **Anti-Decompiler**.

## Konsep

Anti-RE bekerja di tiga lapis analisis yang berbeda, dan penting membedakannya karena cara menetralkannya berbeda:

- **Anti-Debug** menyerang **analisis dinamis** — mendeteksi atau menggagalkan debugger (`gdb`, `x64dbg`) saat program berjalan. Di Linux, senjata utamanya adalah syscall `ptrace`. Begitu terdeteksi, program biasanya keluar diam-diam, mengubah jalur eksekusi, atau mencetak flag palsu.
- **Anti-Disassembly** menyerang **analisis statis tingkat instruksi** — menyisipkan byte sampah / instruksi yang tumpang-tindih sehingga disassembler salah menerjemahkan byte mentah menjadi instruksi yang keliru, lalu **desync** (tergeser) dari aliran kode asli.
- **Anti-Decompiler** menyerang **rekonstruksi tingkat tinggi** — mengganggu analisis stack frame, batas fungsi, atau calling convention sehingga decompiler (Hex-Rays, Ghidra) menghasilkan pseudo-C yang salah, putus, penuh `goto`, atau bahkan gagal/crash.

Sebagai modul defensif, ketiganya adalah keterampilan inti analis malware: sampel nyata hampir selalu memakai kombinasi ini untuk menghambat triase. Memahaminya bukan hanya untuk "membuka" binari lomba, tapi untuk mengenali pola yang sama pada malware sungguhan.

## Cara Kerja

**Anti-Debug via PTRACE.** Di Linux, sebuah proses hanya boleh punya **satu tracer** pada satu waktu. Trik klasik: program memanggil `ptrace(PTRACE_TRACEME, 0, 0, 0)` pada dirinya sendiri di awal `main`/konstruktor. Jika tidak ada debugger, panggilan ini berhasil (return `0`). Jika program sudah dijalankan di bawah `gdb` (yang sudah menjadi tracer), panggilan kedua ini **gagal** (return `-1`, `errno = EPERM`) — dan dari sini program tahu sedang di-debug. Varian lain: membaca field `TracerPid` di `/proc/self/status` (non-nol = ada tracer), cek `getppid()` (parent adalah debugger), pengukuran waktu via `rdtsc`/`cpuid` (eksekusi melambat drastis di bawah debugger), atau memasang handler `SIGTRAP` lalu menjalankan `int3` (0xCC) — bila debugger "menelan" trap, handler tak terpanggil. Di Windows padanannya: `IsDebuggerPresent()`, flag `BeingDebugged` di PEB, `NtQueryInformationProcess(ProcessDebugPort)`, dan `NtGlobalFlag`.

**Anti-Disassembly via overlapping instruction.** Ada dua mazhab disassembler: **linear sweep** (`objdump`) yang menerjemahkan byte berurutan dari awal sampai akhir, dan **recursive descent / flow-oriented** (IDA, Ghidra, Binary Ninja) yang mengikuti aliran kontrol (cabang/`call`). Teknik klasik ini menipu **keduanya**: pasang `jz label` diikuti `jnz label` ke **target yang sama** — kombinasi ini secara efektif **lompatan tak bersyarat** (salah satu dari ZF=0/ZF=1 pasti benar). Tepat setelahnya disisipkan satu **byte sampah `0xE8`** (opcode `call rel32`, panjang 5 byte). CPU tak pernah mengeksekusi byte itu karena selalu melompat ke `label`. Linear sweep jelas tertipu; **recursive descent pun ikut tersesat** karena ia tetap menelusuri jalur *fall-through* setelah `jnz` dan mulai men-decode dari `0xE8`, menerjemahkannya sebagai `call` lima byte sehingga **menelan** awal instruksi asli dan desync. Inilah sebabnya teknik ini jadi contoh kanonik anti-disassembly: IDA/Ghidra tidak otomatis kebal.

**Anti-Decompiler via stack/flow manipulation.** Decompiler perlu memulihkan stack frame, batas fungsi, dan calling convention. Penyerang merusak asumsi ini: `sub rsp, <nilai aneh>` palsu, manipulasi `rbp`, `call` yang tak pernah `ret` (dipakai sebagai `push` alamat), control-flow flattening, indirect jump lewat tabel, atau "decompiler bomb" yang membuat output meledak/crash. Hasilnya: variabel bayangan, argumen salah, dan pseudo-C yang tidak merepresentasikan logika sebenarnya.

## Indikator / Cara Mengenali

Tanda bahwa sebuah binari memasang proteksi anti-RE:

- **Impor mencurigakan**: `ptrace` (Linux); `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `NtQueryInformationProcess` (Windows) — lihat dengan `rabin2 -i` / IDA Imports.
- **String pemberi sinyal**: `/proc/self/status`, `TracerPid`, `"debugger detected"`, `"ptrace"`, `"Nope"`/`"gdb"`.
- **Instruksi timing**: `rdtsc`/`cpuid` berpasangan, atau pembacaan `clock_gettime` mengapit satu blok kecil.
- **`int3` (0xCC) tersebar** di tengah kode, atau handler `SIGTRAP` terpasang.
- **`objdump` menampilkan `(bad)`**, `call`/`jmp` ke alamat ganjil di tengah fungsi, atau aliran yang "putus" tiba-tiba → indikasi byte sampah anti-disasm.
- **Beda hasil linear-sweep vs recursive-descent**: bila `objdump -d` dan IDA menunjukkan instruksi yang berbeda di alamat sama, salah satunya tertipu — sinyal kuat overlapping instruction.
- **Decompiler "menyerah"**: fungsi tak dikenali, banyak region `undefined`, pseudo-C penuh `goto`, atau Ghidra/Hex-Rays gagal/lambat luar biasa di satu fungsi.

## Langkah Analisis/Investigasi

1. **Triage statis** — `file`, `strings`, `rabin2 -i`/Imports untuk memetakan indikator anti-debug/anti-disasm sebelum menjalankan apa pun.
2. **Klasifikasikan proteksi** — tentukan apakah yang dihadapi anti-debug (runtime), anti-disassembly (statis), atau anti-decompiler — karena penanganannya berbeda.
3. **Konfirmasi dinamis dengan aman** — jalankan di **VM terisolasi** (snapshot dulu); pakai `strace -e trace=ptrace` / `ltrace` untuk memastikan panggilan `ptrace`/anti-debug tanpa men-debug penuh.
4. **Netralkan anti-debug** — paksa `ptrace` selalu "berhasil" lewat `gdb` (`catch syscall ptrace` → set return 0), `LD_PRELOAD` stub, atau patch byte (NOP call / balik cabang).
5. **Resync anti-disassembly** — di IDA: `U` (undefine) byte salah lalu `C` (code) pada offset benar; di Ghidra: *Clear Code Bytes* lalu *Disassemble*; atau patch byte sampah `0xE8` → `0x90` (NOP).
6. **Perbaiki anti-decompiler** — koreksi batas fungsi (*Create Function*), *Edit Function Signature*/calling convention, dan *Edit Stack Frame*; bila tetap menyesatkan, **baca disassembly langsung** sebagai sumber kebenaran.
7. **Lanjut ke logika asli** — setelah proteksi netral, rekonstruksi algoritma validasi (mis. dengan `z3`) dan pulihkan input/flag.
8. **Dokumentasikan POC** — catat indikator → langkah bypass → flag sebagai bukti (Judgement).

## Tools

| Tool / Plugin | Fungsi singkat |
|---|---|
| `strace` / `ltrace` | Ungkap syscall `ptrace` & library call anti-debug saat runtime |
| `gdb` + `pwndbg` / `gef` | Debug, `catch syscall ptrace`, set register, patch in-memory |
| `LD_PRELOAD` stub | Override `ptrace()`/`getppid()` agar selalu kembalikan nilai aman |
| `radare2` / `rizin` | Disasm + patch (`wa`/`wx`), debug (`dr`,`db`,`dc`), tandai data (`Cd`) |
| `Ghidra` | Decompiler; *Clear Code Bytes*/*Disassemble*, *Patch Instruction*, *Edit Function Signature* |
| `IDA Pro` / Hex-Rays | Recursive descent; `U`/`C`/`D`, *Edit > Patch Program* |
| `Binary Ninja` | Disasm/decompiler multi-IL, bantu re-align kode ter-obfuscate |
| `objdump` | Linear sweep — acuan untuk *melihat* efek anti-disassembly (`(bad)`) |
| `frida` | Hook fungsi (`ptrace`, `IsDebuggerPresent`) secara runtime |
| `x64dbg` + `ScyllaHide` / `TitanHide` | Anti-anti-debug Windows (sembunyikan debugger dari PEB/Nt*) |
| `rabin2` / `patchelf` | Info & manipulasi struktur ELF (imports, header) |

## Contoh / Payload

**Triage: kenali proteksi tanpa menjalankan.**

```bash
file ./crackme
strings -a ./crackme | grep -iE 'ptrace|TracerPid|/proc/self/status|debugger'
rabin2 -i ./crackme | grep -i ptrace          # impor ptrace (radare2/rizin)
objdump -d -M intel ./crackme | grep -iE 'ptrace|rdtsc|int3|\(bad\)'
```

**Konfirmasi anti-debug PTRACE secara dinamis.**

```bash
strace -f -e trace=ptrace ./crackme
# ptrace(PTRACE_TRACEME, 0, NULL, NULL) = 0     <- jalan biasa: berhasil
# (di bawah gdb, panggilan ini = -1 EPERM -> program exit "debugger detected")
```

**Bypass A — gdb memaksa ptrace selalu "berhasil" (return 0).**

```gdb
gdb ./crackme
(gdb) catch syscall ptrace
(gdb) commands
 > set $rax = 0          # x86_64: $rax (gunakan $eax di x86)
 > continue
 > end
(gdb) run                # ptrace kini selalu kembalikan 0 -> deteksi gagal
```

**Bypass B — LD_PRELOAD stub `ptrace()` → 0 (hanya untuk inferior, bukan gdb).**

```bash
cat > noptrace.c <<'EOF'
#include <sys/ptrace.h>
long ptrace(int request, int pid, void *addr, void *data) { return 0; }
EOF
gcc -shared -fPIC noptrace.c -o noptrace.so

# Jalankan langsung:
LD_PRELOAD=./noptrace.so ./crackme
# Atau di dalam gdb agar preload hanya kena ke target:
#   (gdb) set exec-wrapper env LD_PRELOAD=./noptrace.so
#   (gdb) run
```

**Bypass C — patch byte: NOP-kan panggilan ptrace atau balik cabang deteksi (radare2 write mode).**

```bash
r2 -w ./crackme
[0x0000]> axt sym.imp.ptrace          # cari xref/call ke ptrace
[0x0000]> s <addr-call>
[0x0000]> wa nop;nop;nop;nop;nop      # NOP-kan call 5-byte
# atau balik cabang hasil deteksi: je -> jmp, atau jne -> nop
[0x0000]> s <addr-cabang>
[0x0000]> wx 9090                     # tulis byte langsung bila perlu
```

**Anti-Disassembly — lihat linear sweep tertipu, lalu re-align.**

Pola sumber yang menyesatkan `objdump`:

```nasm
    jz   real          ; jz + jnz ke target sama = lompatan tak bersyarat
    jnz  real
    .byte 0xE8         ; byte sampah: opcode CALL rel32 (5 byte) -> desync (linear sweep & recursive descent)
real:
    <instruksi asli>   ; CPU selalu mendarat di sini; 0xE8 tak pernah dieksekusi
```

```bash
# objdump (linear sweep) salah baca jadi "call <alamat aneh>":
objdump -d -M intel ./obf | sed -n '/<check>:/,+10p'

# radare2: tandai byte sampah sebagai data agar disasm resync
r2 -A ./obf
[0x0000]> s <addr-byte-sampah>
[0x0000]> Cd 1                 # define 1 byte sebagai data, lewati junk
# atau patch jadi NOP:  r2 -w ./obf ; s <addr> ; wx 90
# di Ghidra: pilih byte sampah -> 'C' (Clear Code Bytes) -> 'D' (Disassemble) di offset benar
```

**Anti-Decompiler — perbaiki agar pseudo-C masuk akal.** Bila Ghidra/Hex-Rays menghasilkan kode putus: gunakan *Edit Function Signature* untuk membetulkan calling convention, *Edit Stack Frame* untuk merapikan variabel lokal, atau *Create Function* pada batas yang benar; bila tetap menyesatkan, jadikan **disassembly sebagai sumber kebenaran** dan rekonstruksi manual.

## Anti-Forensik & Pitfall

**Teknik evasion penyerang (mempersulit analis):**

- **Anti-debug berlapis** — bukan hanya satu `ptrace`, tapi gabungan `TracerPid`, `getppid`, timing `rdtsc`, dan `int3`/`SIGTRAP`. Mem-bypass satu titik tak cukup; harus dipetakan semua.
- **Anti-debug tersamar (constructor / `IFUNC`)** — panggilan `ptrace` dipasang sebelum `main` (atribut `constructor` / `.init_array`) sehingga breakpoint di `main` sudah terlambat.
- **Eksekusi tetap jalan, tapi salah** — alih-alih exit, deteksi mengubah kunci dekripsi/cabang sehingga program tampak berjalan namun memproduksi **flag palsu** (jebakan paling licik).
- **Overlapping instruction & opaque predicate** — byte sampah, lompat ke tengah instruksi, atau predikat selalu-benar yang menyamarkan aliran asli dari recursive descent.
- **Anti-decompiler** — stack frame palsu, `call`/`pop` sebagai cara `push` alamat, control-flow flattening, hingga "decompiler bomb" yang membuat Ghidra/Hex-Rays meledak.

**Pitfall analis (kesalahan yang membuat flag terlewat):**

- **Men-debug sampel di host kerja** — sampel anti-debug sering juga jahat; selalu di **VM terisolasi, snapshot, jaringan host-only**.
- **`LD_PRELOAD` salah sasaran** — `LD_PRELOAD=... gdb ./bin` mem-preload ke *gdb*, bukan target. Gunakan `set exec-wrapper env LD_PRELOAD=...` atau jalankan binari langsung.
- **Patch terlalu kasar** — mem-NOP terlalu banyak byte atau salah membalik cabang justru mengubah logika asli; verifikasi panjang instruksi (call = 5 byte, `je` short = 2 byte).
- **Percaya buta pada satu disassembler** — byte sampah dapat menyesatkan `objdump` **maupun** IDA/Ghidra (recursive descent tetap menelusuri jalur *fall-through*). Pemulihan yang andal bukan sekadar berganti disassembler, melainkan *undefine → redefine* di offset benar atau patch byte sampah `0xE8` → `0x90`.
- **Percaya buta pada decompiler** — pseudo-C dari fungsi anti-decompiler bisa **salah total**; saat ragu, baca disassembly.
- **Lupa konstruktor `.init_array`** — proteksi yang jalan sebelum `main` terlewat bila hanya memasang breakpoint di `main`.

## Mini-Lab

**Skenario:** Diberikan `crackme` (Linux x86_64). Program memanggil `ptrace(PTRACE_TRACEME)` di awal; bila di-debug ia mencetak `Nope` dan keluar. Rutin validasi flag disembunyikan dengan `jz/jnz` ke target sama + byte sampah `0xE8` agar `objdump` tersesat.

1. **Lakukan:** `strace -e trace=ptrace ./crackme` → **Dapatkan:** konfirmasi `PTRACE_TRACEME` sebagai mekanisme anti-debug.
2. **Lakukan:** `gdb` dengan `catch syscall ptrace` lalu `set $rax = 0` (atau `LD_PRELOAD` stub) → **Dapatkan:** sesi debug yang lolos cek anti-debug (program tak lagi mencetak `Nope`).
3. **Lakukan:** di Ghidra/IDA temukan pasangan `jz/jnz` ke target sama + byte `0xE8`; *Clear Code Bytes* → *Disassemble* di offset benar (atau patch `0xE8` → `0x90`) → **Dapatkan:** rutin validasi yang ter-disassemble dengan benar.
4. **Dapatkan:** baca/rekonstruksi pengecekan (bila perlu pakai `z3`) untuk memperoleh input yang benar → **`flag{...}`**; tulis timeline indikator → bypass → flag sebagai POC.

## Referensi & Latihan

- **Practical Malware Analysis** (Sikorski & Honig) — bab *Anti-Disassembly*, *Anti-Debugging*, *Anti-VM*: referensi kanonik (sumber pola `jz/jnz` + `0xE8`).
- **Peter Ferrie — "The Ultimate Anti-Debugging Reference"** — katalog lengkap trik anti-debug Windows.
- **CTF Wiki — Detect Debugging / Anti-Debug (Linux)** (`ctf-wiki.mahaloz.re`) — `ptrace`, `TracerPid`, timing, beserta bypass.
- **yellowbyte/reverse-engineering-reference-manual** (GitHub) — bagian *anti-analysis* (Anti-Debugging, Anti-Disassembly) ringkas & praktis.
- **Ghidra — "Improving Disassembly and Decompilation"** (`ghidra.re` GhidraClass/Advanced) — memperbaiki fungsi, stack frame, dan kode ter-obfuscate.
- **Latihan:** **crackmes.one** (tag *anti-debug*), **pwn.college** (Reverse Engineering), **HackTheBox** Reversing & Challenges, **picoCTF** kategori Reverse Engineering, **CyberDefenders** & **BlueTeam Labs Online** (BTLO) untuk konteks analisis malware, serta **HackTheBox Sherlocks** untuk investigasi DFIR.

> Materi ini **hanya** untuk lab pribadi, VM terisolasi, lingkungan kompetisi, atau binari dengan **izin tertulis eksplisit**. Teknik menembus anti-RE di sini dipakai untuk belajar memecahkan tantangan CTF dan menganalisis sampel di lab — **bukan** untuk membongkar proteksi, membajak, atau merekayasa balik perangkat lunak orang lain tanpa izin.
