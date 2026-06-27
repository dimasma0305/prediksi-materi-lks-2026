# 2. Dynamic Analysis

> Dynamic analysis adalah menganalisis sebuah biner **saat ia berjalan** (runtime), kebalikan dari static analysis yang membaca kode tanpa mengeksekusinya. Alih-alih menebak dari disassembly, kita *mengamati* nilai register, isi memori, syscall yang dipanggil, dan string yang dibandingkan — pada saat program benar-benar hidup. Di CTF LKSN 2026 (Modul C — Reverse Engineering), teknik ini wajib ketika kode di-*unpack*/decrypt runtime, kunci dihitung saat eksekusi, atau static buntu karena obfuscation. Dua pilarnya: **Tracing** (`strace`/`ltrace`/`frida-trace` — mengintip panggilan keluar tanpa kontrol mendalam) dan **Debugging** (`GDB` + `pwndbg`/`GEF` — kontrol penuh: breakpoint, step, baca/ubah state). Sering kali satu panggilan `strcmp` yang ketahuan sudah membocorkan flag tanpa reverse penuh.

## Konsep

Static dan dynamic saling melengkapi, bukan saling menggantikan. Static memberi peta menyeluruh (semua cabang kode), tapi buta terhadap nilai konkret yang baru muncul saat runtime. Dynamic memberi *ground truth* satu jalur eksekusi: alamat aktual setelah ASLR, isi buffer setelah dekripsi, argumen nyata yang masuk ke fungsi pembanding.

Dynamic analysis menjadi pilihan utama saat:

- Biner **packed** (mis. UPX) atau men-decrypt/unpack kode ke memori baru saat berjalan — static hanya melihat *stub*.
- Kunci/checksum/flag **dihitung runtime** dari waktu, PID, atau input, sehingga tidak ada di string statis.
- Control flow di-obfuscate (flattening, opaque predicate) sehingga membaca disassembly tidak ekonomis.
- Cukup mencegat **satu titik perbandingan** input-vs-flag (`strcmp`/`memcmp`/cek custom) untuk membongkar jawaban.

Dua pendekatan utama. **Tracing** mencatat interaksi program dengan dunia luar — *syscall* (kernel) atau *library call* (libc/PLT) — pasif dan cepat. **Debugging** memberi kendali penuh: hentikan eksekusi di titik tertentu, baca/tulis register & memori, melangkah per-instruksi. Karena dynamic berarti **benar-benar menjalankan** sampel, semua dilakukan di **VM/sandbox terisolasi** (snapshot dulu) — terutama untuk malware.

## Cara Kerja

Di Linux, fondasi hampir semua debugger/tracer adalah syscall **`ptrace(2)`**. `gdb` dan `strace` memanggil `ptrace(PTRACE_TRACEME/PTRACE_ATTACH, PTRACE_PEEKTEXT, PTRACE_POKETEXT, ...)` untuk membaca/menulis memori dan register proses target. Konsekuensi penting: **hanya satu tracer** yang boleh meng-attach sebuah proses pada satu waktu — fakta inilah yang dieksploitasi anti-debug.

- **Software breakpoint** = debugger menambal satu byte di alamat target dengan opcode `int3` (`0xCC`). CPU mengeksekusinya → raise `SIGTRAP` → kernel kembalikan kendali ke debugger, yang memulihkan byte asli. Karena memodifikasi kode, breakpoint bisa **terdeteksi** lewat self-checksum.
- **Hardware breakpoint / watchpoint** memakai debug register `DR0–DR7` — tidak mengubah byte kode, jadi lebih sulit dideteksi dan dipakai `watch` untuk memantau perubahan memori.
- **`strace`** mencegat di batas user↔kernel: ia mencatat nomor syscall + argumen tiap kali program masuk kernel (`open`, `read`, `connect`, bahkan `ptrace`). 
- **`ltrace`** meng-hook **PLT/GOT** untuk mencatat panggilan ke fungsi library (mis. `strcmp`, `memcmp`, `strncmp`). Karena bergantung pada *dynamic linking*, ia **gagal** pada biner *statically-linked*, *stripped* internal call, atau fungsi yang di-*inline*.
- **`frida`** melakukan *dynamic instrumentation*: menyuntik engine JavaScript ke proses dan menulis *trampoline* di entry fungsi (`Interceptor.attach`) — lintas platform (Linux/Windows/Android/iOS).

Ide kunci CTF: argumen di fungsi pembanding adalah flag dalam bentuk *plaintext*. Mencegat `strcmp(input, flag)` membocorkan jawaban tanpa memahami algoritma sama sekali.

## Indikator / Cara Mengenali

Sinyal bahwa dynamic analysis adalah jalan tercepat, dan apa yang dicari:

- Program **meminta input** lalu mencetak `Correct`/`Wrong`/`Access denied` → set breakpoint dekat string itu (cross-reference dari Ghidra), lalu mundur ke fungsi pembanding.
- Ada **satu fungsi cek** (`strcmp`/`memcmp`/`==` custom) tepat sebelum percabangan sukses → cegat argumennya.
- Entropi tinggi / section `UPX0`,`UPX1` / banyak `mmap` + region **RWX** baru saat berjalan → kode di-unpack runtime, dump dari memori setelah unpack.
- String menarik **tidak ada** di output `strings` statis tapi muncul di memori runtime → di-decrypt saat eksekusi.

Tanda biner **memasang anti-debug** (perilaku berubah di bawah debugger):

- Program langsung `exit`/`SIGSEGV` atau mencetak "debugger detected" hanya saat di-`gdb`/`ltrace`.
- `strace` menampilkan panggilan `ptrace(PTRACE_TRACEME, ...)` di awal, atau pembacaan `/proc/self/status` (cek field `TracerPid`).
- Cek timing `rdtsc`/`clock_gettime` — selisih waktu melonjak saat *single-step* memicu cabang "terdeteksi".
- Program memasang **handler `SIGTRAP` sendiri** sehingga breakpoint "tertelan" tanpa menghentikan eksekusi.

## Langkah Analisis/Investigasi

1. **Siapkan lab terisolasi** — VM/sandbox, ambil *snapshot* sebelum menjalankan sampel asing.
2. **Recon statis singkat** — `file`, `rabin2 -I` / `checksec` untuk tahu arsitektur, PIE/NX/RELRO, *stripped*, dan dynamic vs static. Ini menentukan strategi (mis. `ltrace` percuma pada biner statis).
3. **Tracing dulu (murah)** — `ltrace` untuk library call (incar `strcmp`/`memcmp`); `strace` untuk syscall (akses file, jaringan, **dan** deteksi `ptrace` anti-debug). Flag sering langsung muncul di sini.
4. **Naik ke debugger** — muat di `gdb` + `pwndbg`/`GEF`, pasang breakpoint pada titik kunci (`b strcmp`, `b *main+0x...`, atau alamat XREF string), `run`, lalu inspeksi argumen (`x/s $rdi`, `x/s $rsi`).
5. **Manipulasi runtime** — lewati cek dengan mengubah state: `set $rax=0`, ubah `$eflags`/`$rip`, atau patch byte cabang. Berguna untuk melompati lisensi/anti-debug tanpa menyelesaikan algoritma.
6. **Netralkan anti-debug** — bila terdeteksi `ptrace`, paksa nilai baliknya 0 (`catch syscall ptrace`), `LD_PRELOAD` `ptrace` palsu, atau tambal panggilannya.
7. **Dump artefak runtime** — `dump memory unpacked.bin <start> <end>` untuk kode ter-unpack, kunci, atau string yang baru ter-decrypt.
8. **Korelasi dengan static** — bawa temuan runtime ke Ghidra/IDA, rekonstruksi algoritma, lalu tulis solver (lihat 01-static-analysis: `z3`) untuk memulihkan input yang sah.

## Tools

| Tool / Plugin | Fungsi singkat |
|---|---|
| `strace` | Trace syscall (`-f` ikut fork, `-e trace=...`, `-p` attach) |
| `ltrace` | Trace library/PLT call (`strcmp`/`memcmp`); `-S` ikut syscall |
| `gdb` | Debugger inti Linux: breakpoint, step, baca/ubah register & memori |
| `pwndbg` | Plugin GDB: `context`, `telescope`, `vmmap`, `heap`, `search` |
| **GEF** (`gdb-gef`) | Plugin GDB alternatif: `checksec`, `vmmap`, `pattern`, `heap` |
| `gdb-multiarch` / `gdbserver` | Debug remote & lintas arsitektur |
| **radare2** / **rizin** (`-d`) | Mode debug: `ood`, `db`, `dc`, `dr`, `px @ reg` |
| **frida** / `frida-trace` | Dynamic instrumentation lintas platform (hook `Interceptor`) |
| **x64dbg** | Debugger GUI untuk biner Windows (PE) |
| **WinDbg** (TTD) | Time Travel Debugging — rekam & mundurkan eksekusi (Windows) |
| `qemu-user` (`-g`) | gdbstub untuk emulasi & debug biner ARM/MIPS lintas arsitektur |
| `LD_PRELOAD` | Sisipkan/override fungsi libc (mis. `ptrace` palsu) tanpa patch |

## Contoh / Payload

**Recon + tracing (langkah pertama, paling murah):**

```bash
# 0) Kenali target: arsitektur, proteksi, dynamic/static, stripped
file ./crackme && rabin2 -I ./crackme        # atau: checksec --file=./crackme

# 1) ltrace mencegat perbandingan — flag sering bocor di sini
ltrace -e 'strcmp+strncmp+memcmp' ./crackme
# strcmp("h4ck3r" , "LKSN{tr4c3_th3_c0mp4r3}") = -1   <-- argumen ke-2 = flag

# 2) strace untuk syscall: akses file, jaringan, ATAU anti-debug
strace -f -e trace=ptrace,openat,connect ./crackme
# ptrace(PTRACE_TRACEME, 0, 0, 0) = -1 EPERM   <-- sudah ada tracer => anti-debug
```

**Sesi GDB: breakpoint di fungsi pembanding lalu baca argumen** (System V AMD64: arg1=`rdi`, arg2=`rsi`, return=`rax`):

```bash
gdb -q ./crackme
```
```gdb
b strcmp                  # atau: b *main+0x1f4  /  b *0xADDR dari XREF string
run                       # untuk PIE, gunakan 'starti' bila perlu break sebelum dipetakan
# saat berhenti di strcmp:
x/s $rdi                  # input kita
x/s $rsi                  # 0x... : "LKSN{...}"   <-- pembanding = flag
info registers rdi rsi rax
set $rax = 0              # paksa "cocok" untuk lewati cek tanpa tahu flag
continue
```

**Skrip GDB non-interaktif** (otomatis, untuk dijalankan cepat saat lomba):

```bash
gdb -q -batch \
  -ex 'b memcmp' -ex 'run' \
  -ex 'printf "len=%d\n", $rdx' \
  -ex 'x/s $rsi' -ex 'continue' ./crackme
```

**Bypass anti-debug `ptrace` — dua cara:**

```gdb
# Cara A (dalam gdb): paksa ptrace() selalu balik 0 saat ia return
catch syscall ptrace
commands
  set $rax = 0
  continue
end
run
```
```bash
# Cara B (LD_PRELOAD): ptrace palsu, lalu jalankan ulang ltrace/gdb
cat > fakeptrace.c <<'EOF'
long ptrace(int request, int pid, void *addr, void *data) { return 0; }
EOF
gcc -shared -fPIC fakeptrace.c -o fakeptrace.so
LD_PRELOAD=./fakeptrace.so ltrace -e 'strcmp' ./crackme
```

**Frida — hook lintas platform (bagus saat `ltrace` mentok / target Windows/Android):**

```bash
frida-trace -i 'strcmp' -f ./crackme      # auto-generate handler per fungsi
```
```javascript
// hook.js  ->  frida -l hook.js -f ./crackme
// Frida >= 17: cari export di semua modul dengan getGlobalExportByName()
Interceptor.attach(Module.getGlobalExportByName('strcmp'), {
  onEnter(args) {
    console.log('s1=' + args[0].readCString() + '  s2=' + args[1].readCString());
  }
});
// Frida <= 16 memakai bentuk lama: Module.getExportByName(null, 'strcmp')
```

**Lintas arsitektur (ARM/MIPS) via QEMU gdbstub:**

```bash
qemu-aarch64 -L /usr/aarch64-linux-gnu -g 1234 ./arm_bin   # terminal 1
gdb-multiarch -q ./arm_bin -ex 'target remote :1234'       # terminal 2
```

## Anti-Forensik & Pitfall

**Teknik anti-debug / anti-trace attacker** (mempersulit dynamic analysis):

- **`ptrace(PTRACE_TRACEME)` self-trace** — biner men-trace dirinya sendiri saat start; karena hanya satu tracer diizinkan, `gdb`/`strace` gagal attach. Lawan dengan `catch syscall ptrace`+`set $rax=0` atau `LD_PRELOAD`.
- **Cek `/proc/self/status` `TracerPid`** — non-nol berarti sedang di-debug. Patch cabangnya atau palsukan pembacaan.
- **Timing check (`rdtsc`/`clock_gettime`)** — *single-step* membuat selisih waktu melonjak → program menyimpang. Hindari step manual; pakai breakpoint langsung ke titik tujuan.
- **`int3`/`0xCC` scanning & self-checksum** — biner memeriksa apakah kodenya ditambal breakpoint. Gunakan **hardware breakpoint** (`hbreak`/debug register) yang tak mengubah byte.
- **SIGTRAP handler hijack** — program memasang handler `SIGTRAP` sendiri sehingga breakpoint "tertelan". Sadari ini saat breakpoint tidak pernah berhenti.
- **Anti-`ltrace`**: static linking, perbandingan *inline*/internal (tanpa PLT), atau implementasi `strcmp` sendiri → tidak ada panggilan library untuk di-hook. Beralih ke `gdb`/`frida`.
- **Anti-`frida`**: scan `/proc/self/maps` mencari `frida-agent`, deteksi named pipe, atau cek port default Frida.

**Pitfall analis** (membuat flag terlewat / lab berbahaya):

- **Menjalankan malware di host asli** tanpa VM/snapshot. Selalu isolasi.
- **Mengandalkan `ltrace` pada biner statis/stripped** → output kosong dan disangka "tidak ada perbandingan". Konfirmasi linking dengan `file` lebih dulu.
- **Lupa ASLR/PIE** — alamat berubah tiap run; jangan hardcode alamat absolut, break by symbol atau pakai offset relatif terhadap base (`vmmap` untuk base PIE).
- **Salah ABI register** — System V (Linux): `rdi,rsi,rdx,rcx,r8,r9`; Windows x64: `rcx,rdx,r8,r9`. Membaca register yang salah = argumen salah.
- **`run < input` & buffering stdin** — interaksi tak sinkron membuat breakpoint seperti "terlewat". Siapkan input lewat file/`pipe`.
- **Single-step memicu anti-debug timing** — gunakan `continue` ke breakpoint, bukan `si`/`ni` beruntun, pada biner berproteksi.
- **Hanya percaya satu jalur eksekusi** — dynamic membuktikan *satu* input; korelasikan dengan static agar tak salah generalisasi.

## Mini-Lab

**Skenario:** Diberikan `crackme01` (ELF x86-64, PIE, *dynamically linked*). Program meminta password, mencetak `Correct!`/`Nope`, dan memasang anti-debug `ptrace(PTRACE_TRACEME)` sehingga `gdb`/`ltrace` polos gagal.

1. **Lakukan:** `file ./crackme01` lalu `strace -e trace=ptrace ./crackme01` → **dapatkan** konfirmasi `ptrace(PTRACE_TRACEME, ...) = -1` (anti-debug aktif).
2. **Lakukan:** netralkan dengan `LD_PRELOAD=./fakeptrace.so ltrace -e 'strcmp+memcmp' ./crackme01` → **dapatkan** argumen fungsi pembanding (kemungkinan flag langsung terbaca).
3. **Lakukan:** bila pembanding *custom* (bukan libc), buka `gdb`, `b *main+<offset_XREF_"Correct!">`, `run`, `x/s $rsi` → **dapatkan** string flag di register/memori.
4. **Dapatkan:** verifikasi dengan menjalankan ulang dan memasukkan password yang ditemukan hingga muncul `Correct!` → catat flag **`LKSN{...}`** beserta langkah (trace → bypass anti-debug → cegat compare) sebagai POC.

## Referensi & Latihan

- **pwndbg** (`pwndbg.re`) & **GEF** (`hugsy.github.io/gef`) — dokumentasi command, cheat sheet `context`/`vmmap`/`telescope`.
- **Frida** (`frida.re/docs`) & **learnfrida.info** — JavaScript API, `Interceptor.attach`, `frida-trace`.
- **GDB manual** & *GDB to RADARE2 cheat sheet* — perintah breakpoint, watchpoint, `catch syscall`.
- **crackmes.one** — ribuan crackme bertingkat untuk latihan tracing & debugging.
- **pwn.college** (*Reverse Engineering*) & **Nightmare** (guyinatuxedo) — kursus & writeup RE/pwn berbasis `gdb`.
- **Flare-On Challenge** (Mandiant) — seri RE tahunan dengan banyak anti-debug nyata.
- **HackTheBox** (Reversing) & **HTB Sherlocks** — tantangan RE dan investigasi DFIR.
- **CyberDefenders** & **BlueTeam Labs Online (BTLO)** — lab blue-team termasuk analisis sampel.
- **SANS FOR610** (*Reverse-Engineering Malware*) — referensi metodologi dynamic analysis di sandbox.

> Materi ini **hanya** untuk lab pribadi, lingkungan kompetisi (CTF), atau biner dengan **izin tertulis eksplisit**. Menjalankan & men-debug sampel dilakukan di **VM/sandbox terisolasi**; teknik di sini untuk belajar memecahkan tantangan dan menganalisis sampel di lab — **bukan** untuk membongkar proteksi atau merekayasa balik perangkat lunak orang lain tanpa izin.
