# 5. Compiled Language Syntax in Executable

> Setiap bahasa terkompilasi meninggalkan "sidik jari" khas di dalam executable: cara kompiler menamai simbol, menyusun string, memetakan section, memanggil fungsi, dan memuat runtime-nya sendiri. Di CTF LKSN 2026 (Modul C — Reverse Engineering), soal kategori ini memberi sebuah biner native (ELF/PE) — sering **stripped** — dan menuntut peserta lebih dulu **mengenali bahasa sumbernya** (C, C++, Golang, Rust, …) sebelum membongkar logikanya. Salah menebak bahasa = salah strategi = timebox habis. Tujuan akhir tetap: temukan *user code* lalu **dapatkan flag**.

## Konsep

Disassembly mentah dari biner mana pun "hanya" instruksi mesin, tapi kompiler tiap bahasa menanam pola yang konsisten dan dapat dikenali. Mengenali bahasa lebih dulu menghemat waktu karena tiap bahasa menuntut pendekatan berbeda:

- **C** — runtime tipis, hampir pemetaan langsung ke libc; biner kecil, mudah dibaca di decompiler. Logika flag biasanya gamblang.
- **C++** — simbol **ter-mangle**, ada **vtable**/RTTI dan **exception**, plus template STL yang membengkak. Butuh demangling untuk membaca alur OOP.
- **Golang** — biner **besar & statis** dengan runtime + scheduler sendiri; nama fungsi **tetap terbaca lewat `.gopclntab`** walau di-strip. String tersimpan tanpa null-terminator.
- **Rust** — statis, ber-LLVM, simbol ter-mangle, dan **pesan `panic!` membocorkan path source** serta nama crate. Banyak monomorphization.

Kesalahan klasik peserta adalah memperlakukan biner Go/Rust seperti biner C kecil, lalu tenggelam di ribuan fungsi runtime/stdlib. Mengenali bahasa = memilih peta yang benar.

## Cara Kerja

Mekanisme bagaimana tiap kompiler membentuk biner:

- **C** — `_start` memanggil `__libc_start_main` lalu `main`. Hampir tidak ada runtime tambahan; proteksi umum hanya stack canary (`__stack_chk_fail`) dan import libc (`printf`, `strcmp`, `malloc`). Dinamis-link adalah default (`.interp`, PLT/GOT).
- **C++** — **name mangling** Itanium ABI (GCC/Clang) berawalan `_Z` (mis. `_ZN3foo3barEv` → `foo::bar()`), sedangkan MSVC memakai skema `?bar@foo@@...`. Tanda lain: vtable `_ZTV`, RTTI `_ZTI`/`_ZTS`, exception `__cxa_throw`/`__cxa_begin_catch` + landing pad, `operator new`/`operator delete`, dan template STL (`std::string`, `std::vector`) yang ter-inline berulang.
- **Golang** — punya runtime sendiri (scheduler goroutine `runtime.morestack`, `runtime.schedule`, GC, `main.main` dipanggil dari `runtime.main`). **Statically linked** default. Tabel **`.gopclntab`** memetakan PC→nama fungsi dan **bertahan walau biner di-strip** (`-ldflags="-s -w"` hanya membuang DWARF/symtab). **String Go = struct `{ptr,len}`**, tidak null-terminated, sehingga datanya tersimpan sebagai satu blob raksasa yang menyambung. Calling convention berbasis **stack sebelum Go 1.17**, berbasis **register (ABIInternal)** sejak Go 1.17 di amd64. Blok **`buildinfo`** (magic `\xff Go buildinf:`) menyimpan versi Go + daftar modul.
- **Rust** — di atas LLVM, **monomorphization** generic, statically linked (glibc/musl). **Mangling default di stable masih skema *legacy*** mirip Itanium: `_ZN...17h<16-hex-hash>E`; skema **v0** (`_R...`) bersifat **opt-in** (`-C symbol-mangling-version=v0`) dan baru dijadikan default di *nightly*. Penanda kuat: pesan `panicked at src/main.rs:L:C` (format Rust ≥1.73; versi lama: `panicked at 'pesan', src/main.rs:L:C` — path selalu di luar tanda kutip), path `/rustc/<hash>/library/...` dan `.cargo/registry/...`, simbol `rust_begin_unwind` / `rust_eh_personality`, serta jalur `core::`, `alloc::`, `std::`.

**Catatan PE/Windows.** Sidik jari di atas tetap berlaku pada target Windows, tapi entry point berbeda: biner **MSVC** C/C++ mulai dari `mainCRTStartup`/`wmainCRTStartup` (CRT MSVCRT/UCRT) dengan mangling `?...@@`, sedangkan **MinGW/GCC** memakai mangling Itanium `_Z` seperti di Linux. Biner **Go** dan **Rust** untuk Windows tetap membawa `.gopclntab`/buildinfo dan simbol `_ZN..17h..E`/path `.cargo` — jadi identifikasi bahasa tidak bergantung pada OS, hanya cara baca entry point dan demangler-nya yang menyesuaikan.

## Indikator / Cara Mengenali

Sidik jari per-bahasa — inti halaman ini. Cocokkan minimal dua kolom sebelum menyimpulkan:

| Bahasa | Mangling / simbol | Section & struktur khas | String & runtime | Linking & ukuran |
|---|---|---|---|---|
| **C** | Tak ter-mangle; nama polos (`main`, `check`) | `.interp`, PLT/GOT ke libc | String null-terminated; `__libc_start_main` | Dinamis (umum); biner kecil (puluhan KB) |
| **C++** | `_Z...` (Itanium) / `?...@@` (MSVC) | vtable `_ZTV`, RTTI `_ZTI`/`_ZTS`, `.eh_frame` | `std::string`, `__cxa_throw`, `operator new` | Dinamis/statis; sedang, membengkak oleh template |
| **Golang** | Nama lengkap `pkg.Func`, `main.main`, `runtime.*` | **`.gopclntab`**, `.go.buildinfo`, `.typelink`, `.itablink` | String **run-on** tanpa null; scheduler goroutine, GC | **Statis**; besar (beberapa MB) |
| **Rust** | `_ZN..17h<hash>E` (legacy/default) atau `_R...` (v0) | `.eh_frame`, banyak monomorphization | `panicked at`, path `src/..`/`.cargo`, `core::`/`alloc::` | **Statis**; besar; `rust_eh_personality` |

Catatan cepat:

- Biner **besar + statis + `.gopclntab`** hampir pasti **Go**; jalankan `go version -m` untuk konfirmasi versi & modul.
- Simbol `_ZN…17h…E` dengan **hash 16-hex** = **Rust legacy**, bukan C++ biasa (skema ini sengaja Itanium-compatible, jadi `c++filt` ikut mendemangle tapi **menyisakan `::h<hash>`**; `rustfilt` membersihkan hash itu).
- Banyak `__cxa_*` + vtable = **C++**; tanpa itu dan tipis = **C**.
- **Detect It Easy (DiE)** dan signature kompiler (`rustc`, `gc: go1.xx`) sering langsung menjawab — tapi verifikasi silang, packer bisa memalsukan.

## Langkah Analisis/Investigasi

Alur triase identifikasi → lokalisasi user code:

1. **Tebakan kasar.** `file ./chall` dan **Detect It Easy** (`diec ./chall`) untuk indikasi tipe, bitness, kompiler, dan apakah ter-pack.
2. **Periksa section & header.** `readelf -hS ./chall` — adanya `.gopclntab`/`.go.buildinfo` = Go; `.interp` = dinamis (cenderung C/C++); tak ada `.interp` + besar = statis (Go/Rust).
3. **Lihat simbol & string.** `nm ./chall` dan `strings -a ./chall` — pola mangling (`_Z`, `_ZN..17h..E`, `_R`), pesan panic Rust, blob string Go.
4. **Bercabang per bahasa** sesuai temuan langkah 2–3.
5. **Demangle.** `c++filt` (Itanium), `undname.exe` (MSVC), `rustfilt` (Rust) agar nama fungsi terbaca.
6. **Lokalisasi *user code*.** Filter runtime/stdlib: di Go fokus ke `main.*` (dan paket non-`runtime`/`internal`), di Rust ke modul crate sendiri (bukan `core::`/`alloc::`/`std::`), di C/C++ mulai dari `main`. Ini langkah penyelamat timebox.
7. **Pulihkan metadata (khusus Go).** Jalankan **GoReSym** dan/atau muat analyzer Go di **Ghidra (10.3+)** untuk mengembalikan nama fungsi + tipe, lalu masuk ke logika flag.

## Tools

| Tool / Plugin | Fungsi singkat |
|---|---|
| `file` / **Detect It Easy** (`diec`) | Identifikasi tipe biner, kompiler, packer |
| `readelf` / `objdump` | Inspeksi section, header, simbol (ELF) |
| `nm` / `strings` | Daftar simbol & string mentah (deteksi mangling/panic) |
| **Ghidra** (10.3+ Go analyzer) | Decompiler utama; analyzer Golang memulihkan nama dari pclntab |
| **IDA Pro/Free** + `golang_loader_assist` | Disassembler/decompiler; plugin pemulih nama fungsi Go |
| **radare2 / rizin (+ Cutter)** | Analisis & demangling C++/Rust/Go (`aaa`, `is`, GUI Cutter) |
| **Binary Ninja** | Decompiler alternatif dengan ILs |
| `c++filt` / `undname.exe` | Demangle simbol C++ Itanium / MSVC |
| `rustfilt` (`rust-demangle`) | Demangle simbol Rust legacy & v0 |
| **GoReSym** (Mandiant/Google FLARE) | Pulihkan nama fungsi, tipe, buildinfo Go (juga dari biner stripped) |
| `go version -m` | Baca versi Go + modul/dependency dari biner |
| **redress** / `gore` | Analisis biner Go (paket, tipe, sumber) |

## Contoh / Payload

**Identifikasi & demangle lintas bahasa:**

```bash
# 1) Tebakan cepat: tipe, kompiler, packer
file ./chall
diec ./chall                                   # Detect It Easy (CLI)
readelf -hS ./chall | grep -E 'gopclntab|buildinfo|interp'

# 2) C++ : demangle simbol Itanium (GCC/Clang)
nm -C ./chall | head                           # -C = auto-demangle
echo '_ZN3foo3barEv' | c++filt                 # -> foo::bar()
#   MSVC (Windows): undname "?bar@foo@@QAEHXZ"

# 3) Rust : simbol legacy _ZN..17h<hash>E (default di stable)
nm ./chall | grep -E '_ZN.*17h[0-9a-f]{16}E' | rustfilt
strings -a ./chall | grep -E 'panicked at|src/main\.rs|\.cargo/registry'
#   simbol v0 (opt-in) berawalan _R... -> juga via rustfilt

# 4) Golang : pclntab tetap simpan nama walau di-strip (-s -w)
strings -a ./chall | grep -F 'Go buildinf:'    # tanda biner Go
go version -m ./chall                           # versi Go + modul/deps
GoReSym -t ./chall > meta.json                  # pulihkan fungsi, tipe, buildinfo
nm ./chall | grep -E '^.* main\.' | head        # fokus ke paket main (user code)
```

**Melacak user code lewat panic (Rust):** pesan `panic!` membawa path source asli, jadi xref-nya menunjuk langsung ke fungsi milik crate — pintasan ampuh menembus tumpukan `core::`/`alloc::`.

```bash
# Petakan string panic -> fungsi yang merujuknya (lokasi user code Rust)
rz-bin -z ./chall | grep -iE 'panicked|main\.rs|unwrap'   # rizin: daftar string+alamat
# lalu di rizin/r2: 'axt @ <addr_string>' untuk lihat siapa yang merujuk

# Inspeksi dependency Go (modul pihak ketiga sering memberi petunjuk algoritma)
go version -m ./chall | grep -E 'dep|mod'      # mis. golang.org/x/crypto -> rutin kripto
```

**Catatan string Go.** Karena string Go tidak null-terminated, `strings` memunculkan blob menyambung — flag bisa "menempel" pada string lain. Saat menemukan kandidat, periksa **panjangnya** di cross-reference (struct `{ptr,len}`), bukan sampai byte `\0`.

**Di Ghidra (Go).** Pastikan *Golang* analyzer aktif (Auto Analysis), lalu di Symbol Tree cari `main.main` sebagai titik masuk logika user; abaikan ribuan fungsi `runtime.*`.

## Anti-Forensik & Pitfall

**Teknik attacker (mempersulit identifikasi/RE):**

- **Symbol stripping** (`strip`, `-s -w`) — membuang DWARF/symtab. **Tapi pada Go, `.gopclntab` tetap menyimpan nama fungsi** → pulihkan dengan **GoReSym**/analyzer Ghidra. "Stripped" bukan berarti hilang.
- **Static linking** — user code terkubur di antara ribuan fungsi libc/runtime. Pisahkan dengan signature pustaka (FLIRT/Lumina di IDA, signature rizin) dan filter ke `main.*`/modul crate.
- **garble** (Go) — obfuscator sejati: meng-hash nama paket/fungsi (SHA-256→base64) sehingga `.gopclntab` **tetap ada tapi nama di dalamnya tak terbaca** (bukan dihapus), mengosongkan buildinfo/VCS info (`debug.ReadBuildInfo` jadi kosong), dan—dengan opsi `-literals`—mengenkripsi literal/string. Justru karena tabelnya tidak hilang melainkan namanya diaburkan, lawan dengan **GoResolver (Volexity)** yang memakai kemiripan control-flow graph untuk memetakan ulang fungsi ke stdlib.
- **Packer** (UPX/kustom) — biner Go/Rust besar sering di-UPX; `upx -d` untuk yang standar, dump-from-memory untuk packer kustom sebelum analisis.
- **Mangling v0 / monomorphization Rust** — ledakan jumlah simbol generic membuat decompile berat; persempit ke fungsi yang menyentuh input.

**Pitfall analis (membuat flag terlewat):**

- **Tersesat di runtime/stdlib.** Mayoritas fungsi Go/Rust adalah `runtime.*` / `core::`/`alloc::`/`std::`. Tanpa memfilter ke `main.*` (Go) atau modul crate (Rust), seluruh timebox habis di pustaka. Ini jebakan skor terbesar topik ini.
- **Mengira stripped = tidak terpulihkan.** Selalu cek `.gopclntab` dulu sebelum menyerah pada biner Go.
- **Membaca nama mangle mentah.** Tanpa `c++filt`/`rustfilt`, alur OOP/generic salah dibaca; demangle dulu.
- **Salah demangler / salah tool.** `c++filt` gagal pada hash Rust legacy; gunakan `rustfilt`. `undname` hanya untuk MSVC, bukan Itanium.
- **Memperlakukan blob string Go sebagai satu string.** Tanpa batas `len`, flag salah dipotong/disambung.

## Mini-Lab

**Skenario:** Diberikan empat crackme tanpa simbol penuh: `bin_a` (C), `bin_b` (C++), `bin_c` (Go, di-strip `-s -w`), `bin_d` (Rust). Masing-masing memvalidasi sebuah input dan mencetak flag bila benar.

1. **Lakukan:** `file` + `diec` + `readelf -hS` pada keempatnya → **Dapatkan** klasifikasi bahasa tiap biner (catat bukti: section/simbol/string penentu).
2. **Lakukan:** demangle `bin_b` (`c++filt`) dan `bin_d` (`rustfilt`); jalankan `go version -m` + `GoReSym -t` pada `bin_c` → **Dapatkan** daftar fungsi user (`main.*` / modul crate).
3. **Lakukan:** buka fungsi validasi di Ghidra/rizin, rekonstruksi algoritma cek input → **Dapatkan** input yang benar lalu **`flag{...}`**.
4. **Tulis POC (Judgement):** untuk satu biner, jelaskan langkah identifikasi bahasa → lokalisasi user code → pemulihan algoritma, sertakan screenshot demangle & decompile.

## Referensi & Latihan

- **Mandiant / Google FLARE — "Ready, Set, Go: Golang Internals and Symbol Recovery"** + repo **`mandiant/GoReSym`** (pemulihan simbol & buildinfo Go).
- **CUJO AI — "Reverse Engineering Go Binaries with Ghidra"** (seri, termasuk type extraction & deteksi versi Go).
- **The rustc book — Symbol Mangling** (legacy vs v0) + **`luser/rustfilt`**.
- **Volexity — GoResolver** (deobfuscation biner Go ber-garble via CFG similarity).
- **0xdevalias gist** — kumpulan catatan/tool RE biner Golang.
- **crackmes.one**, **CyberDefenders**, **BlueTeam Labs Online (BTLO)**, **HackTheBox** (challenges/Sherlocks) — latihan RE multi-bahasa.
- **SANS FOR710 / malware analysis** posters & cheat sheet untuk referensi cepat saat lomba.

> Materi ini **hanya** untuk lab pribadi, lingkungan kompetisi, atau biner dengan **izin tertulis eksplisit**. Identifikasi bahasa & reverse engineering di sini dipakai untuk belajar memecahkan tantangan CTF dan menganalisis sampel di VM terisolasi, **bukan** untuk membongkar proteksi atau merekayasa balik perangkat lunak orang lain tanpa izin.
