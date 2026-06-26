# 7. Special Framework

> Tidak semua biner adalah kode native "biasa" yang hasil dekompilasinya langsung terbaca. Beberapa framework membungkus logika asli aplikasi di balik **runtime, bytecode, snapshot, atau meta-object system** sendiri — sehingga disassembly native standar (Ghidra/IDA) menampilkan kerangka VM/loader, bukan algoritma yang Anda cari. Di CTF LKSN 2026 (Modul C — Reverse Engineering), tiga keluarga "special framework" yang paling sering muncul: **Flutter** (logika Dart di-AOT ke `libapp.so`), **Kotlin** (logika di JVM bytecode atau Kotlin/Native), dan **Desktop Apps berbasis Qt** (C++ dengan meta-object dari `moc`). Halaman ini fokus pada *masalah membongkar framework-nya*; untuk mekanika pengemasan mobile (APK/IPA, smali/dex, hook Frida umum) lihat halaman **09 — Mobile Reverse Engineering**.

## Konsep

Disebut "special" karena logika aplikasi tidak duduk sebagai fungsi C/C++ polos di `.text`. Tiap framework menyisipkan lapisan abstraksi sendiri:

- **Flutter** meng-**AOT-compile** kode Dart menjadi instruksi native, tetapi membungkusnya dalam **snapshot + object pool** dengan **calling convention non-standar**. Decompiler generik tak mengenali struktur Dart, jadi fungsi terlihat seperti rangkaian load dari sebuah register pool yang misterius.
- **Kotlin** umumnya **tidak** dikompilasi ke native — ia menjadi **JVM bytecode** (dex di Android, `.class`/JAR di desktop/Compose), sehingga bisa **didekompilasi balik mendekati source**. Tantangannya adalah idiom Kotlin (metadata, intrinsics, coroutine state machine) yang membuat bytecode lebih "berisik". Pengecualian: **Kotlin/Native** dikompilasi via LLVM ke biner native sejati.
- **Qt** adalah C++ native biasa, tetapi **meta-object system** (signals/slots, properties, introspeksi) ditambahkan oleh **`moc` (Meta-Object Compiler)**. Akibatnya alur kontrol jadi tak langsung (lewat `QObject::connect`) dan string disimpan sebagai **`QString` UTF-16**, sehingga `strings` ASCII default tidak menemukannya.

Relevansi pertahanan: analis malware/responder makin sering menerima sampel Flutter (dropper mobile), tooling internal ber-Kotlin, atau aplikasi desktop Qt — mengenali frameworknya menentukan *tool dan pendekatan* yang benar sebelum membuang waktu di disassembly mentah.

## Cara Kerja

**Flutter / Dart AOT.** Aplikasi Flutter rilis memuat dua library kunci: **`libflutter.so`** (engine, termasuk stack jaringan BoringSSL sendiri) dan **`libapp.so`** (kode Dart aplikasi yang sudah di-AOT). Kode Dart bukan fungsi native lazim:

- **Object pool** — konstanta, string, dan referensi objek diakses lewat sebuah register pool, bukan immediate. Pada ARM64 (lihat `runtime/vm/constants_arm64.h`): **`x27` = PP (Object Pool)**, **`x26` = THR (Thread)**, **`x28` = HEAP_BITS** (`write_barrier_mask << 32 | heap_base >> 32` — gabungan mask write-barrier GC + heap base untuk dekompresi pointer).
- **Calling convention** bersifat **version-dependent**: Dart AOT versi lama memakai konvensi **custom** (sebagian besar argumen di-*push* ke stack VM Dart sendiri, dengan **`x15` sebagai Dart SP**), sedangkan Dart yang lebih baru bergerak ke konvensi ARM64 standar. Jangan asumsikan satu konvensi mutlak — cek versi engine dulu.
- **Snapshot** — heap awal isolate (`kDartVmSnapshotData/Instructions`, `kDartIsolateSnapshotData/Instructions`) di-deserialisasi saat start; nama class/fungsi Dart hilang dari simbol native, tetapi masih dapat direkonstruksi dari struktur pool oleh tool yang memuat runtime Dart yang cocok.

**Kotlin (JVM & Native).** Pada target JVM, compiler menghasilkan bytecode + penanda khas Kotlin: anotasi **`kotlin.Metadata`** (`@Metadata`) di tiap class, panggilan **`Intrinsics.checkNotNullParameter`/`checkNotNull`** untuk null-safety, **lambda → class sintetik**, **`companion object` → field statik `Companion`**, **`data class` → `component1()`/`copy()`**, dan **coroutine `suspend` → state machine** (`Continuation`, method `invokeSuspend`, `switch` atas `label`). Karena ini bytecode, dekompilasi mengembalikan kode mirip-source. **Kotlin/Native** (dipakai Compose Multiplatform native, iOS) berbeda total: dikompilasi via **LLVM** ke biner native + `.klib`, sehingga harus dibaca seperti C/C++ native di Ghidra.

**Qt (Desktop C++).** Sebelum kompilasi, `moc` membaca header ber-`Q_OBJECT` dan men-generate kode meta-object: struktur **`staticMetaObject`**, tabel **`qt_meta_stringdata_*`** dan **`qt_meta_data_*`**, fungsi **`qt_static_metacall`** dan **`qt_metacall`** (parameter pertama `int _c`: 0 = invoke method, 1 = read property, 2 = write property). Signal/slot tidak dipanggil langsung — `QObject::connect(sender, SIGNAL, receiver, SLOT)` menyimpan koneksi, lalu emisi signal di-*dispatch* lewat `qt_metacall`. Inilah kenapa "siapa memanggil siapa" tidak terlihat dari xref biasa, dan kenapa memulihkan nama slot dari `qt_meta_stringdata` sangat berharga.

## Indikator / Cara Mengenali

Fingerprint cepat — tentukan framework sebelum memilih tool:

| Framework | File / library | Simbol & string penanda | Catatan deteksi |
|---|---|---|---|
| **Flutter** | `libapp.so`, `libflutter.so`, `flutter_assets/` | `kDartVmSnapshotData`, `kDartIsolateSnapshotInstructions`, akses pool via `x27` | Native, tapi decompile "aneh" → cek 2 library di atas |
| **Kotlin (JVM)** | `.dex`/`classes*.dex`, JAR, `kotlin-stdlib` | anotasi `kotlin.Metadata`, `Intrinsics.checkNotNull*`, `Lkotlin/...` | Bytecode → bisa didekompilasi mendekati source |
| **Kotlin/Native** | `.kexe` / framework / `.so` | string `Kotlin`, simbol `kfun:`, `.klib` terpisah | Native LLVM → perlakukan seperti C/C++ |
| **Qt** | `Qt6Core.dll`/`Qt5Core.dll`, `libQt6Core.so` | `qt_meta_stringdata_*`, `qt_static_metacall`, `QString`, `QObject::connect` | `QString` = **UTF-16LE** → pakai `strings -e l` |

Petunjuk tambahan:

- **`file`** + **`readelf -d`/`objdump -p`** memperlihatkan dependency (`NEEDED libflutter.so`, `Qt6Core.dll`) — penanda framework paling cepat dan paling jujur.
- Pada Flutter, dekompilasi `libapp.so` yang penuh load dari satu register (pool) tanpa string immediate adalah tanda khas Dart AOT.
- Pada Qt, jika `strings` biasa nyaris kosong padahal UI penuh teks, hampir pasti string ada sebagai **UTF-16** — ganti ke `strings -e l`.

## Langkah Analisis/Investigasi

1. **Sidik framework** — `file`, `readelf -d`/`objdump -p`/cek import PE, dan daftar isi APK/bundle. Tentukan: Flutter? Kotlin JVM vs Native? Qt? (Salah identifikasi = salah seluruh pendekatan.)
2. **Pilih jalur sesuai framework:**
   - **Flutter** → ekstrak `libapp.so` (arm64), jalankan **Blutter** untuk memulihkan nama class/fungsi Dart + object pool, atau **reFlutter** untuk patch engine (dump snapshot / bypass SSL) saat butuh dinamis.
   - **Kotlin JVM** → dekompilasi langsung (**jadx** untuk dex, **CFR/Procyon/Vineflower** untuk `.class`/JAR); abaikan boilerplate `Intrinsics`, fokus logika.
   - **Kotlin/Native / Qt** → muat di **Ghidra/IDA**; untuk Qt pasang **QtREAnalyzer**/**QtRE** agar nama signal/slot & method ter-recover.
3. **Pulihkan semantik** — di Flutter, korelasikan output Blutter (`pp.txt`, `addNames.py`) dengan disassembly; di Qt, baca `qt_meta_stringdata` untuk memetakan `qt_metacall` index → nama slot.
4. **Tangani string** — Qt: `strings -e l` (UTF-16); Flutter: string sering hidup di object pool, bukan `.rodata`.
5. **Verifikasi dinamis bila perlu** — hook dengan **frida** (template Frida dari Blutter, atau hook `QString`/slot di Qt) untuk mengonfirmasi alur dan menangkap nilai runtime.
6. **Rekonstruksi & dokumentasi** — susun algoritma cek (mis. validasi password) menjadi solver; flag muncul setelah logika framework-spesifik dipahami.

## Tools

| Tool | Fungsi singkat |
|---|---|
| **Blutter** (worawit) | Reversing Flutter: memuat runtime Dart, parse `libapp.so` (Android **arm64**), keluarkan nama fungsi/class, `pp.txt` (object pool), `addNames.py` (IDA), template Frida |
| **reFlutter** (Impact-I) | Patch Flutter engine: dump snapshot deserialisasi & bypass SSL pinning untuk analisis dinamis |
| **unflutter** | Static analyzer snapshot Dart AOT (recover fungsi/class) tanpa menjalankan VM |
| **jadx** | Dekompilasi dex → Java/Kotlin-like (Android/Kotlin JVM) |
| **CFR / Procyon / Vineflower** | Dekompiler `.class`/JAR untuk Kotlin/Java desktop (Vineflower = penerus Fernflower/Quiltflower; CFR & Procyon dekompiler independen) |
| **Bytecode-Viewer** | GUI multi-dekompiler + editor bytecode JVM |
| **Ghidra** | Decompiler native multi-arch: Kotlin/Native, Qt, `libapp.so` mentah |
| **QtREAnalyzer** (diommsantos) / **QtRE** (OSUSecLab) | Ekstensi Ghidra: recover meta-object Qt, nama signal/slot, resolusi `QObject::connect` |
| **IDA Pro / Binary Ninja** | Disassembler/decompiler alternatif (plugin Dart/Qt tersedia) |
| **frida** | Instrumentasi dinamis lintas framework (hook Dart/JVM/Qt) |
| **`strings -e l`** | Ekstrak string **UTF-16LE** (wajib untuk `QString` Qt) |

## Contoh / Payload

**1) Identifikasi framework dari dependency:**

```bash
file app.so
readelf -d libapp.so | grep NEEDED        # NEEDED libflutter.so  -> Flutter
objdump -p game.exe | grep -i 'Qt[56]Core' # Qt6Core.dll          -> Qt desktop
unzip -l app.apk | grep -E 'libapp\.so|kotlin|libflutter\.so'
```

**2) Flutter — recover semantik Dart dengan Blutter:**

```bash
# arm64 libapp.so + libflutter.so dari APK (lib/arm64-v8a/)
python3 blutter.py path/to/lib/arm64-v8a out_dir
# out_dir/ berisi:
#   asm/            -> disassembly per-library
#   pp.txt          -> isi Object Pool (string/konstanta Dart)
#   addNames.py     -> skrip IDA untuk menamai fungsi Dart
#   blutter_frida.js-> template hook Frida
grep -i 'flag\|password\|secret' out_dir/pp.txt   # flag sering di object pool
```

**3) Flutter — analisis dinamis dengan reFlutter (dump snapshot / intercept):**

```bash
pip install reflutter
reflutter app.apk        # pilih mode: dump snapshot ATAU SSL bypass
# -> menghasilkan release.RE.apk; sign lalu install, jalankan, baca dump
```

**4) Kotlin JVM — dekompilasi & kenali idiom Kotlin:**

```bash
jadx -d out app.apk                   # dex -> sumber Java/Kotlin-like
cfr app.jar --outputdir out_jar       # JAR desktop/Compose
# Penanda yang boleh diabaikan saat membaca:
#   Intrinsics.checkNotNullParameter(x, "x")   <- boilerplate null-check
#   @Metadata(...)                              <- metadata Kotlin
#   invokeSuspend(...) + switch(label)          <- coroutine state machine
```

**5) Qt — string UTF-16 & pemulihan meta-object:**

```bash
strings -e l game.exe | grep -iE 'flag|key|wrong|correct'   # QString = UTF-16LE
# Di Ghidra: File > Install Extensions > QtREAnalyzer, lalu Auto-Analyze.
# Hasil: qt_metacall index -> nama slot asli (mis. on_submit_clicked).
```

**6) Qt — hook QString runtime dengan Frida (konfirmasi logika cek):**

```javascript
// QString::compare / fromUtf8 sering jadi titik validasi input
// Frida 17+ menghapus Module.getExportByName statik -> pakai Process.getModuleByName(...)
// fromUtf8 mengembalikan QString by value (tipe non-trivial): args[0] = pointer hasil (sret),
// jadi const char* input ada di args[1] (ABI MSVC x64 maupun Itanium/Linux).
const fromUtf8 = Process.getModuleByName('Qt6Core.dll')
  .getExportByName('?fromUtf8@QString@@...');   // lengkapi nama mangled asli dari binari
Interceptor.attach(fromUtf8, {
  onEnter(args) { console.log('[QString] ', args[1].readUtf8String()); }
});
```

## Anti-Forensik & Pitfall

**Teknik evasion attacker (mempersulit reversing framework):**

- **Flutter — mismatch versi engine.** Dart AOT terikat versi engine; sampel dibangun dengan engine yang Anda tak punya snapshot/symbol-nya membuat Blutter gagal atau menamai salah. Attacker juga bisa memodifikasi engine agar deserialisasi tak standar.
- **Flutter — calling convention non-standar** sengaja dibiarkan agar decompiler generik tak mengenali batas/argumen fungsi; tanpa Blutter, `libapp.so` terlihat seperti rangkaian load pool tanpa makna.
- **Kotlin — pengaburan idiom & obfuscation.** R8/ProGuard merename class/method dan menghapus `@Metadata`, plus string encryption; coroutine state machine yang berlapis sengaja mengaburkan alur.
- **Qt — meta-object indirection.** Logika disembunyikan di slot yang hanya dipanggil lewat `qt_metacall`/`connect`, sehingga xref langsung kosong; ditambah `QString` UTF-16 agar lepas dari `strings` ASCII.
- **Kotlin/Native & native packing** — beralih ke Kotlin/Native atau mem-pack `libapp.so` agar analis yang menyangka "tinggal didekompilasi" tersesat.

**Pitfall analis (kesalahan yang membuat flag terlewat):**

- **Salah identifikasi framework** → memaksa decompiler native pada Flutter, atau mencari "bytecode" pada Kotlin/Native. Selalu `readelf -d`/cek import dulu.
- **`strings` ASCII pada Qt** → flag berupa `QString` UTF-16 tak muncul. Gunakan **`strings -e l`**.
- **Salah arsitektur/versi untuk Blutter** → Blutter hanya **Android arm64**; salah arch atau versi engine = output kosong/garbage tanpa error jelas. Sediakan `libapp.so` **dan** `libflutter.so` yang sepadan.
- **Menyangka argumen Dart ada di `x0–x7`** → pada Dart AOT lama argumen di stack VM (`x15`), bukan ABI ARM64 standar; salah baca register = salah algoritma.
- **Tersesat di boilerplate Kotlin** → menghabiskan waktu pada `Intrinsics`/getter-setter sintetik alih-alih logika inti.
- **Mengabaikan `qt_meta_stringdata`** di Qt → tidak memetakan index `qt_metacall` ke nama slot, sehingga alur signal→slot tak terbaca.

## Mini-Lab

**Skenario:** Diberikan tiga artefak: (a) `app.apk` Flutter, (b) `tool.jar` Kotlin desktop, (c) `crackme.exe` Qt. Masing-masing memvalidasi sebuah serial/password dan mencetak flag bila benar.

1. **Lakukan (Flutter):** `unzip -l app.apk | grep libapp`, ekstrak `lib/arm64-v8a/`, jalankan `python3 blutter.py lib/arm64-v8a out` → **dapatkan** nama fungsi Dart + `pp.txt`; cari rutin cek serial dan string flag di object pool.
2. **Lakukan (Kotlin):** `cfr tool.jar --outputdir out_jar` (atau jadx) → **dapatkan** sumber mendekati asli; abaikan `Intrinsics`/`@Metadata`, rekonstruksi fungsi validasi (sering `data class` + `equals`).
3. **Lakukan (Qt):** `strings -e l crackme.exe | grep -i flag`, lalu muat di Ghidra + **QtREAnalyzer** → **dapatkan** nama slot (mis. `on_check_clicked`) dan baca logika pembanding `QString`.
4. **Dapatkan:** untuk tiap artefak, rekonstruksi algoritma cek menjadi solver (atau hook Frida untuk menangkap input benar) hingga memperoleh **`flag{...}`**; dokumentasikan framework → tool → langkah sebagai POC.

## Referensi & Latihan

- **Blutter** (github.com/worawit/blutter) & materi HITB "B(l)utter — Reversing Flutter Applications by using Dart Runtime" — pemulihan semantik Dart AOT.
- **reFlutter** (github.com/Impact-I/reFlutter) & **unflutter** — dump snapshot, SSL bypass, analisis statis Dart.
- **Guardsquare — "Current State and Future of Reversing Flutter Apps"** dan blog **cryptax**/**ping (tst.sh)** — calling convention Dart, object pool, register `x15/x26/x27`.
- **QtREAnalyzer** (diommsantos) & **QtRE** (OSUSecLab) + paper USENIX Security 2023 *"Egg Hunt in Tesla Infotainment: A First Look at Reverse Engineering of Qt Binaries"* (Wen & Lin, OSU) — meta-object, signals/slots.
- **Kotlin SCP — M9 Reverse Engineering** & dokumentasi **jadx/CFR/Vineflower** — idiom `@Metadata`, `Intrinsics`, coroutine.
- **crackmes.one** — filter Flutter/Qt/JVM untuk latihan per-framework.
- **CyberDefenders**, **Blue Team Labs Online (BTLO)**, **HackTheBox Sherlocks** — challenge RE/DFIR melibatkan aplikasi framework-spesifik.

> **Etika:** Materi ini hanya untuk lab pribadi, lingkungan kompetisi (CTF), atau aplikasi dengan **izin tertulis eksplisit**. Membongkar Flutter/Kotlin/Qt di sini dipakai untuk belajar memecahkan tantangan, menganalisis sampel di lab, dan menguji program milik sendiri — **bukan** untuk merekayasa balik perangkat lunak orang lain tanpa izin.
