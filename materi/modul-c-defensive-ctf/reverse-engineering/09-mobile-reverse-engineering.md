# 9. Mobile Reverse Engineering

> Mobile reverse engineering adalah membongkar aplikasi **Android (APK)** dan **iOS (IPA)** tanpa source code untuk memahami logikanya, memulihkan algoritma/kunci, dan menembus proteksi runtime. Berbeda dari biner native murni, target mobile umumnya berlapis: **bytecode terkelola** (DEX/Dalvik di Java/Kotlin, atau Mach-O Objective-C/Swift) yang relatif mudah didekompilasi, **plus** kode native `.so`/Mach-O ARM yang harus dianalisis seperti RE klasik. Di CTF LKSN 2026 (Modul C — Reverse Engineering), soal mobile biasanya memberi sebuah `.apk`/`.ipa` dan menuntut peserta menemukan validasi flag yang tersembunyi di Java, di smali, atau di JNI `.so` — sering kali jalan tercepatnya bukan reverse penuh, melainkan **hook Frida** untuk membaca/melewati cek saat aplikasi hidup.

## Konsep

Aplikasi mobile mengemas kode + resource + manifest dalam satu arsip. **APK** adalah ZIP berisi `classes.dex` (satu atau lebih), `lib/<abi>/*.so`, `resources.arsc`, `AndroidManifest.xml` (binary XML), dan `assets/`. **IPA** adalah ZIP berisi `Payload/<App>.app/` dengan sebuah binary **Mach-O** dan `Info.plist`. Karena lapisan terkelola menyimpan banyak metadata (nama kelas, method, tipe), dekompilasi balik ke pseudo-Java atau header Objective-C jauh lebih informatif daripada disassembly C yang stripped — inilah kenapa **static analysis mobile sering 80% selesai hanya dengan `jadx`**.

Mobile RE muncul di CTF ketika: flag divalidasi oleh sebuah method Java/Kotlin yang bisa dibaca langsung; logika disembunyikan ke native `libcheck.so` (JNI) agar tidak terlihat di dekompiler Java; aplikasi memasang **root/Frida detection** atau **SSL pinning** yang harus dilewati; atau APK dipatch (smali) lalu di-rebuild untuk mengubah perilaku. Dua mode kerja: **static** (`jadx`/`apktool`/`Ghidra`) untuk membaca kode, dan **dynamic** (`frida`/`objection` + device/emulator) untuk mengamati dan memanipulasi runtime.

## Cara Kerja

**Android.** DEX (Dalvik Executable) adalah bytecode **register-based** (berbeda dari JVM yang stack-based), dijalankan oleh **ART (Android Runtime)** — modern ART meng-AOT/JIT-compile DEX ke kode native, tapi metadata DEX tetap utuh. **smali/baksmali** adalah sintaks assembly manusiawi untuk DEX; `apktool` memakai baksmali untuk mengurai `classes.dex` → file `.smali` yang bisa diedit lalu di-assemble ulang. Kode native dipanggil via **JNI**: fungsi C diekspor dengan nama ter-mangle `Java_<paket>_<Kelas>_<method>` (titik paket → `_`, underscore literal → `_1`) di dalam `lib/arm64-v8a/libx.so` (ELF ARM64) — dianalisis dengan Ghidra/IDA seperti biner native biasa.

**iOS.** Binary Mach-O berisi metadata runtime **Objective-C** (nama kelas/selector di section `__objc_*`) yang bisa di-dump jadi header (`class-dump`); **Swift** lebih buram (name mangling `$s...`). Aplikasi dari App Store dienkripsi **FairPlay DRM**: header `LC_ENCRYPTION_INFO`/`cryptid=1` menandai segmen terenkripsi, sehingga **disassembly biner App Store langsung = sampah** — harus di-dump dalam keadaan ter-decrypt dari memori (`frida-ios-dump`) di perangkat jailbreak.

**Frida** mengikat semua ini: ia menyuntik engine JavaScript + **Gum** ke proses target dan menulis trampoline di entry fungsi. Untuk lapisan terkelola, `Java.use('com.x.Checker')` mem-bind kelas dan `.implementation =` menimpa method; untuk native, `Interceptor.attach(Module.getExportByName('libx.so', '...'))`. Ide kunci CTF identik dengan dynamic analysis biner: argumen yang masuk ke fungsi pembanding adalah flag/kunci dalam bentuk plaintext.

## Indikator / Cara Mengenali

Sinyal saat membedah sebuah target mobile, dan ke mana harus menggali:

- `AndroidManifest.xml`: `android:debuggable="true"`, komponen `exported="true"`, dan `usesCleartextTraffic` → titik masuk & kemudahan instrumentasi.
- Method bernama `check`, `validate`, `verify`, `decrypt`, `isCorrect`, atau handler tombol "Submit" di `jadx` → kandidat lokasi cek flag.
- Kode Java hanya memanggil `System.loadLibrary("check")` lalu `native boolean verify(...)` → **logika ada di `.so`**, bukan di DEX; pindah ke Ghidra.
- Nama kelas/method satu huruf (`a.a.b`) → di-obfuscate ProGuard/R8; andalkan string, resource, atau dynamic.
- Banyak `classes2.dex`, `classes3.dex` → **multidex**; cari di semua, jangan hanya `classes.dex`.
- iOS: `otool -l app | grep -A4 LC_ENCRYPTION_INFO` menunjukkan `cryptid 1` → binary masih terenkripsi, perlu dump.
- Aplikasi crash/exit hanya di device rooted/jailbroken, atau menolak proxy HTTPS → ada root/jailbreak detection / SSL pinning.

## Langkah Analisis/Investigasi

1. **Unpack & recon** — `unzip -l app.apk`; identifikasi ABI native, jumlah DEX, dan baca `AndroidManifest.xml` (`apktool d` mendekode binary XML → readable).
2. **Dekompilasi cepat** — `jadx -d out app.apk` (atau `jadx-gui`) untuk membaca pseudo-Java; mulai dari entry-point Activity & string mencurigakan (cari `flag`, URL, label "Correct").
3. **Telusuri cek flag** — cross-reference dari string sukses ke method pemanggil; rekonstruksi algoritmanya, atau catat bahwa ia memanggil `native`.
4. **Analisis native bila perlu** — buka `lib/arm64-v8a/lib*.so` di **Ghidra** (ARM64), cari fungsi `Java_...` atau yang dipanggil JNI, pulihkan logikanya.
5. **Siapkan instrumentasi** — emulator/HP dengan **frida-server** (versi cocok dengan client) atau repackage Frida **Gadget** untuk device non-root.
6. **Hook runtime** — `frida -U -f <pkg> -l hook.js --no-pause`: cetak argumen/return method pembanding, atau timpa return untuk bypass; `objection` untuk tugas umum (SSL pinning, root, keychain).
7. **Patch statis (alternatif)** — `apktool d` → edit `.smali` → `apktool b` → `zipalign` → `apksigner sign` (re-sign wajib).
8. **Korelasi & POC** — satukan temuan (static → native → hook) menjadi langkah reproduksi yang menghasilkan **`flag{...}`**.

## Tools

| Tool / Plugin | Fungsi singkat |
|---|---|
| `apktool` | Decode/rebuild APK; baksmali `.dex` → `.smali`, dekode `AndroidManifest.xml`/resource |
| `jadx` / `jadx-gui` | Dekompiler DEX → pseudo-Java (deobfuscation dasar, cross-ref) |
| `dex2jar` (`d2j-dex2jar`) | Konversi `.dex` → `.jar` untuk JD-GUI/CFR/Procyon |
| `baksmali` / `smali` | Disassemble/assemble DEX ke/dari smali (juga di dalam apktool) |
| **Ghidra** / **IDA** | Analisis native `.so` (ARM/ARM64) & Mach-O; load DEX/APK langsung |
| **frida** / `frida-server` | Dynamic instrumentation: `Java.use`, `Interceptor.attach`, lintas OS |
| **objection** | Toolkit di atas Frida: `android sslpinning disable`, `root disable`, `memory search` |
| `frida-trace` | Auto-generate handler per fungsi/method (`-j` Java, `-m` ObjC) |
| **MobSF** | Analisis statis+dinamis otomatis (manifest, secret, izin, scoring) |
| `adb` | Bridge Android: install, `logcat`, `pull`, jalankan frida-server |
| `apksigner` / `zipalign` | Re-sign (skema v2/v3) & alignment setelah patch (zipalign **sebelum** sign) |
| **frida-ios-dump** / **bagbak** | Dump Mach-O ter-decrypt dari app iOS (lewati FairPlay) di device jailbreak |
| `class-dump` / `otool` / `lipo` | Dump header ObjC, inspeksi load command/`cryptid`, pisah arsitektur (iOS) |

## Contoh / Payload

**Recon & dekompilasi (Android, paling murah):**

```bash
# 0) APK = ZIP: lihat isi (jumlah DEX, ABI native)
unzip -l app.apk | grep -E 'classes.*dex|lib/.*\.so'

# 1) Dekode manifest + smali + resource
apktool d app.apk -o app_src        # AndroidManifest.xml jadi terbaca
# 2) Dekompilasi ke pseudo-Java dan grep titik menarik
jadx -d out app.apk
grep -rEi 'flag\{|password|secret|loadLibrary|Java_' out/sources | head
```

**Hook Frida — baca argumen & timpa return method validasi:**

```javascript
// hook.js  ->  frida -U -f com.lksn.app -l hook.js --no-pause
Java.perform(function () {
  var Checker = Java.use('com.lksn.app.Checker');
  // jika method punya overload, gunakan .overload('java.lang.String')
  Checker.validate.implementation = function (input) {
    console.log('[+] input   = ' + input);
    var ret = this.validate(input);          // panggil asli, intip hasilnya
    console.log('[+] retAsli = ' + ret);
    return true;                              // bypass: selalu "benar"
  };

  // bonus: bongkar string yang dibandingkan via String.equals
  var S = Java.use('java.lang.String');
  S.equals.implementation = function (o) {
    console.log('[equals] this="' + this + '"  arg="' + o + '"');
    return this.equals(o);
  };
});
```

**Hook fungsi JNI native (logika di `.so`):**

```javascript
// catatan: Frida 17+ men-deprecate Module.getExportByName (masih jalan, dengan warning);
// padanan modern: Process.getModuleByName('libcheck.so').getExportByName('Java_...')
Interceptor.attach(Module.getExportByName('libcheck.so',
    'Java_com_lksn_app_Checker_verify'), {
  onEnter(args) { this.in = Java.vm.tryGetEnv().getStringUtfChars(args[2], null).readCString(); },
  onLeave(ret) { console.log('verify("' + this.in + '") = ' + ret); }
});
```

**objection — bypass proteksi umum tanpa nulis skrip:**

```bash
objection -g com.lksn.app explore
# di prompt objection:
#   android sslpinning disable          (lewati certificate pinning)
#   android root disable                (lewati root detection)
#   android hooking watch class_method com.lksn.app.Checker.validate --dump-args --dump-return
```

**Patch smali lalu re-sign (alternatif statis):**

```bash
apktool d app.apk -o app_src
# edit app_src/smali/com/lksn/app/Checker.smali:
#   ubah  "const/4 v0, 0x0"  ->  "const/4 v0, 0x1"  (paksa return true)
apktool b app_src -o patched.apk
zipalign -p -f 4 patched.apk aligned.apk        # align SEBELUM sign
keytool -genkey -v -keystore k.jks -alias a -keyalg RSA -keysize 2048 -validity 10000
apksigner sign --ks k.jks aligned.apk           # skema v2/v3
adb install -r aligned.apk
```

**iOS — cek enkripsi lalu dump biner ter-decrypt:**

```bash
otool -l "Payload/App.app/App" | grep -A4 LC_ENCRYPTION_INFO   # cryptid 1 = terenkripsi
# di device jailbreak (frida-server aktif):
python3 dump.py com.lksn.iosapp        # frida-ios-dump -> App.ipa ter-decrypt
class-dump -H App.app/App -o headers/  # dump header Objective-C
```

## Anti-Forensik & Pitfall

**Proteksi/evasion attacker** (mempersulit RE mobile):

- **Obfuscation (ProGuard/R8, DexGuard, Allatori)** — rename `a.b.c`, string encryption, control-flow flattening, bahkan pindahkan kode ke native. Lawan: andalkan string/resource yang tak bisa di-rename, dan dynamic hook ketimbang baca statis.
- **Signature/integrity check** — aplikasi menghitung hash/signature APK-nya sendiri (`PackageManager.getPackageInfo(...).signatures`) dan menolak jalan bila berbeda. Akibatnya **APK yang di-patch + re-sign langsung terdeteksi**. Solusi: jangan repackage — **hook cek itu dengan Frida** (timpa return verifikasi), atau hook `getPackageInfo`.
- **Root/jailbreak detection** — cek `su`/`busybox`/Magisk/`test-keys` (Android), atau `/Applications/Cydia.app`/`fork()`/sandbox (iOS). Lawan: `objection android root disable` / hook fungsi deteksi.
- **Frida/anti-debug detection** — scan `/proc/self/maps` untuk `frida-agent`/`gum-js-loop`, cek port default `27042`, named pipe `re.frida.server`, atau `TracerPid` di `/proc/self/status`; iOS pakai `ptrace(PT_DENY_ATTACH)`/`sysctl`. Lawan: Gadget mode, rename artefak, hook fungsi deteksi.
- **SSL/certificate pinning** — memvalidasi sertifikat server sehingga proxy MITM gagal; lewati dengan `objection android sslpinning disable` atau skrip Frida universal.
- **Dynamic code loading** — `DexClassLoader` memuat DEX terenkripsi dari `assets/` saat runtime; kode tak ada di `classes.dex`. Dump DEX dari memori setelah dekripsi.

**Pitfall analis** (membuat flag terlewat / build gagal):

- **Lupa re-sign / zipalign** setelah `apktool b` → `INSTALL_PARSE_FAILED_NO_CERTIFICATES`. Selalu `zipalign` lalu `apksigner`.
- **Hanya cek `classes.dex`** pada APK multidex → cek logika ada di `classes2.dex`. Cari di semua DEX.
- **Mengira semua di Java** padahal `native` → `jadx` hanya menampilkan deklarasi stub; logika di `.so`. Periksa `loadLibrary`/method `native`.
- **Versi frida-server ≠ frida client** → `Failed to spawn`/protokol mismatch. Samakan versi; cocokkan **ABI** server dengan arsitektur device (arm64 vs x86 emulator).
- **Menganalisis Mach-O App Store yang masih terenkripsi** (`cryptid 1`) → dekompiler menghasilkan sampah. Dump dulu dengan `frida-ios-dump`.
- **Capture jaringan tanpa trust CA** — Android 7+ mengabaikan user-CA secara default; butuh `network_security_config` atau pinning bypass, bukan sekadar pasang proxy.

## Mini-Lab

**Skenario:** Diberikan `lksn-crackme.apk`. Aplikasi meminta serial, mencetak `Correct!`/`Nope`. Validasi tahap-1 ada di Java (`com.lksn.app.Checker.validate`), tahap-2 dilimpahkan ke `libcheck.so` (`verify`). APK juga memeriksa signature-nya sendiri sehingga repackage naif ditolak.

1. **Lakukan:** `apktool d lksn-crackme.apk` dan `jadx -d out lksn-crackme.apk` → **dapatkan** lokasi `Checker.validate` dan konfirmasi adanya `System.loadLibrary("check")` + method `native verify`.
2. **Lakukan:** jalankan `frida -U -f com.lksn.app -l hook.js --no-pause` dengan hook yang mencetak argumen `validate` dan `String.equals` → **dapatkan** string yang dibandingkan (kandidat bagian serial).
3. **Lakukan:** hook `Java_com_lksn_app_Checker_verify` di `libcheck.so` (atau buka di Ghidra) → **dapatkan** algoritma/konstanta tahap-2.
4. **Dapatkan:** susun serial yang benar (atau timpa return `verify` → `true` untuk membongkar cabang sukses), masukkan hingga muncul `Correct!`, lalu catat **`flag{...}`** beserta langkah (jadx → Frida → native) sebagai POC. Karena ada signature check, lakukan via **Frida hook**, bukan patch+re-sign.

## Referensi & Latihan

- **OWASP MASTG/MASVS** (`mas.owasp.org`) — metodologi kanonik mobile security testing, daftar tool (frida-ios-dump, objection, apktool) & teknik bypass.
- **Frida** (`frida.re/docs`) & **learnfrida.info** — Java/ObjC API, `Interceptor`, `frida-trace`, Gadget mode.
- **jadx** (`github.com/skylot/jadx`) & **apktool** (`apktool.org`) — dokumentasi dekompilasi/rebuild Android.
- **HackTricks** — *Android* & *iOS Application Pentesting* — recipe smali patching, SSL pinning, jailbreak/root bypass.
- **MobileHackingLab**, **OWASP iGoat/UnCrackable** (MASTG Crackmes) & **DIVA / InsecureBankv2** — aplikasi latihan rentan bertahap.
- **HackTheBox** (Mobile) & **HTB Sherlocks**, **CyberDefenders**, **BlueTeam Labs Online (BTLO)** — challenge mobile RE & analisis sampel.
- **SANS FOR585** (*Smartphone Forensic Analysis*) & **FOR610** — referensi metodologi analisis mobile/malware.

> Materi ini **hanya** untuk lab pribadi, lingkungan kompetisi (CTF), atau aplikasi dengan **izin tertulis eksplisit**. Instrumentasi & dump dilakukan di **emulator/perangkat uji terisolasi** milik sendiri; teknik di sini untuk belajar memecahkan tantangan dan menganalisis sampel di lab — **bukan** untuk membongkar proteksi, membajak, atau merekayasa balik aplikasi orang lain tanpa izin.
