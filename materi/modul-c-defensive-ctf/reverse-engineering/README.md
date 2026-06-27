# Reverse Engineering — Modul C (Defensive / CTF)

> Indeks & **MANIFEST** kategori **Reverse Engineering** (sering disingkat *RE*) pada Modul C (defensive / Blue-Team CTF). Di lomba, soal RE menguji kemampuan **membongkar program tanpa source code** — dari biner native (ELF/PE), bytecode, sampai aplikasi mobile — untuk **memahami logikanya**, **memulihkan algoritma tersembunyi**, dan **menembus proteksi** (anti-debug, anti-disassembly, obfuscation, enkripsi) yang sengaja dipasang. Yang dinilai bukan sekadar menjalankan tool, tapi **membaca semantik kode** (assembly, dekompilasi, struktur file) sampai bisa menjawab pertanyaan "apa yang dilakukan program ini" dan **memulihkan input/kunci yang benar**. Sebagai modul defensif, RE adalah keterampilan inti analis malware & responder: mengerti perilaku sampel untuk mempertahankan sistem. Tujuan akhirnya tetap sama: **dapatkan flag**.

## Peta ke Kisi-kisi LKSN 2026

Kategori ini adalah bagian dari **Modul C — Defensive Blue-Team CTF** pada kisi-kisi **LKSN (Lomba Kompetensi Siswa Nasional) bidang Cyber Security 2026**, berdampingan dengan kategori defensif lain di Modul C: **Digital Forensic**. Modul C berbobot **tertinggi (40%)** di antara ketiga modul, sehingga kategori **Reverse Engineering** layak mendapat porsi latihan terbesar. Fokus kategori ini: **analisis statis & dinamis** terhadap biner dan aplikasi untuk memulihkan algoritma, menembus proteksi, dan memahami perilaku — dikerjakan dengan tooling RE (umumnya **Ghidra**/**IDA**/**radare2**/**Binary Ninja**, debugger `gdb`+`pwndbg`/`gef` atau `x64dbg`, plus `z3`/Python untuk merekonstruksi & menyelesaikan constraint) dalam batas **lingkungan lomba / lab berizin**.

---

## Daftar Topik

Sembilan halaman berikut adalah cakupan tetap kategori ini. Kerjakan **berurutan 01 → 09**: mulai dari fondasi membaca kode tanpa menjalankan (static analysis) dan mengamati saat berjalan (dynamic analysis), naik ke pemahaman format file & assembly tingkat rendah, lalu teknik anti-RE yang menghalangi analisis, pengenalan jejak bahasa & arsitektur target, framework khusus, sampai ditutup dengan obfuscation/patching dan reverse engineering aplikasi mobile yang paling kompleks.

| No | Topik | File | Cakupan/Contoh | Status |
|---|---|---|---|---|
| 1 | Static Analysis | [01-static-analysis.md](01-static-analysis.md) | Reconstruct Algorithm, z3 | ✅ selesai |
| 2 | Dynamic Analysis | [02-dynamic-analysis.md](02-dynamic-analysis.md) | Tracing, GDB | ✅ selesai |
| 3 | Low Level File Formats | [03-low-level-file-formats.md](03-low-level-file-formats.md) | Assembly & Bytecodes Translation | ✅ selesai |
| 4 | Anti RE | [04-anti-re.md](04-anti-re.md) | Anti Debug (PTRACE), Anti disassembly, Anti Decompiler | ✅ selesai |
| 5 | Compiled Language Syntax in Executable | [05-compiled-language-syntax-in-executable.md](05-compiled-language-syntax-in-executable.md) | C, C++, Golang, Rust | ✅ selesai |
| 6 | Arsitektur | [06-arsitektur.md](06-arsitektur.md) | x86_64, x64, ARM, MIPS | ✅ selesai |
| 7 | Special Framework | [07-special-framework.md](07-special-framework.md) | Flutter, Kotlin, Desktop Apps (Qt) | ✅ selesai |
| 8 | Obfuscation & Binary Patching | [08-obfuscation-dan-binary-patching.md](08-obfuscation-dan-binary-patching.md) | Known/Custom Encryption | ✅ selesai |
| 9 | Mobile Reverse Engineering | [09-mobile-reverse-engineering.md](09-mobile-reverse-engineering.md) | APK/IPA, smali/dex, Frida | ✅ selesai |

---

## Catatan Format

Setiap topik di atas adalah **satu halaman** yang ditulis dengan **template seragam** berikut, agar mudah dipakai sebagai referensi cepat saat lomba:

1. **Konsep** — apa teknik/topik RE ini dan kenapa relevan di CTF & analisis pertahanan.
2. **Cara Kerja** — mekanisme yang dianalisis atau ditembus (di mana letak logika/proteksinya: alur kode, struktur file, jebakan anti-analisis).
3. **Indikator / Cara Mengenali** — ciri-ciri & triase awal untuk mengenali jenis soal/proteksi dari permukaan biner sebelum menyelam (mis. pola string, packer, transform per-karakter, jejak anti-debug).
4. **Langkah Analisis/Investigasi** — alur analisis langkah demi langkah, dari mengenali target & memetakan kode sampai memulihkan algoritma/input yang menghasilkan flag.
5. **Tools** — alat yang dipakai (mis. `Ghidra`/`IDA`/`radare2`/`Binary Ninja`, `gdb`+`pwndbg`/`gef`/`x64dbg`, `z3`, `frida`, `jadx`/`apktool`, `dnSpy`).
6. **Contoh/Payload** — skrip solver / contoh nyata (script Ghidra, solver z3, patch byte, hook Frida) yang bisa langsung diadaptasi.
7. **Anti-Forensik & Pitfall** — teknik anti-analisis yang dipasang penyusun soal/malware (packing, obfuscation, anti-debug) sekaligus jebakan analis yang membuat flag terlewat.
8. **Mini-Lab** — latihan mandiri untuk menguji pemahaman.
9. **Referensi** — sumber rujukan (paper, writeup, dokumentasi tool).

> Materi ini **hanya** untuk lab pribadi, lingkungan kompetisi, atau biner/aplikasi dengan **izin tertulis eksplisit**. Teknik RE di sini dipakai untuk belajar memecahkan tantangan CTF, menganalisis sampel di lab, dan menguji program milik sendiri, **bukan** untuk membajak, membongkar proteksi, atau merekayasa balik perangkat lunak orang lain tanpa izin.
