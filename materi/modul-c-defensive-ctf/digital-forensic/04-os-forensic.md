# 4. OS Forensic

> OS forensic adalah analisis artefak yang ditinggalkan **sistem operasi** dan aplikasi di atasnya untuk merekonstruksi aktivitas user dan attacker: program apa yang dieksekusi, file apa yang dibuka, situs apa yang dikunjungi, dan kapan semuanya terjadi. Di CTF LKSN 2026 (Modul C — Digital Forensic), soal kategori ini biasanya memberi sebuah image disk / triage collection (mis. hasil **KAPE**) lalu menuntut peserta menggali jejak dari **browser**, folder **AppData**, log **third-party app**, serta artefak OS bawaan (registry, prefetch, EVTX, log Linux). Inti kerjanya adalah **artifact discovery**: tahu di mana bukti hidup, dan tahu apa arti tiap artefak.

## Konsep

OS menulis jejak di banyak tempat secara diam-diam: setiap eksekusi program, pembukaan file, koneksi RDP, dan kunjungan web meninggalkan artefak dengan timestamp. Berbeda dari memory forensic (volatile) dan file carving (konten mentah), OS forensic bekerja pada **artefak terstruktur yang persisten di disk** — database SQLite browser, registry hive, jurnal NTFS, log teks Linux. Tujuannya adalah membangun **timeline** "siapa melakukan apa, kapan".

Empat sumber yang menjadi tulang punggung topik ini (dan kisi-kisi LKSN):

- **Browser** — riwayat, cookie, download, dan kredensial tersimpan di profil Chromium/Firefox. Sering memuat flag pada URL kunjungan, query pencarian, atau download dari C2.
- **AppData** — direktori per-user (`C:\Users\<u>\AppData\`) tempat hampir semua aplikasi menaruh state. Tiga subfolder: **`Roaming`** (ikut roaming profile domain), **`Local`** (mesin-spesifik, cache besar), **`LocalLow`** (proses low-integrity/sandboxed). Browser, chat client, dan tool remote semua menulis di sini.
- **Third-party app** — Discord/Telegram/Slack, email client (`.pst`/`.ost`), dan terutama **remote-access tool** (AnyDesk, TeamViewer) yang menjadi favorit attacker untuk akses dan eksfiltrasi.
- **Artifact discovery OS** — artefak bawaan Windows (registry, Prefetch, Amcache, EVTX, `$MFT`) **dan** Linux (`/var/log`, shell history, auditd, `wtmp`). "Windows/Linux" eksplisit di kisi-kisi: kuasai keduanya.

## Cara Kerja

Setiap artefak punya **lokasi tetap** dan **semantik spesifik** — kesalahan paling mahal di OS forensic adalah salah mengartikan apa yang dibuktikan sebuah artefak. Hafalkan peta berikut sebagai cheat-sheet lomba.

**Artefak Windows** (mayoritas adalah registry hive atau database biner yang butuh parser khusus):

| Artefak | Lokasi | Nilai forensik |
|---|---|---|
| **Prefetch** | `C:\Windows\Prefetch\*.pf` | Bukti **EKSEKUSI**: nama, run count, 8 timestamp run terakhir |
| **Amcache.hve** | `C:\Windows\AppCompat\Programs\Amcache.hve` | Program dieksekusi/ter-install + **SHA1** biner |
| **ShimCache** (AppCompatCache) | hive `SYSTEM` → `...\Session Manager\AppCompatCache` | Bukti **KEBERADAAN** (bukan eksekusi) — path & last-modified |
| **SRUM** | `C:\Windows\System32\sru\SRUDB.dat` | Resource usage per app/user: bytes terkirim/diterima |
| **NTUSER.DAT** / **UsrClass.dat** | `C:\Users\<u>\` (UsrClass di `AppData\Local\Microsoft\Windows\`) | UserAssist, RecentDocs, RunMRU, **ShellBags**, TypedPaths |
| **Jump Lists** | `AppData\Roaming\Microsoft\Windows\Recent\*Destinations` | File & app yang dibuka user |
| **`$MFT`** / **`$UsnJrnl:$J`** | root volume NTFS (`$Extend\$UsnJrnl:$J`) | Metadata semua file; timeline create/rename/delete |
| **EVTX** | `C:\Windows\System32\winevt\Logs\*.evtx` | Logon (4624/4625), proses (4688/Sysmon 1), service, PowerShell |
| **`$Recycle.Bin`** | `C:\$Recycle.Bin\<SID>\` (`$I` metadata, `$R` konten) | File terhapus + nama/path/waktu asli |

**Artefak Linux** (mayoritas log teks polos atau biner sederhana — lebih mudah dibaca, tapi mudah disunting attacker):

| Artefak | Lokasi | Nilai forensik |
|---|---|---|
| **Auth log** | `/var/log/auth.log` (Debian) / `/var/log/secure` (RHEL) | `sudo`, `sshd`, `su`: login sukses & gagal |
| **wtmp / btmp / lastlog** | `/var/log/wtmp`, `/var/log/btmp` | Histori login (`last`), login gagal (`lastb`) |
| **Shell history** | `~/.bash_history`, `~/.zsh_history` | Command yang dijalankan tiap user |
| **auditd** | `/var/log/audit/audit.log` | Eksekusi (execve), akses file via `ausearch` |
| **systemd journal** | `/var/log/journal/` | Log biner terstruktur, dibaca `journalctl` |
| **Persistence** | `/etc/crontab`, `/var/spool/cron/`, `/etc/systemd/system/`, `~/.ssh/authorized_keys` | Backdoor/persistensi attacker |
| **Trash / recent** | `~/.local/share/Trash/`, `~/.local/share/recently-used.xbel` | File terhapus & dibuka via GUI |

**Browser** menyimpan profil di AppData (Windows) atau `~/.config`/`~/.mozilla` (Linux). Kunci timestamp **berbeda per engine** — mencampurnya adalah kesalahan timeline klasik:

| Engine | Profil | File kunci | Epoch timestamp |
|---|---|---|---|
| **Chromium** (Chrome/Edge/Brave) | `AppData\Local\Google\Chrome\User Data\Default\` | `History`, `Cookies`, `Login Data`, `Web Data` (SQLite); `Bookmarks` (JSON) | **WebKit**: µs sejak **1601-01-01** |
| **Firefox** | `AppData\Roaming\Mozilla\Firefox\Profiles\<rand>.default\` | `places.sqlite`, `cookies.sqlite`, `formhistory.sqlite`, `logins.json`+`key4.db` | **PRTime**: µs sejak **1970-01-01** |

## Indikator / Cara Mengenali

Tanda aktivitas mencurigakan di artefak OS:

- **Eksekusi dari path tak lazim** — Prefetch/Amcache menunjukkan biner berjalan dari `%TEMP%`, `AppData`, `Downloads`, atau `C:\Users\Public`.
- **Anomali timestamp `$SI` vs `$FN`** — `$STANDARD_INFORMATION` bisa diubah userland (timestomp, T1070.006), `$FILE_NAME` tidak. Selisih keduanya, atau detik/nanodetik yang ter-nol (`...00.000`), adalah tell kuat.
- **Log dibersihkan** — Windows Event ID **1102** (Security log cleared) / **104** (log lain cleared); di Linux: `wtmp`/`auth.log` yang "lompat" waktunya, atau `~/.bash_history` kosong/`-> /dev/null`.
- **Remote-access tool muncul** — adanya `C:\ProgramData\AnyDesk\` atau log TeamViewer (`Connections_incoming.txt`) padahal tidak ada alasan bisnis = jalur akses attacker.
- **Browser ke domain mencurigakan** — `History` memuat URL paste-site, file-host, atau C2; download `.exe`/`.ps1`/`.hta`.
- **Persistensi** — entri baru di `Run`/`RunOnce`, scheduled task, service, atau (Linux) cron/systemd unit/`authorized_keys` yang asing.
- **Baris yang "hilang"** — gap waktu di history browser atau log; data terhapus mungkin masih di SQLite WAL/freelist (lihat Pitfall).

## Langkah Analisis/Investigasi

1. **Triage & mount** — kumpulkan artefak (mis. **KAPE** `--target`), atau mount image read-only. Catat **timezone** sistem (registry `TimeZoneInformation`) — mayoritas artefak UTC.
2. **Profil sistem** — identifikasi OS/build, hostname, user (hive `SYSTEM`/`SAM`, atau `/etc/passwd`, `/etc/os-release`).
3. **Bukti eksekusi** — parse **Prefetch** + **Amcache** + **ShimCache** + **UserAssist**; korelasikan: presence vs run vs run-count.
4. **Aktivitas user** — ShellBags, Jump Lists, RecentDocs, LNK untuk file/folder yang diakses; `recently-used.xbel` di Linux.
5. **Browser** — copy profil, query SQLite (jangan kunci file live), normalkan timestamp ke UTC; pakai **Hindsight** untuk timeline gabungan.
6. **Third-party app** — periksa log AnyDesk/TeamViewer (ID remote, transfer file), chat client di AppData, email store.
7. **Log & event** — EVTX dengan **chainsaw**/**Hayabusa** (Sigma); Linux dengan `journalctl`/`ausearch`/`last`. Cari logon, eksekusi, dan log-clearing.
8. **Supertimeline & korelasi** — gabungkan semua sumber dengan **plaso** (`log2timeline.py` → `psort.py`); susun timeline lintas-artefak sebagai POC.

## Tools

| Tool | Fungsi singkat |
|---|---|
| **KAPE** | Akuisisi (Targets) + parsing (Modules) artefak triage Windows |
| **Eric Zimmerman tools** (EZ) | Suite parser: `PECmd` (Prefetch), `AmcacheParser`, `AppCompatCacheParser`, `MFTECmd` (`$MFT`/`$J`), `SBECmd` (ShellBags), `JLECmd` (Jump Lists), `LECmd` (LNK), `SrumECmd`, `RBCmd` (Recycle Bin), `RECmd`/Registry Explorer |
| **RegRipper** | Ekstraksi cepat key/value penting dari registry hive via plugin |
| **EvtxECmd** / **chainsaw** / **Hayabusa** | Parsing & hunting EVTX; chainsaw & Hayabusa berbasis **Sigma** rules |
| **Hindsight** | Parser browser Chromium **dan** Firefox; normalisasi timestamp → timeline CSV/JSONL |
| **sqlite3** / DB Browser for SQLite | Query manual `History`/`places.sqlite`; akses WAL & freelist |
| **The Sleuth Kit** (`fls`, `mactime`, `icat`) / **Autopsy** | Filesystem timeline, listing, ekstraksi file (Win & Linux) |
| **plaso** (`log2timeline.py`, `psort.py`) | Supertimeline lintas-artefak (ribuan parser) |
| **Velociraptor** | DFIR endpoint: koleksi & query artefak skala besar (VQL) |
| **Linux native** (`last`, `lastb`, `ausearch`, `journalctl`, `stat`, `debugfs`) | Baca log login, auditd, journal, dan timestamp inode |

## Contoh / Payload

**Browser — angkat riwayat & normalkan timestamp** (salin profil dulu; jangan query file yang terkunci proses live):

```bash
# Chromium: last_visit_time = WebKit (µs sejak 1601) -> konversi ke UTC
sqlite3 History "SELECT datetime(last_visit_time/1000000-11644473600,'unixepoch') AS ts,
  url, title FROM urls ORDER BY last_visit_time DESC LIMIT 20;"
# Download mencurigakan (.exe/.ps1 dari internet)
sqlite3 History "SELECT datetime(start_time/1000000-11644473600,'unixepoch'),
  target_path, tab_url FROM downloads;"

# Firefox: visit_date = PRTime (µs sejak 1970) -> epoch BERBEDA, jangan kurangi 11644473600!
sqlite3 places.sqlite "SELECT datetime(v.visit_date/1000000,'unixepoch'), p.url
  FROM moz_places p JOIN moz_historyvisits v ON p.id=v.place_id ORDER BY v.visit_date DESC;"

# Timeline browser otomatis dgn Hindsight (satu engine per run: -b Chrome [default] / -b Firefox)
hindsight.py -i "User Data/Default" -o report   # -> report.xlsx/jsonl

# Baris terhapus sering masih di WAL/freelist -> jangan hanya SELECT biasa
strings -a History-wal | grep -iE 'http|flag\{'
```

**Windows — bukti eksekusi & event log** (EZ tools + Sigma hunting):

```powershell
# Prefetch: bukti EKSEKUSI + run count + waktu run terakhir
PECmd.exe -d C:\Windows\Prefetch --csv .\out

# ShimCache (KEBERADAAN, bukan eksekusi) & Amcache (eksekusi + SHA1)
AppCompatCacheParser.exe -f SYSTEM --csv .\out
AmcacheParser.exe -f C:\Windows\AppCompat\Programs\Amcache.hve --csv .\out

# Timeline filesystem dari $MFT + jurnal $UsnJrnl ($J) -> delete/rename/timestomp
MFTECmd.exe -f '$MFT' --csv .\out
MFTECmd.exe -f '$J'   --csv .\out

# Hunting EVTX berbasis Sigma (logon, proses, log-clearing 1102/104)
chainsaw hunt .\winevt\Logs -s sigma\ --mapping mappings\sigma-event-logs-all.yml
hayabusa.exe csv-timeline -d .\winevt\Logs -o timeline.csv
```

**Third-party app — jejak AnyDesk** (favorit attacker untuk akses & eksfiltrasi):

```bash
# Service (terinstal) -> ProgramData ; portable -> AppData\Roaming
type "C:\ProgramData\AnyDesk\connection_trace.txt"   # ID remote + arah koneksi + waktu
type "C:\ProgramData\AnyDesk\ad_svc.trace"           # detail sesi semua user
# user-context: %AppData%\AnyDesk\ad.trace, connection_trace.txt, chat\, thumbnails\  (%AppData% = ...\AppData\Roaming)
```

**Linux — login, history, dan timestamp inode:**

```bash
last  -f /var/log/wtmp        # histori login sukses (IP, durasi)
lastb -f /var/log/btmp        # percobaan login GAGAL (brute force)
ausearch -m execve -i         # semua eksekusi via auditd
journalctl --since "2026-06-25 00:00" -o short-iso-precise
grep -aE 'curl|wget|nc |chmod \+x' /home/*/.bash_history   # command attacker
stat /home/user/.ssh/authorized_keys          # cek crtime/mtime persistensi
debugfs -R 'stat <inode>' /dev/sda1           # crtime (birth) ext4, tak ada di stat biasa
```

## Anti-Forensik & Pitfall

**Teknik anti-forensik attacker** (MITRE **T1070 Indicator Removal**):

- **Timestomping** (T1070.006) — `$SI` timestamp diset ke masa lalu agar file lolos timeline. Lawan: bandingkan dengan `$FN` (tak bisa diubah userland) lewat `MFTECmd`.
- **Clear event log** (T1070.001) — `wevtutil cl`/`Clear-EventLog` menghapus EVTX; meninggalkan Event ID **1102/104**. Di Linux (T1070.003): `history -c`, `unset HISTFILE`, atau `ln -sf /dev/null ~/.bash_history`.
- **File deletion / wiping** (T1070.004) — hapus prefetch/`$Recycle.Bin`/log; tapi `$UsnJrnl` & SQLite WAL sering masih merekam jejaknya.
- **Disable artefak** — matikan Prefetch (`EnablePrefetcher=0`), SysMain, atau auditd agar bukti eksekusi tak terbentuk.
- **Living-off-the-land** — pakai biner sah (`certutil`, `bitsadmin`, `mshta`) sehingga eksekusi tampak normal di Prefetch/Amcache.
- **Browser private/portable** — incognito tak menulis `History`; tapi DNS cache, `$MFT`, dan memori bisa tetap menyimpan jejak.

**Pitfall analis** (kesalahan yang membuat flag/temuan terlewat):

- **ShimCache = eksekusi.** SALAH — ShimCache/AppCompatCache hanya bukti **keberadaan** file. Bukti eksekusi sejati ada di **Prefetch** dan **Amcache** (dengan catatan masing-masing). Salah artikan ini = kesimpulan keliru.
- **Salah epoch browser.** Chromium = µs sejak **1601** (`/1e6 − 11644473600`); Firefox = µs sejak **1970**. Tertukar → timeline meleset ratusan tahun atau jam.
- **Hanya `SELECT` baris hidup.** Riwayat terhapus tinggal di **WAL/`-journal` & freelist page** SQLite — butuh tool recovery atau `strings`, bukan query biasa.
- **Abaikan timezone.** Mayoritas artefak Windows **UTC**, sebagian log Linux local-time. Konversi sembrono merusak korelasi antar-sumber.
- **Edit artefak secara live.** Buka/ubah file di image asli mengubah `atime`/`mtime`. Selalu kerja pada **salinan**, mount read-only.
- **Lupa Linux.** Kisi-kisi menuntut Windows **dan** Linux; fokus berlebih ke registry/EVTX sambil melewatkan `auth.log`, `wtmp`, auditd, dan cron adalah celah umum.

## Mini-Lab

**Skenario:** Diberikan triage collection `host01` (Windows 10). Attacker mengakses host via AnyDesk, mengunduh tool lewat browser, mengeksekusinya dari `AppData`, lalu mencoba membersihkan jejak. Flag terbagi: satu di URL download, satu di nama biner yang dieksekusi.

1. **Lakukan:** parse Prefetch + Amcache (`PECmd`, `AmcacheParser`) → **dapatkan** biner yang dieksekusi dari path `AppData\Local\Temp` beserta SHA1 dan run-count.
2. **Lakukan:** query `History` browser dengan konversi WebKit (`/1000000-11644473600`) → **dapatkan** URL download yang memuat bagian pertama **`flag{...}`**.
3. **Lakukan:** baca `C:\ProgramData\AnyDesk\connection_trace.txt` → **dapatkan** ID remote attacker dan waktu sesi; korelasikan dengan Event ID logon di EVTX.
4. **Dapatkan:** jalankan `chainsaw hunt`/`Hayabusa` pada EVTX → temukan **Event ID 1102** (log dibersihkan), buktikan upaya anti-forensik, lalu rangkai timeline AnyDesk → download → eksekusi → clear-log sebagai POC (Judgement).

## Referensi & Latihan

- **SANS DFIR** — poster *Windows Forensic Analysis* & *Hunt Evil* (parent/child, prefetch, ShimCache vs Amcache); kursus **FOR500** (Windows) & **FOR577** (Linux).
- **Eric Zimmerman Tools** (`ericzimmerman.github.io`) & **KAPE** docs — referensi parser dan Targets/Modules resmi.
- **Hindsight** (RyanDFIR/obsidianforensics) — dokumentasi parser browser Chromium/Firefox.
- **chainsaw** (WithSecure) & **Hayabusa** (Yamato Security) — hunting EVTX berbasis Sigma.
- **plaso / log2timeline** docs — pembuatan supertimeline.
- **CyberDefenders** & **BlueTeam Labs Online (BTLO)** — lab DFIR berbasis disk/triage image nyata (Sysinternals, AnyDesk, browser).
- **HackTheBox Sherlocks** — investigasi DFIR end-to-end (Windows & Linux host).
- **inversecos / The DFIR Spot / Forensic Focus** — write-up artefak AnyDesk, EVTX, dan browser.

---

> **Catatan etika.** Teknik di halaman ini hanya untuk **lingkungan lab, sistem milik sendiri, atau dengan izin tertulis**, serta untuk keperluan **CTF/latihan resmi LKSN 2026**. Artefak OS memuat data pribadi (riwayat browsing, kredensial, kredensial chat); mengakses atau menganalisis artefak dari perangkat orang lain tanpa otorisasi adalah pelanggaran hukum dan etika. Lakukan analisis hanya pada bukti yang sah dan dalam ruang lingkup yang diizinkan.
