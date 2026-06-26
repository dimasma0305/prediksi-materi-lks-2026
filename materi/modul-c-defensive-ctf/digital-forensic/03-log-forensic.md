# 3. Log Forensic

> Log forensic adalah analisis catatan aktivitas (log) sistem, aplikasi, dan jaringan untuk merekonstruksi *apa yang terjadi, kapan, dan oleh siapa* selama sebuah insiden. Log adalah memori jangka-panjang sebuah sistem: setiap logon, eksekusi proses, instalasi layanan, request HTTP, dan upaya gagal meninggalkan baris jejak yang bisa diurutkan menjadi sebuah timeline. Di CTF LKSN 2026 (Modul C — Digital Forensic), soal kategori ini biasanya memberi sebuah file log mentah — `.evtx` (Windows Event Log), `auth.log`/`access.log` (Linux/web), atau export JSON/CSV dari sebuah **SIEM** — dan menuntut peserta menemukan pola serangan (brute force, webshell, privilege escalation, lateral movement, log clearing) lalu mengangkat flag yang tersembunyi di dalam argumen perintah, payload request, atau urutan event.

## Konsep

Forensik log bekerja pada dua dunia yang saling melengkapi:

- **Standalone Logs** — file log individual yang hidup di endpoint itu sendiri. Di Windows berupa `.evtx` di `C:\Windows\System32\winevt\Logs\` (channel Security, System, Application, plus operational Sysmon & PowerShell). Di Linux berupa text log di `/var/log/` (`auth.log`/`secure`, `syslog`), systemd journal (biner, dibaca `journalctl`), serta `wtmp`/`btmp` (dibaca `last`/`lastb`). Web server menulis access log dalam Common/Combined Log Format. Analisis standalone fokus pada satu host, mendalam tapi terbatas cakupan.
- **SIEM** (Security Information and Event Management) — platform agregasi terpusat (**Splunk**, **Elastic/ELK**, **Wazuh**, **Microsoft Sentinel**, **Graylog**) yang menelan log dari banyak host, menormalisasinya, mengindeks, lalu memungkinkan **korelasi lintas-sistem** dengan query language (SPL, KQL, Lucene/EQL). Kekuatan SIEM adalah melihat serangan yang menyebar antar mesin (mis. brute force di host A → logon sukses → lateral movement ke host B) — sesuatu yang tak terlihat dari satu file log.

Inti pekerjaannya sama: ubah baris log yang berserakan menjadi **timeline insiden** yang dapat dipertanggungjawabkan. Di lomba, flag bisa berada di command line yang ter-audit (4688/Sysmon 1), di payload request webshell, di nama akun backdoor, atau bahkan disembunyikan dalam celah yang ditinggalkan attacker saat membersihkan log.

## Cara Kerja

**Windows Event Log** disimpan dalam format **EVTX** — binary XML ber-channel. Setiap record memiliki **Event ID**, provider, timestamp (disimpan **UTC**), dan `EventData` terstruktur. Yang dicatat sangat bergantung pada **audit policy**: banyak event penting (mis. process creation 4688) *mati secara default* dan baru aktif bila kebijakan audit dinyalakan. **Sysmon** (Sysinternals) adalah agen tambahan yang menulis ke channel `Microsoft-Windows-Sysmon/Operational` dan memberi telemetri jauh lebih kaya (process, network, image load, registry) ketimbang audit bawaan.

**Linux** menulis log sebagai teks via syslog/rsyslog, ditambah **systemd journal** yang biner dan terindeks (akses lewat `journalctl`). Autentikasi tercatat di `auth.log` (Debian) atau `secure` (RHEL); sesi login historis ada di `wtmp`/`btmp`. **Web server** menulis tiap request sebagai satu baris: IP, timestamp, metode, path, status code, user-agent.

**SIEM** menjalankan pipeline: *ingest → parse/normalize → index → correlate → alert*. Aturan deteksi sering ditulis dalam **Sigma** — format YAML vendor-agnostik yang bisa dikonversi ke SPL/KQL/Elasticsearch query, sehingga satu aturan deteksi berlaku lintas platform. Tool hunting modern (chainsaw, hayabusa, zircolite) menerapkan ribuan aturan Sigma langsung ke file EVTX tanpa perlu SIEM penuh — sangat relevan untuk kerja CTF.

## Indikator / Cara Mengenali

Event ID Windows yang paling sering jadi kunci di lomba:

| Event ID | Channel | Arti & relevansi |
|---|---|---|
| 4624 | Security | Logon **sukses** (perhatikan Logon Type & source IP) |
| 4625 | Security | Logon **gagal** — banyak berturut = brute force/password spray |
| 4672 | Security | Special privileges di-assign saat logon (akun admin) |
| 4688 | Security | **Process creation** (+ command line bila di-audit) |
| 4720 / 4732 | Security | User account dibuat / ditambahkan ke grup admin (backdoor) |
| 4698 | Security | Scheduled task dibuat (persistence) |
| 4768 / 4769 / 4776 | Security | Kerberos TGT/TGS & NTLM auth (lateral movement, AD) |
| 1102 | Security | **Audit log dibersihkan** (anti-forensik) |
| 7045 | System | **Service** baru di-install (persistence umum) |
| 104 | System | Event log dibersihkan |
| 1 / 3 / 11 / 13 | Sysmon | Process create / network connect / file create / registry set |
| 4104 | PowerShell/Operational | **Script Block Logging** — isi skrip PowerShell mentah |

Hafalkan juga **Logon Type** pada 4624/4625 — penyimpangan adalah sinyal kuat:

| Type | Makna | Catatan curiga |
|---|---|---|
| 2 | Interactive (konsol) | — |
| 3 | Network (SMB, share) | Banyak Type 3 dari IP asing = lateral/pass-the-hash |
| 4 / 5 | Batch / Service | Service login tak biasa |
| 8 | Network cleartext | Kredensial dikirim plaintext (mis. form auth) |
| 9 | NewCredentials | `runas /netonly` — sering pada pass-the-hash |
| 10 | RemoteInteractive (RDP) | RDP dari sumber tak dikenal |
| 11 | CachedInteractive | Login dengan cached credential |

Di **Linux/web**, perhatikan: deretan `Failed password for ...` lalu `Accepted password` dari IP yang sama (brute force berhasil), `sudo: ... COMMAND=` ke root, cron baru, atau di access log — request `POST` ke file `.php`/`.aspx` aneh yang mengembalikan `200`, user-agent tool (`sqlmap`, `nikto`, `curl`), dan parameter berisi `cmd=`/`whoami`/base64.

## Langkah Analisis/Investigasi

1. **Identifikasi sumber & format** — tentukan jenis log (EVTX, journal, access log, export SIEM) dan **konfirmasi timezone**. EVTX dalam UTC; salah konversi merusak seluruh timeline.
2. **Parse ke timeline** — konversi ke format yang bisa di-grep/filter: `EvtxECmd` (EVTX→CSV/JSON), `evtx_dump.py`, `journalctl -o json`, atau `jq` untuk log JSON.
3. **Hunting otomatis** — terapkan aturan Sigma dengan `chainsaw hunt` / `hayabusa` / `zircolite` untuk menyorot record mencurigakan lebih dulu.
4. **Fokus autentikasi** — cari brute force (4625 bertumpuk → 4624), logon sukses anomali, dan Logon Type tak wajar.
5. **Eksekusi & persistence** — periksa process creation (4688/Sysmon 1) untuk command line attacker, service install (7045), scheduled task (4698), run keys (Sysmon 13).
6. **Lateral & jaringan** — korelasikan 4624 Type 3/10, Sysmon 3 (network), dan request mencurigakan antar-host.
7. **Cek log tampering** — cari 1102/104 dan **gap pada Record Number** EVTX (record hilang tanpa jejak clear).
8. **Korelasi & dokumentasi** — satukan timeline (auth → eksekusi → persistence → jaringan → flag) sebagai bukti POC.

## Tools

| Tool / Plugin | Fungsi singkat |
|---|---|
| **chainsaw** (WithSecure) | Hunting cepat EVTX berbasis Sigma + tau-engine (Rust) |
| **hayabusa** (Yamato Security) | Timeline forensik & threat hunting EVTX berbasis Sigma |
| **zircolite** | Terapkan aturan Sigma ke EVTX/JSON via SQLite |
| **EvtxECmd** (Eric Zimmerman) | Konversi EVTX → CSV/JSON/XML untuk timeline |
| **python-evtx** (`evtx_dump.py`) | Parse EVTX ke XML dari Python |
| **Sigma** / `sigma-cli` (pySigma) | Aturan deteksi YAML vendor-agnostik + konverter ke SPL/KQL |
| `Get-WinEvent` / `wevtutil` | Query & ekspor Event Log native Windows (PowerShell/CLI) |
| **LogParser** | Query SQL-like ke EVTX, IIS, dan text log |
| **Splunk** (SPL) | SIEM — index & korelasi lintas-host |
| **Elastic/ELK** + Kibana | SIEM — pencarian Lucene/EQL & visualisasi |
| **Wazuh** / **Sentinel** (KQL) | SIEM/XDR open-source & cloud-native |
| `journalctl` / `last` / `lastb` | Baca systemd journal & sesi login Linux (`wtmp`/`btmp`) |
| **lnav** / **goaccess** | Navigator log teks & analisa access log web |

## Contoh / Payload

**Windows — deteksi brute force lalu temukan logon sukses & command line attacker:**

```bash
# 0) Hunting otomatis berbasis Sigma di seluruh folder EVTX
chainsaw hunt ./Logs/ -s ./sigma/ --mapping ./mappings/sigma-event-logs-all.yml

# 1) Hitung kegagalan logon per akun (4625) -> kandidat brute force
hayabusa csv-timeline -d ./Logs -o timeline.csv
# atau native PowerShell:
Get-WinEvent -Path Security.evtx -FilterXPath "*[System[EventID=4625]]" |
  Group-Object { $_.Properties[5].Value } | Sort-Object Count -Descending

# 2) Logon SUKSES (4624) setelah ledakan 4625 -> kapan brute force berhasil
Get-WinEvent -Path Security.evtx -FilterXPath "*[System[EventID=4624]]" |
  Where-Object { $_.Properties[8].Value -eq 3 }   # Logon Type 3 (network)

# 3) Command line proses (4688) — flag sering ada di sini
EvtxECmd.exe -f Security.evtx --csv . --csvf sec.csv
grep -iE "4688" sec.csv | grep -iE "powershell|cmd|-enc|flag"

# 4) Decode PowerShell terkodekan (4104 / argumen -enc base64 UTF-16LE)
echo 'SQBFAFgAIAAo...' | base64 -d | iconv -f UTF-16LE -t UTF-8

# 5) Persistence: service install (7045) & scheduled task (4698)
Get-WinEvent -Path System.evtx -FilterXPath "*[System[EventID=7045]]"
```

**Linux — brute force SSH & webshell di access log:**

```bash
# SSH brute force -> berhasil dari IP mana?
grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn
grep "Accepted password" /var/log/auth.log      # logon sukses (korelasikan IP & waktu)

# Webshell / RCE di access log (POST status 200 ke skrip mencurigakan)
awk '$6=="\"POST" && $9==200 {print $7, $1}' access.log | grep -iE "\.php|\.aspx|cmd|upload"

# Sesi login historis & gagal
last -f /var/log/wtmp ; lastb -f /var/log/btmp
journalctl -u ssh --since "2026-06-25" -o short-iso
```

**SIEM — query korelasi (Splunk SPL & Sentinel KQL):**

```spl
index=wineventlog EventCode=4625 | stats count by Account_Name, src_ip
| where count > 20    /* spray/brute force */
```

```kql
SecurityEvent | where EventID == 4624 and LogonType == 10
| summarize count() by Account, IpAddress | where count_ > 5   // RDP anomali
```

## Anti-Forensik & Pitfall

**Teknik anti-forensik attacker** (menghapus/menyamarkan jejak log):

- **Clear event log** — `wevtutil cl Security` atau `Clear-EventLog`. Bising: meninggalkan **1102** (Security) / **104** (System), justru jadi penanda kuat insiden.
- **`mimikatz event::drop`** — mem-*patch* `wevtsvc.dll` (fungsi `Channel::ActualProcessEvent`) di memori agar EventLog service berhenti mencatat; `event::clear` lalu menghapus log **tanpa** memunculkan 1102. Penting: modifikasi ini **in-memory**, kembali normal setelah service restart/reboot.
- **DanderSpritz `eventlogedit`** — menghapus **record individual** dengan meng-unlink (menggabungkan ukuran record korban ke record sebelumnya), tanpa event clear. Namun record asli tetap utuh di file, sehingga **dapat dipulihkan** (script recovery Fox-IT) — cari gap/Record Number tak berurutan.
- **`Invoke-Phant0m`** — mematikan thread EventLog tanpa mematikan service-nya, agar logging diam-diam berhenti.
- **Disable audit** — `auditpol /set ... /success:disable`, hentikan service, atau **downgrade ke PowerShell v2** untuk menghindari Script Block Logging (4104).
- **Linux** — `history -c`, `unset HISTFILE`, `export HISTSIZE=0`, atau `ln -s /dev/null ~/.bash_history`; mengedit `auth.log`/access.log secara manual; **log flooding** untuk mengubur baris bukti.

**Pitfall analis** (kesalahan yang membuat flag/timeline meleset):

- **Timezone.** EVTX disimpan UTC; mencampur waktu lokal merusak korelasi lintas-host. Normalkan semua ke UTC.
- **Mengira 4688 selalu berisi command line.** Butuh *dua* hal: "Audit Process Creation" **dan** GPO "Include command line in process creation events". Tanpa keduanya, kolom command line kosong.
- **Lupa Sysmon tidak terpasang default.** Tanpa Sysmon, telemetri jaringan/registry/process sangat terbatas — jangan simpulkan "tidak ada aktivitas" dari ketiadaan event.
- **Hanya membaca Security log.** Persistence sering hanya muncul di System (7045), PowerShell/Operational (4104), atau Sysmon. Periksa semua channel.
- **Log rollover/overwrite.** Log berukuran maksimum dapat menimpa event lama; ketiadaan bukti bisa berarti tergusur, bukan tak terjadi.
- **Gap Record Number terlewat.** Tanpa memeriksa keberurutan record EVTX, penghapusan ala `eventlogedit` lolos tanpa terdeteksi.

## Mini-Lab

**Skenario:** Diberikan `Security.evtx` + `Sysmon.evtx` (Windows Server 2019). Attacker melakukan brute force RDP, berhasil masuk dengan akun `svc-backup`, membuat user backdoor, lalu memasang service persistence. Flag tertanam di command line service tersebut.

1. **Lakukan:** `hayabusa csv-timeline -d ./Logs -o tl.csv` lalu cari ledakan **4625** → identifikasi akun & source IP brute force.
2. **Lakukan:** filter **4624 Logon Type 10 (RDP)** dari IP yang sama → tentukan kapan brute force **berhasil**.
3. **Lakukan:** cari **4720/4732** (user backdoor dibuat & ditambah ke admin) dan **7045** (service install).
4. **Dapatkan:** baca command line pada event **7045**/Sysmon 1 (atau decode argumen `-enc`) untuk memperoleh **`flag{...}`**, lalu tulis timeline `brute force → logon → backdoor → persistence → flag` sebagai POC (Judgement).

## Referensi & Latihan

- **Sigma HQ** (`sigmahq.io`) — repositori aturan deteksi & dokumentasi `sigma-cli`/pySigma.
- **chainsaw** (WithSecureLabs) & **hayabusa** (Yamato-Security) — README dan rule set di GitHub untuk hunting EVTX.
- **Eric Zimmerman Tools** — `EvtxECmd`, `Timeline Explorer`, dan cheat sheet artefak Windows.
- **SANS DFIR** — poster "Hunt Evil", "Windows Forensic Analysis", dan kelas SEC555 (SIEM with Tactical Analytics).
- **CyberDefenders** & **BlueTeam Labs Online (BTLO)** — challenge blue-team berbasis Event Log/SIEM nyata (mis. seri Sysmon, brute force, web log).
- **HackTheBox Sherlocks** — investigasi DFIR yang banyak berpusat pada analisis log Windows/Linux.

> **Catatan etika:** Teknik dan command di halaman ini hanya untuk pembelajaran defensif di lingkungan **lab**, sistem milik sendiri, atau challenge CTF resmi seperti LKSN 2026. Menganalisis, mengakses, atau merusak log pada sistem tanpa **izin tertulis** adalah ilegal. Gunakan pengetahuan ini untuk bertahan dan menyelidiki, bukan menyerang.
