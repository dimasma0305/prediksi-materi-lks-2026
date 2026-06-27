# 5. Logging

> Logging adalah "mata dan telinga" dari host Linux yang sudah di-harden: tanpa jejak yang benar, Anda bisa memblokir serangan tetapi tidak akan pernah tahu bahwa serangan terjadi, siapa pelakunya, dan file/syscall apa yang disentuh. Dari sudut pandang penyerang, log adalah bukti yang harus dimatikan atau dihancurkan — itulah sebabnya teknik seperti `rm -rf /var/log/*`, `systemctl stop auditd`, dan menghapus `~/.bash_history` ("Indicator Removal", T1070) menjadi langkah baku setelah kompromi. Di Linux ada **tiga subsistem logging yang berbeda jalur**: `systemd-journald`, `rsyslog`, dan **kernel audit (`auditd`)**. Modul ini mengajarkan cara membuat ketiganya persisten & granular, mengelola rotasinya tanpa kehilangan bukti, dan **men-sentralisasi** log off-host agar tidak bisa dihapus attacker di mesin yang sudah dikuasai. Konsep ini paralel dengan Windows Event Log + WEF/WEC — lihat [../windows/06-logging-auditing.md](../windows/06-logging-auditing.md) untuk padanannya, modul ini tidak mengulang Windows.

> **Distro acuan:** Ubuntu/Debian sebagai utama. Padanan RHEL/Rocky/AlmaLinux diberi catatan bila berbeda (path, nama paket, atau service). **Urutan bagian:** Konsep -> Arsitektur -> journald -> rsyslog -> auditd -> logrotate -> Sentralisasi -> Serangan & Mitigasi -> Checklist -> Lab -> Verifikasi -> Referensi.

## Daftar Isi

1. [Konsep & Tujuan](#1-konsep--tujuan)
2. [Arsitektur Logging Linux (journald vs rsyslog vs auditd)](#2-arsitektur-logging-linux-journald-vs-rsyslog-vs-auditd)
3. [systemd-journald](#3-systemd-journald)
4. [rsyslog](#4-rsyslog)
5. [auditd (Linux Audit Framework)](#5-auditd-linux-audit-framework)
6. [logrotate (dan apa yang TIDAK boleh dirotasi olehnya)](#6-logrotate-dan-apa-yang-tidak-boleh-dirotasi-olehnya)
7. [Sentralisasi Log (off-host)](#7-sentralisasi-log-off-host)
- [Serangan Umum & Mitigasi](#serangan-umum--mitigasi)
- [Hardening Checklist (Modul Ini)](#hardening-checklist-modul-ini)
- [Lab Praktik](#lab-praktik)
- [Perintah Audit/Verifikasi](#perintah-auditverifikasi)
- [Referensi](#referensi)

---

## 1. Konsep & Tujuan

Tujuan logging dalam hardening Linux ada tiga lapis, sama seperti di Windows:

1. **Deteksi (detection)** — menghasilkan event saat aktivitas mencurigakan terjadi (logon SSH gagal beruntun, eksekusi binary SUID, perubahan `/etc/passwd`, load kernel module).
2. **Forensik (forensics)** — menyimpan jejak cukup detail untuk merekonstruksi serangan (siapa, kapan, dari IP mana, syscall/command apa).
3. **Akuntabilitas (accountability)** — mengaitkan tiap aksi sensitif (mis. `sudo`) ke identitas yang bisa dipertanggungjawabkan.

Tiga prinsip yang membedakan logging "ada" dari logging "berguna":

- **Granularitas & persistensi** — journald default sering **volatile** (hilang saat reboot); audit syscall harus dipilih spesifik agar tidak banjir noise.
- **Integritas & sentralisasi** — log yang hanya ada di host adalah log yang bisa dihapus penyerang. **Forward off-host** ke collector/SIEM agar ada salinan di luar jangkauan host yang sudah dikompromikan (analog WEF/WEC Windows).
- **Korelasi** — waktu sinkron (NTP via `chrony`/`systemd-timesyncd`) membuat ratusan ribu baris log dari banyak host menjadi narasi yang bisa dibaca.

> **Catatan pembagian materi.** Modul ini adalah pemilik **journald + rsyslog + auditd + logrotate + sentralisasi**. Hal terkait yang dimiliki modul lain (di sini hanya disinggung lalu menunjuk): hardening **SSH & firewall** -> [04-network-service-security.md](04-network-service-security.md); **PAM/sudo/`sudoers` & `pam_tty_audit`** -> [01-privileged-access-management-pam.md](01-privileged-access-management-pam.md); **SUID/SGID, cron, PATH** yang menjadi *target* aturan audit -> [03-common-linux-misconfigurations.md](03-common-linux-misconfigurations.md). Padanan Windows lengkap -> [../windows/06-logging-auditing.md](../windows/06-logging-auditing.md).

---

## 2. Arsitektur Logging Linux (journald vs rsyslog vs auditd)

**APA.** Berbeda dengan Windows yang punya satu Event Log, Linux modern punya **tiga jalur log yang berdiri sendiri**. Salah memahami jalur = mengira event "hilang" padahal tercatat di subsistem lain.

| Subsistem | Daemon | Sumber data | Penyimpanan | Cara baca |
|-----------|--------|-------------|-------------|-----------|
| **systemd-journald** | `systemd-journald` | syslog API, stdout/stderr unit, kernel (`kmsg`), `_AUDIT` | Biner terstruktur di `/run/log/journal` (volatile) atau `/var/log/journal` (persistent) | `journalctl` |
| **rsyslog** | `rsyslog` | socket `/run/systemd/journal/syslog` atau `imjournal`, `imklog` | Teks di `/var/log/*.log` | `cat`/`grep`/`less`, `tail -f` |
| **kernel audit** | `auditd` | **Audit subsystem kernel** via netlink (jalur terpisah, **bukan** lewat syslog) | Teks di `/var/log/audit/audit.log` | `ausearch`, `aureport` |

**KENAPA jalurnya penting.** Kernel audit (`auditd`) menerima event langsung dari kernel melalui netlink — **tidak melewati journald maupun rsyslog**. Artinya: mematikan rsyslog tidak mematikan audit, dan sebaliknya. Inilah kekuatan `auditd` sebagai kontrol tamper-resistant (lihat §5). Sebaliknya, journald & rsyslog berbagi data: di Ubuntu modern, journald yang menerima syslog lalu meneruskan ke rsyslog (`imjournal`/`ForwardToSyslog`).

**Model facility/severity syslog** (dipakai journald & rsyslog untuk routing): *facility* (`auth`, `authpriv`, `cron`, `daemon`, `kern`, `local0`–`local7`) × *severity* (`emerg`..`debug`, 0–7). Selektor rsyslog ditulis `facility.severity`, mis. `authpriv.*` atau `*.err`.

**Path kunci:** `/etc/systemd/journald.conf` + `/var/log/journal/` (journald) · `/etc/rsyslog.conf`, `/etc/rsyslog.d/` (rsyslog) · `/var/log/auth.log` & `/var/log/syslog` (RHEL: `/var/log/secure` & `/var/log/messages`) · `/etc/audit/auditd.conf`, `/etc/audit/rules.d/*.rules`, `/var/log/audit/audit.log` (auditd) · `/etc/logrotate.conf`, `/etc/logrotate.d/` (logrotate).

---

## 3. systemd-journald

**APA.** `systemd-journald` mengumpulkan log terstruktur dari unit, kernel, dan syslog API ke dalam file biner ber-index dengan metadata kaya (`_PID`, `_UID`, `_SYSTEMD_UNIT`, `_COMM`, dll.).

**KENAPA.** Di banyak instalasi, journald **volatile** — `Storage=auto` hanya menulis ke disk jika `/var/log/journal` *sudah ada*. Tanpa direktori itu, **seluruh log hilang saat reboot** → attacker cukup memicu reboot untuk menghapus bukti. Hardening pertama: paksa **persistent** dan batasi ukuran agar tidak memenuhi disk.

**CARA.** Edit `/etc/systemd/journald.conf` (atau drop-in `/etc/systemd/journald.conf.d/10-hardening.conf`):

| Opsi | Nilai disarankan | Alasan |
|------|------------------|--------|
| `Storage` | `persistent` | Log selamat melewati reboot |
| `Compress` | `yes` | Hemat disk |
| `Seal` | `yes` | Aktifkan Forward Secure Sealing (anti-tamper) bila key sudah dibuat |
| `SystemMaxUse` / `SystemKeepFree` | mis. `1G` / `2G` | Batas total journal & sisa ruang disk |
| `MaxRetentionSec` | mis. `1month` | Retensi minimum waktu |
| `ForwardToSyslog` | `yes` | Teruskan ke rsyslog untuk diparse/diforward |
| `RateLimitIntervalSec` / `RateLimitBurst` | sesuaikan | Cegah log flooding membuang event lama |

```bash
sudo mkdir -p /var/log/journal
sudo systemd-tmpfiles --create --prefix /var/log/journal
sudo systemctl restart systemd-journald

journalctl --disk-usage          # konfirmasi journal kini di /var/log/journal
```

**Forward Secure Sealing (FSS) — integritas anti-tamper.** FSS menandatangani (seal) journal secara berkala dengan *sealing key* di host, sementara *verification key* disimpan **di luar host**. Modifikasi journal yang terjadi sebelum seal berikutnya akan terdeteksi saat verifikasi.

```bash
# Buat key pair (tampilkan verification key untuk disimpan off-host; default interval seal 15m)
sudo journalctl --setup-keys
sudo journalctl --setup-keys --interval=10s   # interval lebih pendek = jendela tamper lebih kecil

# Verifikasi integritas (gunakan verification key yang disimpan off-host)
sudo journalctl --verify
```

Pemakaian harian `journalctl`:

```bash
journalctl -p err -b                                # severity >= err, boot ini saja
journalctl _SYSTEMD_UNIT=ssh.service --since "1 hour ago"
journalctl --vacuum-size=500M                       # pangkas manual berdasar ukuran
journalctl --vacuum-time=2weeks                     # pangkas manual berdasar umur
```

> **RHEL/Rocky:** identik (sama-sama systemd); rsyslog menyerap journal via modul `imjournal`. Tetap set `Storage=persistent` agar journal tidak hanya di RAM.

---

## 4. rsyslog

**APA.** `rsyslog` adalah daemon syslog yang merutekan pesan (berdasarkan `facility.severity`) ke file teks di `/var/log/`, dan — yang terpenting untuk hardening — **meneruskan log ke server jarak jauh** (§7).

**KENAPA.** File teks `/var/log/*.log` adalah yang dibaca paling cepat saat insiden, dan rsyslog adalah mekanisme sentralisasi paling umum di Linux. Dua isu hardening: (1) **permission file log** harus ketat agar non-admin tidak membaca kredensial yang bocor ke log; (2) routing harus mencakup forwarding off-host.

**CARA.** Konfigurasi utama `/etc/rsyslog.conf` + drop-in `/etc/rsyslog.d/*.conf`. Selektor klasik (Ubuntu `/etc/rsyslog.d/50-default.conf`):

```text
auth,authpriv.*                 /var/log/auth.log     # RHEL: authpriv.* -> /var/log/secure
*.*;auth,authpriv.none          -/var/log/syslog      # RHEL umum: /var/log/messages
kern.*                          -/var/log/kern.log
*.emerg                         :omusrmsg:*
```

**Permission default file log (CIS — *Ensure rsyslog default file permissions configured*).** Set agar file baru dibuat dengan mode ketat:

```text
# /etc/rsyslog.d/99-hardening.conf
$FileCreateMode 0640
$umask 0022
```

`$FileCreateMode 0640` memastikan file log baru tidak world-readable (default rsyslog `0644`). Validasi sintaks lalu reload: `sudo rsyslogd -N1 && sudo systemctl restart rsyslog`. Untuk file yang sudah ada (CIS *Ensure permissions on all logfiles are configured*): cari yang longgar dengan `sudo find /var/log -type f -perm /137` lalu `chmod 0640`.

> **RHEL/Rocky:** file utama `/var/log/messages` (umum) dan `/var/log/secure` (auth/authpriv), bukan `/var/log/syslog` & `/var/log/auth.log`. Konsep selektor & `$FileCreateMode` identik.

---

## 5. auditd (Linux Audit Framework)

**APA.** `auditd` adalah userspace daemon yang menerima event dari **audit subsystem di kernel** (lewat netlink) dan menuliskannya ke `/var/log/audit/audit.log`. Aturan (`audit rules`) menentukan **syscall** dan **file watch** mana yang direkam. Inilah padanan paling dekat dari "Advanced Audit Policy + Sysmon" Windows.

**KENAPA melampaui syslog.** auditd berjalan **di luar jalur syslog/journald**, merekam pada level syscall (siapa memanggil `execve`, siapa membuka `/etc/shadow`, siapa memuat kernel module), dan dapat dikunci **immutable** sehingga aturannya tidak bisa diubah tanpa reboot. Ini membuatnya jauh lebih sulit di-bypass daripada log teks biasa.

**Instalasi (perbedaan distro penting):**

```bash
# Ubuntu/Debian — auditd TIDAK terpasang default:
sudo apt install auditd audispd-plugins
# RHEL/Rocky — biasanya sudah terpasang; plugin remote dari paket 'audispd-plugins' (audit-remote)
sudo systemctl enable --now auditd
```

> Sejak **audit 3.x** (Ubuntu 22.04 / RHEL 9), komponen `audispd` **digabung** ke `auditd`. Konfigurasi plugin pindah dari `/etc/audisp/...` lama ke **`/etc/audit/plugins.d/`** dan **`/etc/audit/audisp-remote.conf`** (relevan untuk sentralisasi §7).

**Daemon config — `/etc/audit/auditd.conf` (anchor: CIS seksi *Configure Data Retention*):**

| Parameter | Nilai disarankan | Alasan |
|-----------|------------------|--------|
| `max_log_file` / `num_logs` | mis. `8` (MB) / `5` | Ukuran per file & jumlah file disimpan |
| `max_log_file_action` | `keep_logs` | **Jangan timpa** log lama — rotasi tanpa menghapus bukti |
| `space_left_action` | `email` (atau `exec`) | Peringatan dini saat disk menipis |
| `admin_space_left_action` | `single` (atau `halt`) | Aksi tegas saat disk kritis (jangan diam-diam buang event) |
| `disk_full_action` | `halt`/`single` | Cegah operasi tanpa audit saat disk penuh |
| `log_format` | `ENRICHED` | Resolusi uid/gid disertakan untuk forensik |

**Aturan audit — `/etc/audit/rules.d/*.rules`.** File-file ini digabung oleh **`augenrules --load`** menjadi `/etc/audit/audit.rules` saat boot. Aturan runtime di-set dengan **`auditctl`** (hilang saat reboot — gunakan untuk uji cepat).

> **Wajib:** pada host 64-bit, aturan berbasis syscall harus dipasang untuk **kedua arsitektur** (`-F arch=b64` *dan* `-F arch=b32`), agar proses 32-bit tidak lolos audit.

Contoh subset aturan yang diselaraskan dengan **CIS Benchmark** (file mis. `/etc/audit/rules.d/50-cis.rules`):

```bash
## Perubahan waktu sistem (b64 + b32)
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change
-a always,exit -F arch=b32 -S adjtimex,settimeofday,clock_settime -k time-change

## Perubahan identitas (user/group/password)
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity

## Modifikasi permission file / DAC (b64 + b32)
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat,chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat,chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod

## Eksekusi privileged / SUID  (inventaris SUID -> Modul 03)
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

## Penghapusan/rename file oleh user (b64 + b32)
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=4294967295 -k delete

## Scope sudoers + load/unload kernel module (rootkit/LKM)
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k modules
-w /sbin/modprobe -p x -k modules

## Catatan login/logout & sesi (wtmp/btmp/utmp) — deteksi brute force & manipulasi log login
-w /var/log/wtmp  -p wa -k logins
-w /var/log/btmp  -p wa -k logins
-w /var/run/utmp  -p wa -k session

## Percobaan akses file yang DITOLAK (EACCES/EPERM) — unauthorized access (b64 + b32)
-a always,exit -F arch=b64 -S open,openat,creat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S open,openat,creat,truncate,ftruncate -F exit=-EPERM  -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S open,openat,creat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S open,openat,creat,truncate,ftruncate -F exit=-EPERM  -F auid>=1000 -F auid!=4294967295 -k access

## Mount filesystem oleh user (exfil via media eksternal / bypass nosuid) (b64 + b32)
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts

## Perubahan Mandatory Access Control — Ubuntu: AppArmor (build acuan); RHEL: SELinux
-w /etc/apparmor/   -p wa -k MAC-policy
-w /etc/apparmor.d/ -p wa -k MAC-policy
# RHEL: -w /etc/selinux/ -p wa -k MAC-policy  ;  -w /usr/share/selinux/ -p wa -k MAC-policy

## Konfigurasi audit dikunci immutable — HARUS aturan PALING AKHIR
-e 2
```

Penjelasan flag kunci:

- `-w <path> -p wa -k <key>` = *watch* file, picu pada **w**rite/**a**ttribute change, beri tag `key`; `-a always,exit -S <syscall>` = audit syscall saat exit.
- `-F auid>=1000 -F auid!=4294967295` = hanya user nyata (UID >= 1000), abaikan daemon & `auid` unset (`-1`).
- **`-e 2`** = konfigurasi **immutable**; aturan tak bisa diubah/ditambah sampai **reboot**. Wajib jadi baris terakhir (CIS *Ensure the audit configuration is immutable*) — letakkan di file bernomor tertinggi, mis. `99-finalize.rules`.

Muat & verifikasi:

```bash
sudo augenrules --load        # gabung rules.d -> audit.rules lalu load
sudo augenrules --check       # cek apakah ada perubahan belum di-load
sudo auditctl -l              # daftar aturan aktif
sudo auditctl -s              # status: cari 'enabled 2' (immutable) & 'lost 0'
```

Pencarian & laporan: `ausearch -k <key> --start today` (cari per-key), `ausearch -m USER_LOGIN` (event logon), `aureport --auth --summary` (ringkasan auth), `aureport -x --summary` (ringkasan eksekusi per-executable).

> **Cross-ref PAM.** Untuk merekam **seluruh perintah** yang diketik dalam sesi (TTY) per-user, gunakan `pam_tty_audit` melalui PAM — itu domain [01-privileged-access-management-pam.md](01-privileged-access-management-pam.md); di sini cukup tahu output-nya juga mengalir ke `auditd` (event `TTY`).

---

## 6. logrotate (dan apa yang TIDAK boleh dirotasi olehnya)

**APA.** `logrotate` merotasi, mengompres, dan menghapus **file log teks** (mis. milik rsyslog) agar tidak memenuhi disk. Dijalankan via cron/timer (`/etc/cron.daily/logrotate` atau `logrotate.timer`).

**KENAPA hati-hati.** Rotasi yang terlalu agresif = bukti tergulir keluar sebelum sempat dibaca (anti-forensik gratis untuk attacker yang mem-flood log). Sebaliknya, rotasi yang salah pada subsistem yang **mengelola rotasinya sendiri** bisa merusak integritas.

**CARA.** `/etc/logrotate.conf` (global) + `/etc/logrotate.d/<paket>` (per-aplikasi). Directive penting:

| Directive | Fungsi |
|-----------|--------|
| `daily`/`weekly`/`monthly` + `rotate N` | Frekuensi rotasi & jumlah generasi disimpan |
| `compress` / `delaycompress` | Kompres arsip (delay: kompres pada rotasi berikutnya) |
| `missingok` / `notifempty` | Aman bila file tak ada / jangan rotasi bila kosong |
| `create 0640 root adm` | Buat file baru dengan **permission ketat** + owner/group |
| `maxsize` / `dateext` | Rotasi paksa per-ukuran / nama arsip pakai tanggal |
| `postrotate ... endscript` | Kirim sinyal (mis. `systemctl reload rsyslog`) |

```bash
sudo logrotate -d /etc/logrotate.conf    # dry-run (debug), tidak mengubah apa pun
sudo logrotate -f /etc/logrotate.conf    # paksa rotasi sekarang (uji)
```

> **JANGAN rotasi dengan logrotate:** (1) **`/var/log/audit/audit.log`** — auditd merotasi sendiri (`max_log_file`/`max_log_file_action=keep_logs`/`num_logs`); logrotate bisa membuatnya kehilangan handle file & event. (2) **journald** (`/var/log/journal`) — dikelola `SystemMaxUse`/`journalctl --vacuum-*`, dan format biner tak cocok untuk logrotate. logrotate hanya untuk **log teks rsyslog** (`/var/log/*.log`).

---

## 7. Sentralisasi Log (off-host)

**APA.** Mengirim salinan log dari banyak host ke satu **collector** terpusat (rsyslog server / SIEM). Padanan langsung dari **WEF/WEC** di Windows — lihat [../windows/06-logging-auditing.md](../windows/06-logging-auditing.md).

**KENAPA — ini kontrol integritas, bukan sekadar kenyamanan.** Jika attacker meng-compromise sebuah host, ia bisa `rm`/menimpa `/var/log/*` untuk menghapus jejak. Tetapi salinan yang **sudah ter-forward** ke collector berada **di luar jangkauannya**. Forwarding + alert adalah mitigasi inti terhadap anti-forensik. Untuk reliabilitas dan kerahasiaan: pakai **TCP/RELP** (bukan UDP) dan **TLS**.

**Sisi pengirim — rsyslog forwarding (`/etc/rsyslog.d/60-forward.conf`):**

```text
# UDP rapuh: *.*  @collector.lab.local:514   (hindari untuk produksi)
# TCP + disk-assisted queue (tidak blocking saat collector down):
*.* action(type="omfwd" target="collector.lab.local" port="514" protocol="tcp"
           action.resumeRetryCount="-1"
           queue.type="linkedList" queue.size="10000"
           queue.spoolDirectory="/var/spool/rsyslog" queue.fileName="fwdq")
```

Sintaks: **`@host`** = UDP, **`@@host`** = TCP (legacy). Untuk **TLS** pakai stream driver `gtls`/`ossl` dengan `StreamDriverMode="1"`, `StreamDriverAuthMode="x509/name"`, plus sertifikat CA. Untuk **delivery 100% reliable** ber-ACK, gunakan **RELP** (`omrelp` pengirim, `imrelp` collector).

**Sisi collector — aktifkan input & pisahkan per-host:**

```text
# /etc/rsyslog.d/10-collector.conf  (di server collector)
module(load="imtcp")
input(type="imtcp" port="514")     # RELP: module(load="imrelp") + input imrelp
template(name="PerHost" type="string" string="/var/log/remote/%HOSTNAME%/%PROGRAMNAME%.log")
*.* ?PerHost                       # simpan per-host untuk korelasi
```

Buka port collector hanya di firewall collector (-> [04-network-service-security.md](04-network-service-security.md)).

**Sentralisasi auditd (audit 3.x).** Gunakan plugin **`au-remote`** untuk mengirim event audit ke `audisp-remote` di collector:

```text
# /etc/audit/plugins.d/au-remote.conf  -> active = yes ; direction = out ;
#                                          path = /sbin/audisp-remote ; type = always
# /etc/audit/audisp-remote.conf        -> remote_server = collector.lab.local ;
#                                          port = 60 ; transport = tcp   (krb5 = terenkripsi)
```

Di collector, `auditd` menerima lewat `tcp_listen_port`. Alternatif journald-native: `systemd-journal-remote`/`systemd-journal-upload` untuk transport journal terstruktur.

> **Kunci forensik:** korelasi lintas host hanya bekerja bila jam sinkron. Pastikan `chrony`/`systemd-timesyncd` aktif dan menunjuk NTP tepercaya (cek `chronyc tracking` / `timedatectl`).

---

## Serangan Umum & Mitigasi

Kaitkan tiap teknik ke **MITRE ATT&CK** dan kontrol di modul ini.

| Teknik penyerang | MITRE ATT&CK | Jejak/Indikator | Mitigasi (modul ini) |
|------------------|--------------|-----------------|----------------------|
| Hapus log teks (`rm -rf /var/log/*`, truncate) | **T1070.002** (Clear Linux or Mac System Logs) | File log hilang/terpotong, gap waktu | Forward off-host (§7); audit watch pada `/var/log`; permission ketat |
| Hapus `~/.bash_history`, `unset HISTFILE`, `HISTSIZE=0` | **T1070.003** (Clear Command History) | History kosong/tak konsisten | `pam_tty_audit` (-> Modul 01); auditd `execve`; shipping off-host |
| Stop/disable auditd/rsyslog atau ubah audit rules untuk membutakan deteksi | **T1562.001** (Impair Defenses) | `auditctl -s` enabled=0; service inactive; `auditctl -l` beda dari baseline; heartbeat hilang di collector | **`-e 2` immutable** (perubahan butuh reboot, dan reboot tercatat); alert hilangnya feed; pantau `systemd` unit |
| Flooding log agar event lama tergulir keluar | **T1562.001 / T1499** | Lonjakan volume, rotasi cepat | `RateLimit*` journald; `max_log_file_action=keep_logs`; ukuran memadai + forwarding |
| Reboot untuk menghapus journald volatile | **T1070** | Journal kosong pasca-reboot | `Storage=persistent` (§3) |
| Manipulasi waktu untuk merusak korelasi/timestomp | **T1070.006** (Timestomp) / T1099 | Offset NTP, urutan event aneh | Audit `time-change`; NTP terkunci; FSS seal interval pendek |
| Edit langsung file log untuk menyembunyikan baris | **T1070** | Verifikasi gagal | **journald FSS** (`--verify`); salinan off-host immutable |
| Tambah user/SUID untuk persistence | **T1136 / T1548.001** | auditd `identity`, `perm_mod`, `privileged` | Watch `/etc/passwd|shadow|sudoers`; audit SUID exec (target -> Modul 03) |
| Muat rootkit LKM | **T1547.006** (Kernel Modules and Extensions) | auditd key `modules` | Audit `init_module`/`finit_module`; watch `insmod`/`modprobe` |

---

## Hardening Checklist (Modul Ini)

- [ ] journald **persistent**: `/var/log/journal` ada, `Storage=persistent`, ukuran dibatasi (`SystemMaxUse`).
- [ ] journald **FSS** aktif (`journalctl --setup-keys`, `Seal=yes`); verification key disimpan off-host.
- [ ] rsyslog `$FileCreateMode 0640`; permission `/var/log/*` ketat (bukan world-readable).
- [ ] `auditd` terpasang & enabled (Ubuntu: `apt install auditd audispd-plugins`).
- [ ] `auditd.conf`: `max_log_file_action=keep_logs`, `admin_space_left_action` tegas, `disk_full_action` aman.
- [ ] Aturan audit CIS terpasang (identity, perm_mod, access EACCES/EPERM, privileged/SUID, delete, scope/sudoers, modules, time-change, **login/session `wtmp`/`btmp`/`utmp`, `mounts`, `MAC-policy`**).
- [ ] Aturan syscall mencakup **`-F arch=b64` dan `-F arch=b32`** di host 64-bit.
- [ ] Konfigurasi audit **immutable**: `-e 2` sebagai aturan terakhir; `auditctl -s` menampilkan `enabled 2`.
- [ ] logrotate mengelola log teks rsyslog dengan `create 0640` — **TIDAK** menyentuh `audit.log` maupun journald.
- [ ] **Sentralisasi**: rsyslog forward via **TCP/RELP (+TLS)** dengan queue disk-assisted, dan auditd via plugin `au-remote` (`/etc/audit/plugins.d/au-remote.conf`), ke collector.
- [ ] Waktu sinkron (NTP via `chrony`/`timesyncd`); `chronyc tracking`/`timedatectl` terverifikasi.
- [ ] Port collector hanya terbuka di sisi collector (-> Modul 04); alert pada hilangnya feed/heartbeat.

---

## Lab Praktik

**Topologi:** `target01` (Ubuntu Server 22.04) + `collector01` (Ubuntu Server, penerima log). Jalankan di `target01` kecuali disebut lain.

### Langkah 1 — Jadikan journald persistent + FSS

**Lakukan:**
```bash
sudo sed -i 's/^#\?Storage=.*/Storage=persistent/' /etc/systemd/journald.conf
sudo mkdir -p /var/log/journal && sudo systemctl restart systemd-journald
sudo journalctl --setup-keys --interval=10s
```
**Konfirmasi dengan:** `journalctl --disk-usage` menunjuk `/var/log/journal`; `sudo journalctl --verify` selesai tanpa `FAIL`.

### Langkah 2 — Pasang & kunci auditd

**Lakukan:**
```bash
sudo apt update && sudo apt install -y auditd audispd-plugins
sudo tee /etc/audit/rules.d/50-lks.rules >/dev/null <<'EOF'
-w /etc/passwd -p wa -k identity
-w /etc/sudoers -p wa -k scope
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k modules
-a always,exit -F arch=b32 -S init_module,finit_module,delete_module -k modules
EOF
echo '-e 2' | sudo tee /etc/audit/rules.d/99-finalize.rules
sudo augenrules --load
```
**Konfirmasi dengan:** `sudo auditctl -s` menampilkan `enabled 2` (immutable); `sudo auditctl -l` memuat aturan di atas.

### Langkah 3 — Picu & temukan event identity

**Lakukan:** `sudo touch /etc/passwd` (update mtime memicu watch `-p wa`).
**Konfirmasi dengan:** `sudo ausearch -k identity --start recent | tail -n 20` menampilkan record `type=PATH name="/etc/passwd"` ber-`key="identity"` dengan `auid` pelaku.

### Langkah 4 — Picu logon SSH gagal

**Lakukan:** dari host lain, `ssh baduser@target01` dengan password salah 3x.
**Konfirmasi dengan:** `sudo journalctl _SYSTEMD_UNIT=ssh.service --since "5 min ago" | grep -i "failed password"` dan `sudo aureport --auth --summary` menampilkan percobaan gagal (Ubuntu juga di `/var/log/auth.log`; RHEL `/var/log/secure`).

### Langkah 5 — Forward ke collector & buktikan integritas off-host

**5a. Siapkan penerima dulu (di `collector01`)** — aktifkan input TCP & pisah per-host (lihat §7), lalu restart:
```bash
sudo tee /etc/rsyslog.d/10-collector.conf >/dev/null <<'EOF'
module(load="imtcp")
input(type="imtcp" port="514")
template(name="PerHost" type="string" string="/var/log/remote/%HOSTNAME%/%PROGRAMNAME%.log")
*.* ?PerHost
EOF
sudo systemctl restart rsyslog
sudo ss -tlnp | grep ':514'                # → rsyslog LISTEN di 514 (penerima siap)
```

**5b. Forward dari `target01` lalu simulasikan attacker menghapus bukti lokal:**
```bash
echo '*.* @@collector01.lab.local:514' | sudo tee /etc/rsyslog.d/60-forward.conf
sudo systemctl restart rsyslog
logger -p auth.notice "LKS-TEST marker dari target01"
sudo truncate -s 0 /var/log/syslog        # attacker "menghapus" bukti lokal (hanya lab)
```

**Konfirmasi dengan:**
```bash
# di target01: marker HILANG dari log lokal
grep LKS-TEST /var/log/syslog                                  # → tidak ada hasil
# di collector01: salinan TETAP ADA di luar jangkauan attacker
sudo grep -r LKS-TEST /var/log/remote/                         # → baris marker muncul (path per-host)
```
Marker `LKS-TEST` hilang dari `target01` tetapi salinannya tetap di `collector01` — inilah alasan forwarding off-host.

---

## Perintah Audit/Verifikasi

Perintah berikut dijamin bisa dijalankan untuk membuktikan setting aktif; output yang diharapkan disebutkan.

```bash
# 1. Status audit -> cari 'enabled 2' (immutable) dan 'lost 0'
sudo auditctl -s

# 2. Daftar aturan audit aktif -> menampilkan watch & syscall yang dipasang
sudo auditctl -l

# 3. Aturan belum di-load? -> 'No change' artinya rules.d == aktif
sudo augenrules --check

# 4. auditd hidup -> 'active'
systemctl is-active auditd

# 5. journald persistent -> path di bawah /var/log/journal, ukuran > 0
journalctl --disk-usage

# 6. Integritas journal (FSS) -> 'PASS' (butuh verification key bila Seal=yes)
sudo journalctl --verify

# 7. Sintaks rsyslog valid -> 'End of config validation run'
sudo rsyslogd -N1

# 8. File log tidak world-readable -> mode 0640/0600 (kolom -rw-r-----)
ls -l /var/log/auth.log /var/log/syslog 2>/dev/null

# 9. Sinkronisasi waktu -> 'System clock synchronized: yes'
timedatectl

# 10. Ringkasan autentikasi dari audit -> jumlah login sukses/gagal
sudo aureport --auth --summary
```

> Catatan: pada RHEL/Rocky ganti `/var/log/auth.log`→`/var/log/secure`, `/var/log/syslog`→`/var/log/messages`. Bila `journalctl --verify` meminta key, itu efek `Seal=yes` — gunakan verification key yang Anda simpan off-host.

---

## Referensi

- **CIS Benchmark — Ubuntu Linux 22.04 LTS** & **CIS Red Hat Enterprise Linux 9**: seksi *Logging and Auditing* (Configure `journald`, Configure `rsyslog`, Configure `auditd`/Data Retention, *Ensure the audit configuration is immutable*, *Ensure rsyslog default file permissions configured*). Anchor tunggal untuk nilai/aturan; bila versi baseline berbeda, ikuti baseline yang dipakai juri dan dokumentasikan.
- **systemd-journald:** `man journald.conf` (Storage, Seal, SystemMaxUse), `man journalctl` (`--setup-keys`, `--verify`, `--vacuum-*`) — Forward Secure Sealing. **rsyslog:** modul `omfwd`/`omrelp`/`imrelp` (forwarding TCP & RELP), TLS driver `gtls`/`ossl`, `$FileCreateMode`. **logrotate:** `man logrotate` (`create`, `maxsize`, `rotate`, `postrotate`).
- **Linux Audit:** `man auditd.conf`, `man auditctl`, `man audit.rules`, `man augenrules`, `man ausearch`, `man aureport`; Red Hat *Security Guide — Defining Audit Rules*. Catatan migrasi audit 3.x (`audispd` → `auditd`, `/etc/audit/plugins.d/`).
- **MITRE ATT&CK:** T1070.002 (Clear Linux/Mac System Logs), T1070.003 (Clear Command History), T1070.006 (Timestomp), T1562.001 (Impair Defenses), T1547.006 (Kernel Modules), T1548.001 (SUID/Setuid).
- **Padanan Windows:** [../windows/06-logging-auditing.md](../windows/06-logging-auditing.md) (Advanced Audit Policy, Sysmon, WEF/WEC) — konsep, tidak diulang di sini.

---

> **Catatan etika.** Seluruh teknik di halaman ini — termasuk menghapus/men-truncate log, mematikan service audit, dan memodifikasi konfigurasi — ditujukan **hanya** untuk lingkungan **lab milik sendiri, sistem dengan izin tertulis, atau arena CTF/LKS resmi**. Bagian "Serangan Umum" dipaparkan agar Anda bisa **mendeteksi dan bertahan**, bukan untuk menyerang sistem orang lain. Menghapus atau memanipulasi log pada sistem tanpa otorisasi adalah tindakan ilegal. Gunakan pengetahuan ini untuk membangun pertahanan.
