# 2. Dangerous/Exposed Services

> Modul ini menutup permukaan serang di lapisan **layanan (service)** Linux: protokol legacy yang mengirim kredensial polos (telnet, FTP, rsh), datastore yang menerima koneksi tanpa autentikasi (Redis, Memcached, MongoDB), kredensial bawaan yang tidak pernah diganti (SNMP `public`, panel admin `admin/admin`), dan **banner** yang membocorkan versi software ke penyerang. Filosofinya satu: *attack surface reduction* — setiap port yang mendengarkan dan setiap versi yang terpampang adalah jalan masuk. Layanan yang mati tidak bisa dieksploitasi; kredensial default yang diganti tidak bisa ditebak; banner yang dibersihkan tidak memandu serangan.

## Daftar Isi

1. [Konsep & Tujuan](#1-konsep--tujuan)
2. [Inventarisasi: Temukan Service & Port yang Terbuka](#2-inventarisasi-temukan-service--port-yang-terbuka)
3. [Layanan Legacy & Cleartext yang Berbahaya](#3-layanan-legacy--cleartext-yang-berbahaya)
4. [Datastore & Service Tanpa Autentikasi / Default Credential](#4-datastore--service-tanpa-autentikasi--default-credential)
5. [Banner & Information Disclosure](#5-banner--information-disclosure)
6. [Mematikan Service dengan Benar (disable / mask / purge / inetd)](#6-mematikan-service-dengan-benar-disable--mask--purge--inetd)
- [Serangan Umum & Mitigasi](#serangan-umum--mitigasi)
- [Hardening Checklist (Modul Ini)](#hardening-checklist-modul-ini)
- [Lab Praktik](#lab-praktik)
- [Perintah Audit/Verifikasi](#perintah-auditverifikasi)
- [Referensi](#referensi)

---

## 1. Konsep & Tujuan

Tiga prinsip yang dipegang modul ini:

1. **Minimal service footprint.** Hanya jalankan layanan yang benar-benar dibutuhkan oleh peran host. Service yang tidak terpakai bukan netral — ia menambah surface, butuh patch, dan sering dikonfigurasi dengan default lemah. Ini paralel langsung dengan filosofi "nonaktifkan service & fitur tak terpakai" di Windows ([../windows/04-network-service-security.md](../windows/04-network-service-security.md) §7).
2. **Tidak ada cleartext, tidak ada anonim.** Protokol yang mengirim kredensial atau data tanpa enkripsi (telnet, FTP, rsh, SNMPv1/v2c, VNC polos) dan service yang menerima koneksi tanpa autentikasi (Redis/Memcached default) harus dimatikan atau diganti varian terautentikasi + terenkripsi.
3. **Tidak ada default credential.** Setiap akun/community/token bawaan adalah kredensial publik — terdokumentasi di internet. SNMP `public`, Tomcat Manager `admin/admin`, database tanpa password, dan panel default wajib diganti atau dimatikan (MITRE **T1078.001 — Default Accounts**).

**Sudut pandang penyerang.** Rantai serangan boot2root hampir selalu dimulai dengan **enumerasi service** (`nmap`, banner grabbing → T1046/T1595): cari port terbuka, baca banner untuk menebak versi dan CVE, lalu coba default credential atau exploit publik (T1190/T1210). Mengeraskan lapisan ini memutus langkah pertama itu — penyerang tidak menemukan apa-apa untuk diserang.

**Kepemilikan topik (agar tidak tumpang tindih).** Modul ini fokus pada *menemukan dan mematikan/mengunci layanan berbahaya per-service*. Desain firewall host (nftables/ufw) dan SSH hardening penuh dimiliki **Linux 04** ([04-network-service-security.md](04-network-service-security.md)) — di sini hanya disinggung sebagai pelengkap. Password/sudo/root-login dan akun sistem dimiliki **Linux 01** ([01-privileged-access-management-pam.md](01-privileged-access-management-pam.md)). SUID/capabilities/cron dimiliki **Linux 03** ([03-common-linux-misconfigurations.md](03-common-linux-misconfigurations.md)). auditd & logging dimiliki **Linux 05** ([05-logging.md](05-logging.md)).

> **Distro.** Contoh utama memakai Ubuntu/Debian (`apt`, `systemd`). Padanan RHEL/Rocky/AlmaLinux diberi catatan bila berbeda (umumnya `dnf remove` menggantikan `apt purge`, dan beberapa nama unit berbeda, mis. `ssh.service` → `sshd.service`).

---

## 2. Inventarisasi: Temukan Service & Port yang Terbuka

**APA:** Sebelum mengeraskan, petakan dulu apa yang sebenarnya berjalan dan mendengarkan. Ini fase *discovery* — dari dalam host (otoritatif) dan dari luar (perspektif penyerang).

**KENAPA:** Kamu tidak bisa menutup apa yang tidak kamu tahu terbuka. Banyak service "tersembunyi" di socket-activation atau di-bind ke `0.0.0.0` tanpa disadari. Membandingkan tampak-dari-dalam vs tampak-dari-luar mengungkap service yang terekspos ke jaringan.

**CARA — dari dalam host:**

```bash
# Socket yang LISTEN + proses + port (paling penting). -t TCP, -u UDP, -l listen, -p proses, -n numerik
ss -tulpn

# Padanan legacy (paket net-tools, mungkin perlu diinstal)
netstat -tulpn

# Service systemd yang sedang berjalan
systemctl list-units --type=service --state=running

# Socket yang dikelola systemd (socket activation - service bisa "mati" tapi tetap bisa diaktifkan)
systemctl list-sockets

# Service yang AKTIF saat boot (enabled) - termasuk yang belum tentu jalan sekarang
systemctl list-unit-files --type=service --state=enabled
```

**CARA — dari luar (perspektif penyerang, jalankan dari host lain di lab):**

```bash
# Service & version detection + banner (inti recon penyerang → T1046)
nmap -sV -sC -p- 10.10.0.10

# Banner grabbing manual (versi service bocor di sini)
nc -nv 10.10.0.10 21          # FTP banner
nmap -sV --script=banner 10.10.0.10
```

**Yang dicari:** port yang di-bind ke `0.0.0.0`/`*`/`[::]` (terekspos ke semua interface) padahal seharusnya hanya `127.0.0.1`; service legacy (§3); datastore (§4); dan versi software yang bocor lewat banner (§5). Triase: untuk tiap port LISTEN tanyakan "apakah peran host ini benar-benar membutuhkannya?" — jika tidak, matikan (§6); jika ya, kunci (§3/§4) dan batasi binding/firewall (Linux 04).

---

## 3. Layanan Legacy & Cleartext yang Berbahaya

**APA:** Sekelompok protokol warisan UNIX yang dirancang sebelum enkripsi jadi standar. Mereka mengirim kredensial dan data dalam **teks polos** dan/atau mempercayai host berdasarkan IP/hostname yang mudah dipalsukan.

**KENAPA:** Siapa pun yang bisa menyadap jaringan (T1040) menangkap username + password telnet/FTP/rsh apa adanya. rsh/rlogin/rexec percaya `.rhosts`/`hosts.equiv` — autentikasi bisa di-bypass dengan spoofing. Tidak ada alasan operasional memakainya di sistem modern; penggantinya sudah ada (SSH, SFTP/SCP, FTPS).

**CARA:** Hapus paket **client** maupun **server**. Menghapus lebih kuat daripada sekadar `disable` (tidak bisa diaktifkan ulang tanpa instal). CIS Benchmark mengatur ini di seksi **"Service Clients"** dan **"Special Purpose Services"**.

| Layanan | Port | Risiko | Pengganti | CIS control (judul) |
|---------|------|--------|-----------|---------------------|
| **telnet** (server+client) | 23/tcp | Kredensial & sesi cleartext (T1040) | SSH | *Ensure telnet client / server is not installed* |
| **FTP** (vsftpd/proftpd; client) | 21/tcp | Kredensial cleartext, bounce attack | SFTP/SCP, FTPS | *Ensure FTP server / ftp client is not installed* |
| **rsh / rlogin / rexec** | 514/513/512 | Trust `.rhosts`, cleartext, spoofable | SSH | *Ensure rsh client / server is not installed* |
| **TFTP** | 69/udp | Tanpa auth, baca/tulis file | SCP, HTTPS | *Ensure tftp server is not installed* |
| **NIS / ypbind / ypserv** | RPC | Distribusi password hash via jaringan tak aman | LDAP+TLS, SSSD | *Ensure NIS client / server is not installed* |
| **talk / ntalk** | 517/518 | Service usang, tak perlu | — | *Ensure talk client is not installed* |
| **finger** | 79/tcp | Enumerasi user (recon, T1087) | — | *Ensure finger is not installed* |
| **rpcbind / portmapper** | 111 | Enumerasi RPC, vektor amplifikasi DDoS | (matikan bila tak ada NFS) | *Ensure rpcbind is not installed/enabled unless required* |
| **NFS server** | 2049 | Export world-readable, `no_root_squash` → root remote | Kunci `exports` + Kerberos | *Ensure NFS is not installed unless required* |

> **Catatan numbering CIS:** judul kontrol di atas stabil lintas versi, tetapi **nomornya berubah antar versi benchmark** (mis. seksi *Service Clients* adalah 2.2.x di CIS Ubuntu 22.04 v2.0.0, berbeda di versi lain). Selalu cocokkan ke judul, bukan nomor.

```bash
# Ubuntu/Debian — hapus paket client & server legacy sekaligus
sudo apt purge -y telnet telnetd inetutils-telnet \
  vsftpd ftp tnftp tftpd-hpa \
  rsh-client rsh-redone-client rsh-server \
  talk talkd nis finger

# RHEL/Rocky/Alma — padanan
sudo dnf remove -y telnet telnet-server \
  vsftpd ftp tftp tftp-server \
  rsh rsh-server ypbind ypserv talk finger

# NFS/rpcbind: jika host BUKAN file server, hapus
sudo apt purge -y nfs-kernel-server rpcbind     # Debian/Ubuntu
sudo dnf remove -y nfs-utils rpcbind            # RHEL
```

> **Jika service tetap dibutuhkan** (mis. NFS untuk berbagi data antar host lab): jangan hapus, tapi kunci. Untuk NFS, pastikan `/etc/exports` tidak memakai `no_root_squash` dan dibatasi ke subnet spesifik (mis. `/srv/share 10.10.0.0/24(ro,root_squash,sync)`), lalu batasi rpcbind/2049 via firewall → **Linux 04**. Mekanisme privesc `no_root_squash` (mount → SUID root) berikut mini-lab attack→hardening dibahas tuntas di [`03-common-linux-misconfigurations.md`](03-common-linux-misconfigurations.md) §7.

---

## 4. Datastore & Service Tanpa Autentikasi / Default Credential

**APA:** Layanan yang, pada konfigurasi tertentu, **menerima koneksi tanpa autentikasi** atau dikirim dengan **kredensial bawaan** yang sudah diketahui publik. Ini adalah salah satu temuan paling umum di boot2root dan insiden nyata (Redis terbuka → RCE; MongoDB terbuka → data dump/ransom).

**KENAPA:** Penyerang yang bisa menjangkau port hanya perlu `redis-cli`/`mongosh`/browser untuk membaca, mengubah, atau menghapus seluruh data — tanpa password (T1078.001 untuk default cred, T1530/T1213 untuk akses data). Beberapa, seperti Memcached/SNMP via UDP, juga menjadi **vektor amplifikasi DDoS** (T1498.002).

**CARA — pola umum untuk SEMUA datastore:** (1) **bind ke `127.0.0.1`** kecuali benar-benar perlu remote; (2) **aktifkan autentikasi**; (3) **ganti kredensial default**; (4) batasi sisanya via firewall (Linux 04).

| Service | Port | Masalah | Kunci utama (file/opsi) |
|---------|------|---------|--------------------------|
| **Redis** | 6379 | Tanpa auth → `CONFIG SET` → write file → RCE | `requirepass` + `bind 127.0.0.1` + `protected-mode yes` |
| **Memcached** | 11211 | Tanpa auth; UDP = amplifikasi DDoS | `-l 127.0.0.1` + `-U 0` (matikan UDP) + SASL |
| **MongoDB** | 27017 | `authorization` off → akses penuh | `security.authorization: enabled` + `bindIp 127.0.0.1` |
| **Elasticsearch** | 9200 | xpack security off (versi lama) → query/CRUD bebas | aktifkan xpack security + `network.host` lokal |
| **MySQL/MariaDB** | 3306 | root tanpa password, bind global | `mysql_secure_installation` + `bind-address=127.0.0.1` |
| **PostgreSQL** | 5432 | `trust` di `pg_hba.conf`, `listen_addresses='*'` | `scram-sha-256` di `pg_hba.conf` + `listen_addresses='localhost'` |
| **SNMP** | 161/udp | Community `public`/`private`, cleartext v1/v2c | SNMPv3 (authPriv) atau hapus paket |
| **VNC** | 5900+ | Password lemah/8-char, cleartext | Tunnel via SSH + `localhost` only |
| **X11** | 6000+ | X server `tcp` terbuka → keylog/screencap | `-nolisten tcp` (default modern) |

### 4.1 Redis (kasus paling kritis)

**KENAPA spesial:** Redis terbuka tanpa auth memungkinkan `CONFIG SET dir`/`dbfilename` untuk menulis file arbitrer (cron, `authorized_keys`, webshell) → **RCE penuh**. Ini exploit boot2root klasik.

```bash
# /etc/redis/redis.conf
bind 127.0.0.1 -::1            # JANGAN 0.0.0.0
protected-mode yes            # default ON sejak 3.2 — biarkan ON
requirepass <password-kuat-panjang>   # autentikasi wajib
# Redis 6+ : pakai ACL untuk granular, dan rename/disable perintah berbahaya:
rename-command CONFIG ""
rename-command FLUSHALL ""
sudo systemctl restart redis-server   # RHEL: redis
```

> **Delta versi (akurat):** Sejak Redis **3.2**, `protected-mode` default **on** — bila bind ke semua interface tanpa password, Redis hanya melayani loopback. Sejak Redis **7.0** (PR #9034), mengubah `bind` ke nilai non-default tidak lagi otomatis mematikan `protected-mode`. Artinya Redis modern **tidak** "wide open by default"; risiko muncul ketika admin meng-uncomment `bind 0.0.0.0` / mematikan protected-mode tanpa men-set `requirepass`. Tetap set `requirepass` secara eksplisit.

### 4.2 SNMP (default community = kredensial publik)

**KENAPA:** SNMPv1/v2c memakai *community string* sebagai password yang dikirim **cleartext**. Default `public` (read) dan `private` (write) terdokumentasi di mana-mana; dengan `public` saja penyerang men-dump seluruh konfigurasi sistem via `snmpwalk` (recon mendalam, T1592). UDP juga vektor amplifikasi.

```bash
# Bila SNMP tidak dibutuhkan — hapus (rekomendasi default)
sudo apt purge -y snmpd        # RHEL: dnf remove -y net-snmp

# Bila dibutuhkan: WAJIB SNMPv3 (authPriv), JANGAN v1/v2c, JANGAN community 'public'
# /etc/snmp/snmpd.conf — hapus baris 'rocommunity public' / 'com2sec ... public'
# createUser idealnya ditaruh di file persisten (Debian: /var/lib/snmp/snmpd.conf) saat snmpd berhenti,
# agar passphrase cleartext dibuang & diganti kunci terlokalisasi setelah dibaca sekali.
createUser monitor SHA "<authpass>" AES "<privpass>"
rouser monitor priv                # level keamanan authPriv = kata kunci 'priv' (net-snmp tak punya 'authpriv')
agentAddress udp:127.0.0.1:161     # batasi binding; default Debian sudah localhost
```

> CIS: *Ensure SNMP server is not installed unless required* dan, bila dipakai, *Ensure SNMP is configured to use SNMPv3*.

### 4.3 Database & service lain (ringkas)

```bash
# MySQL/MariaDB: set root password, hapus anonim/test db, batasi binding
sudo mysql_secure_installation
echo -e "[mysqld]\nbind-address=127.0.0.1" | sudo tee /etc/mysql/mysql.conf.d/zz-bind.cnf

# Memcached: bind localhost + matikan UDP (vektor amplifikasi)
# /etc/memcached.conf  → tambahkan/ubah:
#   -l 127.0.0.1
#   -U 0
sudo systemctl restart memcached
```

> **Delta versi:** **MongoDB** sejak 3.6 default `bindIp: 127.0.0.1` (tidak terekspos), tetapi `authorization` **tetap perlu diaktifkan manual**. **Elasticsearch** mengaktifkan xpack security **secara default sejak 8.0**; cluster 7.x dan lebih lama sering tanpa auth — verifikasi versi sebelum mengasumsikan aman. **Memcached** menonaktifkan listener UDP secara default sejak 1.5.6 — tetap set `-U 0` untuk jaminan.

### 4.4 Panel & Aplikasi dengan Default Credential (Tomcat, dll.)

**KENAPA:** Panel manajemen aplikasi sering dikirim dengan akun bawaan yang terdokumentasi publik. Yang paling sering muncul di boot2root adalah **Apache Tomcat Manager** (`/manager/html`): bila kredensialnya masih default, penyerang login lalu **deploy file `.war` berisi webshell/JSP reverse shell → RCE sebagai user Tomcat** (T1078.001 → T1190). Kredensial Tomcat tersimpan di **`conf/tomcat-users.xml`** (`$CATALINA_HOME`, mis. `/etc/tomcat9/tomcat-users.xml` atau `/opt/tomcat/conf/tomcat-users.xml`).

**CARA — kunci Tomcat Manager.** (1) hapus/ganti user default & beri password kuat; (2) batasi role hanya yang perlu; (3) batasi akses Manager per-IP; (4) hapus webapp `manager`/`host-manager` bila tak dipakai.

```xml
<!-- conf/tomcat-users.xml — JANGAN biarkan user default (tomcat/tomcat, admin/admin, role1/role1) -->
<tomcat-users>
  <role rolename="manager-gui"/>
  <user username="svc-deploy" password="P4ssphrase-Panjang-Acak" roles="manager-gui"/>
</tomcat-users>
```

```xml
<!-- Batasi Manager hanya dari subnet management — webapps/manager/META-INF/context.xml -->
<Context antiResourceLocking="false" privileged="true">
  <Valve className="org.apache.catalina.valves.RemoteAddrValve"
         allow="127\.\d+\.\d+\.\d+|::1|10\.10\.0\.\d+"/>
</Context>
```

```bash
# Bila Manager/Host-Manager tidak dibutuhkan sama sekali — hapus webapp-nya:
sudo rm -rf "$CATALINA_HOME"/webapps/manager "$CATALINA_HOME"/webapps/host-manager
sudo systemctl restart tomcat9         # nama unit bisa 'tomcat'/'tomcat9'/'tomcat10'
```

**Tabel default-credential umum (cek & ganti semuanya).** Setiap baris di bawah = kredensial publik; perlakukan seperti "tanpa password" sampai diganti.

| Service / Panel | Default credential | Lokasi / path | Remediasi |
|---|---|---|---|
| **Tomcat Manager** | `tomcat:tomcat`, `admin:admin`, `role1:role1` | `/manager/html`, `conf/tomcat-users.xml` | ganti/hapus user, `RemoteAddrValve`, atau hapus webapp |
| **SNMP** | community `public` / `private` | `/etc/snmp/snmpd.conf` | SNMPv3 authPriv (§4.2) atau hapus |
| **MySQL/MariaDB** | `root:` (kosong) | — | `mysql_secure_installation` (§4.3) |
| **PostgreSQL** | `postgres` + `trust` | `pg_hba.conf` | `scram-sha-256`, bind lokal |
| **Jenkins** | wizard awal / token admin | `initialAdminPassword` | aktifkan security realm + matrix authz |
| **Grafana** | `admin:admin` | `/login` | paksa ganti saat first-login |
| **Apache ActiveMQ** | `admin:admin` | web console `/admin` | `conf/jetty-realm.properties` |
| **phpMyAdmin** | mengikuti `root:` MySQL kosong | `/phpmyadmin` | password DB kuat + batasi akses |
| **Dell iDRAC / HP iLO** | `root:calvin` / `Administrator:<label>` | panel BMC | ganti, isolasi ke jaringan management |
| **Redis / MongoDB** | tanpa auth | — | `requirepass` (§4.1) / `authorization` (§4.3) |

> Saat enumerasi boot2root: cek setiap panel web yang ditemukan (Tomcat, Jenkins, Grafana, phpMyAdmin) terhadap tabel ini **sebelum** mencari exploit — default credential jauh lebih cepat daripada CVE.

---

## 5. Banner & Information Disclosure

**APA:** *Banner* adalah string identitas yang dikirim service saat koneksi (SSH version string, FTP `220` greeting, HTTP `Server:` header, login banner `/etc/issue`). Ia membocorkan OS, distro, dan versi software.

**KENAPA:** Banner memandu penyerang langsung ke exploit yang cocok (T1595/T1592 → T1190). "OpenSSH 7.2p2 Ubuntu" memberi tahu CVE mana yang dicoba. Memangkas banner **bukan** kontrol keamanan utama (ini *security by obscurity*, mirip "ganti port RDP" di [../windows/04-network-service-security.md](../windows/04-network-service-security.md) §4.4) — service yang di-patch tetap aman walau versinya terlihat. Tetapi memangkas banner mengurangi recon gratis, dan **login banner peringatan hukum** sering diwajibkan CIS/standar kepatuhan.

**CARA:**

| Permukaan | File / Opsi | Nilai aman |
|-----------|-------------|------------|
| **Login banner lokal** | `/etc/issue` | Teks peringatan; **hapus** escape `\m \r \s \v` (bocorkan kernel/OS/arch) |
| **Login banner remote** | `/etc/issue.net` | Sama; dirujuk SSH `Banner /etc/issue.net` |
| **MOTD** | `/etc/motd`, `/etc/update-motd.d/*` | Hapus skrip yang menampilkan versi OS |
| **SSH version** | `sshd_config` → `DebianBanner no` | Sembunyikan suffix distro (`-Ubuntu-...`) dari banner |
| **Apache** | `ServerTokens Prod` + `ServerSignature Off` | Hilangkan versi di header & halaman error |
| **nginx** | `server_tokens off;` | Hilangkan versi di header & error |
| **Postfix (SMTP)** | `smtpd_banner = $myhostname ESMTP` | Tanpa versi/OS |
| **vsftpd (jika dipakai)** | `ftpd_banner=Authorized access only` | Banner kustom, sembunyikan versi |

```bash
# Login banner peringatan (CIS: warning banner configured properly) + buang info OS
printf 'Authorized access only. Activity is monitored.\n' | sudo tee /etc/issue /etc/issue.net
# Pastikan tak ada escape \m \r \s \v yang membocorkan info
grep -E '\\[mrsv]' /etc/issue /etc/issue.net   # tidak boleh ada output

# SSH: sembunyikan suffix distro dari version string + tampilkan banner
echo 'DebianBanner no' | sudo tee /etc/ssh/sshd_config.d/10-no-banner.conf
echo 'Banner /etc/issue.net' | sudo tee -a /etc/ssh/sshd_config.d/10-no-banner.conf
sudo sshd -t && sudo systemctl reload ssh    # RHEL: systemctl reload sshd

# Apache — Debian: /etc/apache2/conf-available/security.conf | RHEL: /etc/httpd/conf/httpd.conf
ServerTokens Prod
ServerSignature Off

# nginx — di blok http {} pada /etc/nginx/nginx.conf
server_tokens off;
```

> **Jujur soal batasan:** `DebianBanner no` hanya menyembunyikan bagian distro; OpenSSH tetap mengiklankan versi protokol/daemon-nya dan tidak bisa disembunyikan total tanpa rekompilasi. Jangan andalkan ini sebagai pertahanan — andalkan patching. Hardening SSH selengkapnya (algoritma, auth, `PermitRootLogin`) dimiliki **Linux 04**.

---

## 6. Mematikan Service dengan Benar (disable / mask / purge / inetd)

**APA:** Empat tingkat "mematikan" service, dari paling ringan ke paling kuat. Pilih sesuai apakah service mungkin perlu dihidupkan lagi.

| Tingkat | Perintah | Efek | Kapan |
|---------|----------|------|-------|
| **stop** | `systemctl stop <svc>` | Mati sekarang, **hidup lagi saat boot** | Sementara saja |
| **disable** | `systemctl disable --now <svc>` | Mati + tidak start saat boot | Service mungkin perlu lagi |
| **mask** | `systemctl mask <svc>` | Link ke `/dev/null`, **tidak bisa di-start** (manual/dependency) | Pastikan benar-benar tak boleh jalan |
| **purge** | `apt purge <pkg>` / `dnf remove` | Hapus binari sepenuhnya | Service tak akan pernah dipakai |

**KENAPA `disable --now` vs `stop`:** `stop` saja menyesatkan — service akan hidup kembali setelah reboot dan kontrolmu "hilang". `disable --now` memastikan mati sekarang *dan* di boot berikutnya. `mask` lebih kuat: mencegah service dinyalakan ulang oleh dependency atau socket activation (mis. cegah `cups` aktif lewat `cups.socket`).

```bash
# Matikan + cegah start saat boot (paling umum)
sudo systemctl disable --now cups avahi-daemon

# Mask bila harus dijamin tak jalan (termasuk via socket)
sudo systemctl mask cups.socket

# Awas socket activation: service "mati" tapi socket-nya masih mengaktifkan on-demand
systemctl list-sockets
```

**Kandidat umum untuk dimatikan di server** (sesuaikan peran):

| Service | Rekomendasi | Alasan |
|---------|-------------|--------|
| `cups` / `cups.socket` | disable/mask di server | Print service, surface tak perlu (paralel PrintNightmare di Windows 04 §7) |
| `avahi-daemon` | disable bila tak butuh mDNS | mDNS/zeroconf = recon & poisoning surface |
| `rpcbind` | disable bila tak ada NFS/RPC | Enumerasi & amplifikasi (§3) |
| `bluetooth` | disable di server | Tak relevan, menambah surface |
| `xinetd` / `openbsd-inetd` | purge bila tak dipakai | Super-server legacy pembungkus telnet/rsh/tftp |

**Legacy super-server (inetd/xinetd).** Service warisan kadang tidak punya unit systemd sendiri — mereka diaktifkan on-demand oleh `inetd`/`xinetd`. Periksa `/etc/inetd.conf` dan `/etc/xinetd.d/*`: baris yang tidak di-comment untuk telnet/rsh/tftp/finger berarti service itu aktif. Comment baris-nya atau, lebih baik, **purge** paket inetd/xinetd-nya.

```bash
# Cek isi konfigurasi super-server legacy (idealnya tidak terpasang sama sekali)
grep -vE '^\s*#|^\s*$' /etc/inetd.conf 2>/dev/null
ls /etc/xinetd.d/ 2>/dev/null
sudo apt purge -y xinetd openbsd-inetd     # RHEL: dnf remove -y xinetd
```

---

## Serangan Umum & Mitigasi

| Serangan | Teknik | MITRE | Mitigasi di modul ini |
|----------|--------|-------|------------------------|
| **Service discovery / banner grab** | `nmap -sV`, `nc` baca versi → cari CVE | T1046 / T1595 | §5 pangkas banner, §6 matikan service tak perlu |
| **Cleartext credential sniffing** | Sadap telnet/FTP/SNMP v1v2c/VNC polos | T1040 | §3 hapus legacy, §4 SNMPv3, §5 tunnel VNC via SSH |
| **Default/anonymous credential** | SNMP `public`, Tomcat `admin/admin`, DB tanpa password | T1078.001 | §4 ganti/aktifkan auth, hapus akun default |
| **Exposed datastore → RCE** | Redis tanpa auth → `CONFIG SET` tulis `authorized_keys`/cron | T1190 / T1210 | §4.1 `requirepass`+`bind 127.0.0.1`+rename-command |
| **Exposed datastore → data theft/ransom** | MongoDB/ES terbuka → dump/hapus | T1530 / T1213 | §4 aktifkan authorization + bind lokal |
| **Trust-based auth bypass** | rsh/rlogin `.rhosts`, host spoof | T1078 / T1021 | §3 hapus rsh/rlogin/rexec |
| **DDoS amplification** | Memcached/SNMP/DNS UDP reflection | T1498.002 | §4 Memcached `-U 0`, §3 rpcbind, bind lokal |
| **User enumeration (recon)** | `finger`, null SMB, NIS yp | T1087 / T1135 | §3 hapus finger/NIS |
| **Exploit of public service** | Versi rentan terexpos (mis. vsftpd backdoor, ProFTPD) | T1190 / T1210 | §2 inventaris, §3/§6 hapus, patch (Linux 04) |

---

## Hardening Checklist (Modul Ini)

- [ ] **Inventaris dibuat:** `ss -tulpn` dari dalam dibandingkan `nmap -sV` dari luar; setiap port LISTEN punya pembenaran peran.
- [ ] **Tidak ada port di-bind `0.0.0.0`** untuk service yang seharusnya lokal (datastore, X11, dsb).
- [ ] **telnet (server+client)** dihapus (`apt purge telnet telnetd`).
- [ ] **FTP server & client** dihapus / diganti SFTP (kecuali FTPS yang dibutuhkan).
- [ ] **rsh / rlogin / rexec** dihapus (server & client).
- [ ] **TFTP, NIS/yp, talk, finger** dihapus.
- [ ] **rpcbind / NFS** dihapus bila bukan file server; bila dipakai, `exports` di-`root_squash` + dibatasi subnet.
- [ ] **Redis:** `requirepass` di-set, `bind 127.0.0.1`, `protected-mode yes`, perintah berbahaya di-rename.
- [ ] **MongoDB/MySQL/PostgreSQL/ES:** autentikasi aktif, bind ke localhost, kredensial default diganti.
- [ ] **Panel/aplikasi** (Tomcat Manager, Jenkins, Grafana, phpMyAdmin) **tidak** memakai default credential; Tomcat `tomcat-users.xml` diganti (tanpa user `tomcat`/`admin`/`role1`) & Manager dibatasi per-IP atau dihapus.
- [ ] **SNMP:** dihapus, atau SNMPv3 authPriv; **tidak ada** community `public`/`private`.
- [ ] **Memcached:** `-l 127.0.0.1` dan UDP dimatikan (`-U 0`).
- [ ] **VNC/X11:** tidak listen TCP terbuka; VNC hanya via SSH tunnel.
- [ ] **Login banner** `/etc/issue` & `/etc/issue.net` di-set, **tanpa** escape `\m \r \s \v`.
- [ ] **Banner versi dipangkas:** SSH `DebianBanner no`, Apache `ServerTokens Prod`/`ServerSignature Off`, nginx `server_tokens off`.
- [ ] **Service tak terpakai** (cups/avahi/bluetooth) `disable --now` atau `mask`; cek `list-sockets`.
- [ ] **inetd/xinetd** tidak terpasang (atau baris legacy di-comment).

---

## Lab Praktik

**Topologi:** `TARGET` (Ubuntu 22.04 server), `ATTACKER` (Kali/Linux untuk `nmap`, `redis-cli`, `snmpwalk`). Subnet lab `10.10.0.0/24`. **Snapshot dulu** sebelum mengubah apa pun (service uptime ikut dinilai).

### Lab 1 — Temukan & matikan layanan legacy

1. **Lakukan** scan dari `ATTACKER`: `nmap -sV -p- 10.10.0.10` → catat port telnet(23)/FTP(21)/finger(79) yang `open`.
2. **Lakukan** di `TARGET`: `sudo apt purge -y telnet telnetd vsftpd ftp finger`.
3. **Konfirmasi dengan:** ulangi `nmap -sV -p21,23,79 10.10.0.10` → port kini `closed`/`filtered`; dan `ss -tulpn | grep -E ':21|:23|:79'` tidak ada output.

### Lab 2 — Redis terbuka → kunci

1. **Lakukan (pra-hardening):** dari `ATTACKER`, `redis-cli -h 10.10.0.10 ping` → balasan `PONG` tanpa password = exposed.
2. **Lakukan** di `TARGET`: set `bind 127.0.0.1`, `requirepass <pass>` di `/etc/redis/redis.conf`, lalu `sudo systemctl restart redis-server`.
3. **Konfirmasi dengan:** dari `ATTACKER` `redis-cli -h 10.10.0.10 ping` → **gagal connect / NOAUTH**; dari `TARGET` `redis-cli -a <pass> ping` → `PONG`.

### Lab 3 — SNMP default community

1. **Lakukan (pra):** dari `ATTACKER`, `snmpwalk -v2c -c public 10.10.0.10` → bila tumpah data sistem = community default aktif.
2. **Lakukan** di `TARGET`: hapus baris `rocommunity public` di `/etc/snmp/snmpd.conf` (atau `apt purge snmpd`), restart.
3. **Konfirmasi dengan:** ulangi `snmpwalk -v2c -c public ...` → timeout / no response.

### Lab 4 — Banner hygiene

1. **Lakukan:** set `/etc/issue.net` + `DebianBanner no` (lihat §5), `sudo sshd -t && sudo systemctl reload ssh`.
2. **Konfirmasi dengan:** dari `ATTACKER` `nc 10.10.0.10 22` → version string tidak lagi memuat suffix `-Ubuntu-...`; `ssh -v` menampilkan banner peringatan.

---

## Perintah Audit/Verifikasi

```bash
# Port LISTEN aktual + proses (bukti hardening "menempel")
ss -tulpn
# Pastikan datastore TIDAK listen di 0.0.0.0 (harapkan hanya 127.0.0.1/::1)
ss -tlnp | grep -E ':6379|:27017|:11211|:9200|:3306|:5432'

# Paket legacy harus TIDAK terpasang (harapkan kosong / "not installed")
dpkg -l | grep -E '^ii\s+(telnet|telnetd|rsh-server|rsh-client|vsftpd|tftpd|nis|finger|talk)'   # Debian/Ubuntu
rpm -qa | grep -E 'telnet|rsh|vsftpd|tftp-server|ypserv|finger|talk'                            # RHEL

# Service tak terpakai harus disabled/masked (harapkan disabled atau masked)
systemctl is-enabled cups avahi-daemon rpcbind bluetooth xinetd 2>/dev/null

# Redis: auth & bind aktif (harapkan ada requirepass, bind 127.0.0.1, protected-mode yes)
sudo grep -E '^\s*(bind|requirepass|protected-mode)' /etc/redis/redis.conf

# SNMP: tidak ada community 'public'/'private' (harapkan kosong)
sudo grep -E 'rocommunity|rwcommunity|com2sec' /etc/snmp/snmpd.conf 2>/dev/null | grep -Ei 'public|private'

# Tomcat: tidak ada user/password default di tomcat-users.xml (harapkan kosong)
sudo grep -RiE 'username="(tomcat|admin|role1)"|password="(tomcat|admin|s3cret|role1|changeit)"' \
  /etc/tomcat*/tomcat-users.xml /opt/tomcat*/conf/tomcat-users.xml 2>/dev/null

# Banner: tidak ada escape yang membocorkan OS (harapkan kosong)
grep -E '\\[mrsv]' /etc/issue /etc/issue.net
# SSH DebianBanner (harapkan: DebianBanner no)
sudo sshd -T 2>/dev/null | grep -i debianbanner
# Web server version disclosure
apachectl -t -D DUMP_RUN_CFG 2>/dev/null | grep -i servertokens   # atau cek config
grep -ri 'server_tokens' /etc/nginx/ 2>/dev/null

# Inetd/xinetd legacy aktif? (harapkan tidak terpasang / tidak ada baris aktif)
grep -vE '^\s*#|^\s*$' /etc/inetd.conf 2>/dev/null; ls /etc/xinetd.d/ 2>/dev/null
```

---

## Referensi

- **CIS Benchmarks** — *CIS Ubuntu Linux 22.04 LTS Benchmark* & *CIS Red Hat Enterprise Linux Benchmark*, seksi **"Service Clients"** (telnet/rsh/NIS/talk/ldap/ftp client tidak terpasang) dan **"Special Purpose Services"** (FTP/telnet/TFTP/NIS/rsh/SNMP/HTTP/DNS server tidak terpasang kecuali dibutuhkan; SNMPv3; warning banner). Cocokkan ke **judul** kontrol, bukan nomor (nomor berubah antar versi).
- **Redis** — *Redis security* (redis.io): `protected-mode` (default on sejak 3.2), `requirepass`, ACL, `bind`, `rename-command`.
- **MongoDB** — *Security Checklist* / *Enable Access Control* (`security.authorization`, `bindIp`).
- **Elastic** — *Security in Elasticsearch* (xpack security on by default sejak 8.0).
- **net-snmp** — `snmpd.conf(5)`, SNMPv3 USM (`createUser`, `rouser <user> priv`).
- **Apache Tomcat** — *Manager App How-To* & *Security Considerations*: `conf/tomcat-users.xml` (role `manager-gui`), `RemoteAddrValve` (`org.apache.catalina.valves.RemoteAddrValve`) untuk membatasi akses Manager per-IP; hapus webapp `manager`/`host-manager` bila tak dipakai.
- **OpenSSH** — `sshd_config(5)` (`Banner`, `DebianBanner` di Debian/Ubuntu), Ubuntu Security docs "Version banners".
- **Apache `mod_status`/core** — `ServerTokens`, `ServerSignature`; **nginx** — `server_tokens`.
- **MITRE ATT&CK** — T1046 (Network Service Discovery), T1595/T1592 (Active Scanning / Gather Host Info), T1040 (Network Sniffing), T1078.001 (Default Accounts), T1190 (Exploit Public-Facing App), T1210 (Exploitation of Remote Services), T1498.002 (Reflection Amplification DoS), T1087/T1135 (Account/Network Share Discovery).
- **Lintas modul:** [01-privileged-access-management-pam.md](01-privileged-access-management-pam.md) (akun/sudo/root, rotasi kredensial), [03-common-linux-misconfigurations.md](03-common-linux-misconfigurations.md) (SUID/capabilities/cron), [04-network-service-security.md](04-network-service-security.md) (SSH hardening penuh, firewall nftables/ufw, service binding), [05-logging.md](05-logging.md) (auditd, deteksi), serta padanan Windows [../windows/04-network-service-security.md](../windows/04-network-service-security.md) (nonaktifkan service tak terpakai, protokol legacy).

> **Catatan etika.** Materi ini untuk **lab pribadi, lingkungan kompetisi LKSN/CTF resmi, atau sistem dengan izin tertulis eksplisit**. Tool ofensif (`nmap`, `redis-cli`, `snmpwalk`) di Lab Praktik dipakai untuk **menguji pertahanan sistem sendiri**, bukan menyerang milik orang lain. Memindai atau mengakses layanan tanpa izin adalah pelanggaran hukum.
