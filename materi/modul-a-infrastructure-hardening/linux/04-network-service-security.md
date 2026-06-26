# 4. Network Service Security

> Modul ini mengeraskan permukaan serang jaringan pada host Linux: SSH sebagai pintu administrasi utama, host-based firewall (nftables / ufw / firewalld), dan service binding agar daemon hanya mendengar di antarmuka yang seharusnya. Setiap port yang `LISTEN` di `0.0.0.0` dan setiap opsi SSH yang longgar adalah jalan masuk: brute force kredensial (Hydra/Medusa), Redis/Memcached tanpa autentikasi yang terekspos ke internet, atau downgrade cipher SSH. Tujuannya: **kecilkan attack surface jaringan sampai hanya yang benar-benar dibutuhkan yang boleh berbicara — dan hanya dari sumber yang diizinkan.**
>
> Build acuan: **Ubuntu/Debian** (utama). Padanan **RHEL/Rocky/AlmaLinux** diberi catatan bila berbeda (umumnya `firewalld`, nama service `sshd`, dan SELinux). Nilai di-anchor ke **CIS Ubuntu Linux 22.04 LTS Benchmark** dan **CIS Red Hat Enterprise Linux 9 Benchmark** plus best practice.

## Daftar Isi

1. [Konsep & Tujuan](#1-konsep--tujuan)
2. [SSH Hardening — sshd_config](#2-ssh-hardening--sshd_config)
3. [SSH — Autentikasi Kunci, Crypto, & 2FA](#3-ssh--autentikasi-kunci-crypto--2fa)
4. [Host Firewall — nftables](#4-host-firewall--nftables)
5. [Host Firewall — ufw (Ubuntu) & firewalld (RHEL)](#5-host-firewall--ufw-ubuntu--firewalld-rhel)
6. [Service Binding & Attack Surface Reduction](#6-service-binding--attack-surface-reduction)
7. [Brute Force Defense — fail2ban](#7-brute-force-defense--fail2ban)
- [Serangan Umum & Mitigasi](#serangan-umum--mitigasi)
- [Hardening Checklist (Modul Ini)](#hardening-checklist-modul-ini)
- [Lab Praktik](#lab-praktik)
- [Perintah Audit/Verifikasi](#perintah-auditverifikasi)
- [Referensi](#referensi)

---

## 1. Konsep & Tujuan

Filosofi modul ini sama dengan padanan Windows-nya ([../windows/04-network-service-security.md](../windows/04-network-service-security.md)): **attack surface reduction** di lapisan jaringan, hanya saja dengan mekanisme Linux. Tiga prinsip:

1. **Default-deny inbound.** Firewall menolak semua koneksi masuk kecuali yang dibuka eksplisit, dengan scope alamat sumber seketat mungkin (mis. SSH hanya dari subnet management).
2. **Bind seminimal mungkin.** Daemon yang hanya dipakai lokal harus `LISTEN` di `127.0.0.1`/`::1`, bukan `0.0.0.0`. Service yang tidak `LISTEN` ke jaringan tidak bisa diserang dari jaringan, bahkan jika firewall salah konfigurasi (defense-in-depth).
3. **Hanya protokol & kredensial yang kuat.** SSH dengan autentikasi kunci (bukan password), cipher/MAC/KEX modern, root login dimatikan, dan brute force diredam (`MaxAuthTries`, fail2ban, rate-limit firewall).

**Mengapa penting dari sudut pandang penyerang:** pada skenario attack-defense, fase awal hampir selalu jaringan — `nmap` untuk discovery (T1046), brute force SSH yang terekspos (T1110), atau mengeksploitasi service tanpa autentikasi yang nyasar bind ke `0.0.0.0` (T1190). Mengeraskan lapisan ini memutus rantai serangan sebelum lawan mendapat foothold.

**Batas kepemilikan antar-modul (jangan diulang di sini):**

| Topik | Modul pemilik |
|-------|---------------|
| `sudoers`, `su`, PAM stack, kebijakan login root interaktif | [01-privileged-access-management-pam.md](01-privileged-access-management-pam.md) |
| Inventaris service berbahaya, banner, default credential | [02-dangerous-exposed-services.md](02-dangerous-exposed-services.md) |
| SUID/SGID, permission, cron, PATH, `capabilities` | [03-common-linux-misconfigurations.md](03-common-linux-misconfigurations.md) |
| `auditd`, `journald`/`rsyslog`, sentralisasi log auth | [05-logging.md](05-logging.md) |

Modul ini fokus pada **transport jaringan**: SSH config, firewall L3/L4, dan binding socket.

---

## 2. SSH Hardening — sshd_config

**File utama:** `/etc/ssh/sshd_config`. Pada Ubuntu/Debian modern terdapat baris `Include /etc/ssh/sshd_config.d/*.conf` di awal file, sehingga konfigurasi dipecah ke drop-in.

> **Gotcha penting (Ubuntu cloud image):** `sshd` memakai **nilai PERTAMA** yang ditemui untuk tiap keyword. Karena `Include` berada di awal `sshd_config`, file drop-in diproses lebih dulu, dan dibaca berurutan secara **leksikal**. Cloud image Ubuntu sering punya `/etc/ssh/sshd_config.d/50-cloud-init.conf` berisi `PasswordAuthentication yes` yang akan **menang** atas setting Anda di `sshd_config`. Solusi: taruh hardening di file yang diproses lebih dulu (mis. `00-hardening.conf`) atau sunting/hapus drop-in cloud-init.

**APA → KENAPA → CARA.** Buat `/etc/ssh/sshd_config.d/00-hardening.conf`:

```bash
sudo tee /etc/ssh/sshd_config.d/00-hardening.conf >/dev/null <<'EOF'
# --- Akses & autentikasi ---
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
HostbasedAuthentication no
IgnoreRhosts yes
PubkeyAuthentication yes
UsePAM yes
AuthenticationMethods publickey

# --- Anti brute force / DoS ---
MaxAuthTries 4
MaxStartups 10:30:60
MaxSessions 10
LoginGraceTime 60

# --- Idle session timeout ---
ClientAliveInterval 300
ClientAliveCountMax 3

# --- Kurangi surface tunneling/forwarding ---
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitTunnel no
GatewayPorts no
PermitUserEnvironment no

# --- Allowlist akun + logging + banner + binding (lihat §6) ---
AllowGroups sshusers
LogLevel VERBOSE
Banner /etc/issue.net
# ListenAddress 10.10.0.10   # bind ke IP mgmt; AddressFamily inet bila tanpa IPv6
EOF
```

Nilai dan alasan (anchor CIS):

| Keyword | Nilai (rekomendasi) | KENAPA | CIS |
|---------|---------------------|--------|-----|
| `PermitRootLogin` | `no` | Cegah login root langsung; paksa user + `sudo` (Modul 01). Default OpenSSH `prohibit-password` masih mengizinkan key root | 5.x: `no` |
| `PasswordAuthentication` | `no` | Mematikan brute force password sepenuhnya; paksa kunci | ✔ |
| `KbdInteractiveAuthentication` | `no` | Nama modern dari `ChallengeResponseAuthentication` (alias usang). Tutup jalur interaktif/password lewat PAM | ✔ |
| `PermitEmptyPasswords` | `no` | Larang akun berpassword kosong login | ✔ |
| `MaxAuthTries` | `4` | Batasi percobaan auth per koneksi (anti brute force, T1110) | ✔ (≤ 4) |
| `MaxStartups` | `10:30:60` | Throttle koneksi pra-auth yang belum login (anti flood) | ✔ |
| `LoginGraceTime` | `60` | Tutup koneksi yang menggantung sebelum auth selesai (anti-flood pra-auth). Catatan CVE-2024-6387 *regreSSHion*: nilai pendek **tidak** memitigasi race signal handler (SIGALRM tetap dipicu saat grace time habis, justru lebih sering); workaround non-patch yang didokumentasikan Qualys adalah `LoginGraceTime 0` (mematikan trigger SIGALRM, dengan tradeoff resource exhaustion/DoS) — **patch OpenSSH tetap solusi utama** | ✔ (≤ 60) |
| `ClientAlive*` | idle timeout aktif | Putus sesi idle (mis. interval 300 + count 3). Catatan: antar-versi CIS nilainya berbeda (mis. 300/0 atau 15/3) — yang penting idle timeout menyala sesuai kebijakan | ✔ |
| `X11Forwarding` | `no` | X11 forwarding menambah surface & rentan penyalahgunaan display | ✔ |
| `AllowTcpForwarding` / `PermitTunnel` | `no` | Cegah SSH dipakai sebagai pivot/tunnel (T1572) ke segmen internal — kecuali memang dibutuhkan | best practice |
| `LogLevel` | `VERBOSE` | Catat fingerprint kunci yang dipakai login (forensik & deteksi, Modul 05) | ✔ |
| `AllowGroups`/`AllowUsers` | allowlist | Hanya akun di grup `sshusers` yang boleh SSH (kurangi identitas untuk lateral movement, T1021.004) | best practice |

**Terapkan dengan aman (anti-lockout):**

```bash
sudo sshd -t                       # validasi sintaks; HARUS tanpa output/error
sudo sshd -T | grep -i passwordauth  # cek nilai efektif sebelum reload
# Ubuntu: service bernama 'ssh'; RHEL/Rocky: 'sshd'
sudo systemctl reload ssh          # RHEL: sudo systemctl reload sshd
```

> **WAJIB saat lomba:** JANGAN tutup sesi SSH yang sedang aktif sampai Anda berhasil membuka sesi BARU dengan konfigurasi baru. Salah konfigurasi (mis. `AllowGroups` tanpa user Anda di dalamnya) bisa mengunci diri sendiri. `sshd -t` + sesi cadangan adalah pengaman.

> **RHEL/Rocky:** mengubah **port** SSH membutuhkan label SELinux: `sudo semanage port -a -t ssh_port_t -p tcp 2222`. Tanpa ini, `sshd` gagal bind ke port non-22. (Catatan: ganti port = *security by obscurity*, bukan kontrol nyata — scanner menemukannya dalam hitungan menit, T1046. Tetap andalkan key auth + firewall scope.)

---

## 3. SSH — Autentikasi Kunci, Crypto, & 2FA

### 3.1 Autentikasi berbasis kunci

**APA:** Ganti password dengan key pair (Ed25519). **KENAPA:** menutup brute force password total dan memberi autentikasi kriptografis. **CARA:**

```bash
# Di mesin klien/admin
ssh-keygen -t ed25519 -a 100 -C "admin@mgmt"
ssh-copy-id -i ~/.ssh/id_ed25519.pub user@target   # menulis ke ~/.ssh/authorized_keys

# Permission WAJIB benar di server (kalau salah, sshd menolak kunci):
chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys
```

### 3.2 Hardening algoritma (KEX / Cipher / MAC)

**APA:** Batasi hanya algoritma modern; matikan yang lemah/legacy. **KENAPA:** cegah downgrade & AiTM (T1557) serta cipher rapuh. **CARA** — tambahkan ke `00-hardening.conf`:

```bash
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com
HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256
```

Verifikasi dengan tool eksternal **`ssh-audit`** (pihak ketiga): `ssh-audit target` akan menandai algoritma lemah (mis. `diffie-hellman-group1-sha1`, `hmac-md5`, `3des-cbc`). Lihat juga panduan Mozilla OpenSSH.

### 3.3 Two-Factor Authentication (opsional, high-sec)

Untuk lapisan tambahan, gabungkan kunci + TOTP via PAM (`libpam-google-authenticator`): set `AuthenticationMethods publickey,keyboard-interactive` dan `KbdInteractiveAuthentication yes` (agar prompt TOTP muncul). Konfigurasi PAM stack & modul `pam_google_authenticator.so` adalah ranah **Modul 01 (PAM)** — di sini cukup tahu bahwa `AuthenticationMethods` di `sshd` yang merangkai faktor.

---

## 4. Host Firewall — nftables

`nftables` adalah framework filter paket modern di kernel Linux (pengganti `iptables`). Pada Ubuntu/Debian, konfigurasi persisten ada di **`/etc/nftables.conf`** dan dimuat oleh `nftables.service`.

**APA:** Terapkan kebijakan **default-drop inbound** dengan allowlist eksplisit + scope sumber. **KENAPA:** semua port tertutup kecuali yang dibuka; SSH dibatasi ke subnet management saja (membatasi T1021/T1046). **CARA:**

```bash
sudo tee /etc/nftables.conf >/dev/null <<'EOF'
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;

    iif "lo" accept                                   # loopback
    ct state established,related accept               # balasan koneksi keluar
    ct state invalid drop                             # buang paket invalid

    ip protocol icmp icmp type echo-request limit rate 5/second accept
    ip6 nexthdr ipv6-icmp accept                      # ICMPv6 (wajib utk IPv6)

    # SSH HANYA dari subnet management:
    tcp dport 22 ip saddr 10.10.0.0/24 ct state new accept

    # Layanan publik (contoh web):
    tcp dport { 80, 443 } ct state new accept

    # Log lalu drop sisanya (policy drop sudah menjatuhkan, log opsional):
    limit rate 10/minute log prefix "nft-input-drop: " level info
  }

  chain forward { type filter hook forward priority 0; policy drop; }
  chain output  { type filter hook output  priority 0; policy accept; }
}
EOF

sudo nft -f /etc/nftables.conf          # muat & uji segera
sudo systemctl enable --now nftables    # persisten saat boot
sudo nft list ruleset                   # verifikasi
```

Catatan:
- Family **`inet`** menangani IPv4 + IPv6 sekaligus. Jangan lupa rule IPv6 (atau matikan IPv6 bila tak dipakai) — port yang aman di IPv4 bisa terbuka di IPv6.
- **Jangan campur** nftables yang dikelola manual dengan `ufw`/`firewalld` aktif di host yang sama; pilih satu manajer agar rule tidak saling tabrak.
- Uji rule baru di sesi yang masih punya koneksi aktif; salah aturan SSH bisa mengunci akses.

---

## 5. Host Firewall — ufw (Ubuntu) & firewalld (RHEL)

Bila tidak mengelola nftables mentah, gunakan frontend. Keduanya pada akhirnya memprogram backend nftables.

### 5.1 ufw (Uncomplicated Firewall — Ubuntu/Debian)

ufw terpasang default di Ubuntu Server namun **inactive**. **CARA:**

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw limit 22/tcp                                  # rate-limit SSH (anti brute force)
sudo ufw allow from 10.10.0.0/24 to any port 22 proto tcp   # atau batasi ke subnet mgmt
sudo ufw allow 443/tcp
sudo ufw logging on
sudo ufw enable
sudo ufw status verbose                                # verifikasi
```

> `ufw limit` memblokir IP sumber yang membuka **6+ koneksi dalam 30 detik** ke port itu — peredam brute force ringan (T1110). Untuk SSH yang sensitif, lebih baik kombinasikan `allow from <subnet>` (scope) daripada `limit` saja.

### 5.2 firewalld (RHEL/Rocky/AlmaLinux)

RHEL-family memakai **`firewalld`** (zone-based, backend nftables). `ufw` umumnya tidak dipakai di sini. **CARA:**

```bash
sudo firewall-cmd --set-default-zone=drop                     # default tolak semua
# Izinkan SSH hanya dari subnet management via rich rule:
sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="10.10.0.0/24" service name="ssh" accept'
sudo firewall-cmd --permanent --add-service=https             # contoh layanan publik
sudo firewall-cmd --reload
sudo firewall-cmd --list-all                                  # verifikasi zone aktif
```

| Konsep | Ubuntu/Debian | RHEL/Rocky |
|--------|---------------|------------|
| Frontend default | `ufw` (inactive) / nftables | `firewalld` |
| File nftables mentah | `/etc/nftables.conf` | (firewalld kelola sendiri) |
| Default policy | `ufw default deny incoming` | zone `drop`/`public` |
| Scope sumber | `ufw allow from <cidr>` | `rich-rule ... source address=` |

---

## 6. Service Binding & Attack Surface Reduction

**APA:** Pastikan tiap daemon hanya `LISTEN` di antarmuka yang perlu — `127.0.0.1`/`::1` untuk service lokal, atau IP antarmuka management spesifik. **KENAPA:** banyak service default bind ke `0.0.0.0` (semua antarmuka). Database atau cache yang nyasar terekspos ke jaringan adalah salah satu temuan paling umum di CTF defense (mis. **Redis tanpa `requirepass` → RCE**, T1190). Bind ke loopback memutus akses jaringan bahkan bila firewall salah (defense-in-depth). Padanan Windows: tutup listener & scope firewall — lihat [../windows/04-network-service-security.md](../windows/04-network-service-security.md) §2/§6.

**CARA — temukan dulu apa yang `LISTEN`:**

```bash
sudo ss -tlnp        # TCP listening + proses (cari 0.0.0.0:* dan :::*  = wildcard!)
sudo ss -ulnp        # UDP listening
```

**Lalu ikat ke alamat yang benar:**

| Service | File konfigurasi | Setting aman |
|---------|------------------|--------------|
| `sshd` | `/etc/ssh/sshd_config.d/00-hardening.conf` | `ListenAddress 10.10.0.10` (IP mgmt) |
| MySQL/MariaDB | `/etc/mysql/mysql.conf.d/mysqld.cnf` | `bind-address = 127.0.0.1` |
| PostgreSQL | `/etc/postgresql/*/main/postgresql.conf` | `listen_addresses = 'localhost'` |
| Redis | `/etc/redis/redis.conf` | `bind 127.0.0.1 ::1` + `protected-mode yes` + `requirepass <kuat>` |
| Memcached | `/etc/memcached.conf` | `-l 127.0.0.1` |
| App dev server (Node/Flask/dll.) | konfig app | bind `127.0.0.1`, bukan `0.0.0.0` |

Contoh Redis (target favorit penyerang):

```bash
sudo sed -i 's/^bind .*/bind 127.0.0.1 ::1/' /etc/redis/redis.conf
sudo sed -i 's/^# *requirepass .*/requirepass S3cret-Long-Pass/' /etc/redis/redis.conf
grep -E '^(protected-mode|bind|requirepass)' /etc/redis/redis.conf
sudo systemctl restart redis-server
```

> Service yang sama sekali tidak dibutuhkan: **matikan dan `mask`** (`sudo systemctl disable --now <svc>; sudo systemctl mask <svc>`). Inventaris service berbahaya dimiliki **Modul 02**; di sini cukup pastikan socket-nya tidak terekspos.

---

## 7. Brute Force Defense — fail2ban

**APA:** `fail2ban` memantau log auth dan mem-ban IP yang gagal login berulang dengan menyuntik rule firewall sementara. **KENAPA:** lapisan reaktif terhadap brute force/spraying SSH (T1110) yang lolos dari rate-limit statis. **CARA:**

```bash
sudo apt install fail2ban -y         # RHEL: sudo dnf install fail2ban
sudo tee /etc/fail2ban/jail.local >/dev/null <<'EOF'
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 5
backend  = systemd

[sshd]
enabled = true
EOF
sudo systemctl enable --now fail2ban
sudo fail2ban-client status sshd     # lihat IP yang ter-ban
```

> `backend = systemd` membaca dari `journald` (default Ubuntu modern). Bila pakai `rsyslog` dengan `/var/log/auth.log`, sesuaikan `logpath`. Korelasi log auth ke SIEM = **Modul 05**.

---

## Serangan Umum & Mitigasi

| Serangan | Teknik / contoh | MITRE ATT&CK | Mitigasi di modul ini |
|----------|-----------------|--------------|------------------------|
| **SSH brute force / password spraying** | Hydra/Medusa ke port 22 | T1110 / T1110.003 | §2 `MaxAuthTries`, §3 key-only auth, §5 `ufw limit`/scope, §7 fail2ban |
| **Exploit service tanpa auth terekspos** | Redis/Memcached unauth, app debug port | T1190 | §6 bind loopback + `requirepass`, §4/§5 default-deny |
| **Network service discovery / port scan** | `nmap -sV target` | T1046 | §4/§5 default-drop inbound + scope, §6 minimkan listener |
| **Exploitation of remote services** | CVE service jaringan (mis. CVE-2024-6387) | T1210 | §2 `LoginGraceTime`+patch, §6 kurangi exposure |
| **AiTM / downgrade crypto SSH** | Paksa cipher/MAC lemah, sniff | T1557 / T1040 | §3.2 KEX/Cipher/MAC modern, verifikasi host key |
| **Lateral movement via SSH (valid accounts/keys)** | Pakai kunci tercuri antar-host | T1021.004 / T1563.001 | §2 `AllowGroups`, §3 higiene kunci, scope firewall |
| **SSH tunneling / pivoting** | Port-forward ke segmen internal | T1572 | §2 `AllowTcpForwarding no`, `PermitTunnel no`, `GatewayPorts no` |
| **Default / weak credentials** | Login service dengan kredensial pabrik | T1078 | Ganti default (Modul 02), §3 key auth, §6 `requirepass` |

---

## Hardening Checklist (Modul Ini)

- [ ] `PermitRootLogin no` dan `PasswordAuthentication no` aktif **dan menang** atas drop-in `50-cloud-init.conf`.
- [ ] `KbdInteractiveAuthentication no`, `PermitEmptyPasswords no`, `HostbasedAuthentication no`, `IgnoreRhosts yes`.
- [ ] `MaxAuthTries 4`, `MaxStartups 10:30:60`, `LoginGraceTime 60`, idle timeout (`ClientAlive*`) aktif.
- [ ] `X11Forwarding no`, `AllowTcpForwarding no`, `AllowAgentForwarding no`, `PermitTunnel no`.
- [ ] `AllowGroups`/`AllowUsers` membatasi siapa yang boleh SSH; `LogLevel VERBOSE`.
- [ ] Autentikasi **kunci Ed25519**; permission `~/.ssh` = 700, `authorized_keys` = 600.
- [ ] KEX/Cipher/MAC modern saja; diverifikasi dengan `ssh-audit` (tanpa temuan lemah).
- [ ] `sshd -t` lolos sebelum `reload`; ada sesi cadangan saat menerapkan (anti-lockout).
- [ ] Firewall **default-deny inbound** (nftables `policy drop` / `ufw default deny` / firewalld `drop`).
- [ ] SSH dibatasi ke **subnet management**; tidak terekspos ke seluruh internet.
- [ ] IPv6 ikut difilter (rule `inet`/ICMPv6) atau IPv6 dimatikan bila tak dipakai.
- [ ] `ss -tlnp` tidak menampilkan service lokal yang bind `0.0.0.0`/`:::` (DB/cache di loopback).
- [ ] Redis/DB punya autentikasi + `protected-mode`/`requirepass`; service tak terpakai di-`mask`.
- [ ] `fail2ban` jail `sshd` aktif (`fail2ban-client status sshd`).
- [ ] (RHEL) port SSH non-default diberi label SELinux `semanage port`.

---

## Lab Praktik

**Topologi:** `TARGET` (Ubuntu 22.04 Server, IP `10.10.0.10`), `MGMT` (admin di subnet `10.10.0.0/24`), `ATTACKER` (Kali, di subnet `192.168.50.0/24` — di luar subnet management).

### Lab 1 — SSH key-only + matikan root/password
1. **Lakukan:** salin kunci (`ssh-copy-id`), buat `00-hardening.conf` (§2) dengan `PasswordAuthentication no` + `PermitRootLogin no`, lalu `sudo sshd -t && sudo systemctl reload ssh`.
2. **Konfirmasi dengan:** `sudo sshd -T | grep -Ei 'permitrootlogin|passwordauthentication'` → harus `permitrootlogin no` dan `passwordauthentication no`. Dari `ATTACKER`, `ssh root@10.10.0.10` dan `ssh user@10.10.0.10` dengan password → **ditolak** (`Permission denied (publickey)`).

### Lab 2 — Firewall default-deny + scope SSH
1. **Lakukan:** terapkan `/etc/nftables.conf` (§4) dengan SSH hanya dari `10.10.0.0/24`, lalu `sudo nft -f /etc/nftables.conf`.
2. **Konfirmasi dengan:** dari `MGMT` (`10.10.0.x`) → `ssh` berhasil. Dari `ATTACKER` (`192.168.50.x`) → `nmap -Pn -p22 10.10.0.10` menunjukkan `filtered`/timeout. `sudo nft list ruleset` menampilkan `policy drop`.

### Lab 3 — Service binding (Redis)
1. **Lakukan:** sebelum hardening, dari `ATTACKER` jalankan `redis-cli -h 10.10.0.10 INFO` (berhasil = terekspos). Lalu set `bind 127.0.0.1 ::1` + `requirepass` (§6) dan restart.
2. **Konfirmasi dengan:** `sudo ss -tlnp | grep 6379` → hanya `127.0.0.1:6379`. Dari `ATTACKER`, `redis-cli -h 10.10.0.10` → connection refused/timeout.

### Lab 4 — Brute force vs fail2ban
1. **Lakukan:** aktifkan `fail2ban` jail `sshd` (§7). Dari `MGMT` (yang diizinkan firewall), `hydra -l user -P rockyou.txt ssh://10.10.0.10` (di lab Anda sendiri).
2. **Konfirmasi dengan:** `sudo fail2ban-client status sshd` menampilkan IP penyerang di *Banned IP list*; koneksi berikutnya dari IP itu di-drop.

---

## Perintah Audit/Verifikasi

```bash
# 1. Nilai sshd EFEKTIF (bukan sekadar isi file) — sumber kebenaran
sudo sshd -T | grep -Ei \
 'permitrootlogin|passwordauthentication|kbdinteractive|maxauthtries|x11forwarding|allowtcpforwarding|logingracetime|clientalive|allowgroups|allowusers|ciphers|macs|kexalgorithms|loglevel'

# 2. Drop-in yang aktif (cari yang menimpa setting Anda, mis. 50-cloud-init.conf)
sudo grep -RHniE 'passwordauthentication|permitrootlogin' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/

# 3. Socket yang LISTEN — cari wildcard 0.0.0.0 / :::
sudo ss -tlnp
sudo ss -ulnp

# 4. Firewall aktif & policy (pilih sesuai stack)
sudo nft list ruleset                       # nftables: cari 'policy drop' di chain input
sudo ufw status verbose                     # ufw:      'Default: deny (incoming)'
sudo firewall-cmd --list-all                # firewalld (RHEL): zone 'drop'/aturan ssh

# 5. Service firewall berjalan
systemctl is-active nftables ufw fail2ban 2>/dev/null

# 6. Audit algoritma SSH dari luar (pihak ketiga; install bila ada)
ssh-audit 127.0.0.1                          # tandai cipher/MAC/KEX lemah

# 7. fail2ban
sudo fail2ban-client status sshd

# 8. (RHEL) label port SSH bila non-default
sudo semanage port -l | grep ssh_port_t
```

Output yang diharapkan: `sshd -T` menampilkan nilai hardened; `ss -tlnp` tidak ada DB/cache lokal di `0.0.0.0`; firewall menunjukkan default-deny; `ssh-audit` tanpa temuan merah; `fail2ban-client` mendaftar jail `sshd` enabled.

---

## Referensi

- **CIS Ubuntu Linux 22.04 LTS Benchmark** — §5 (SSH Server Configuration: `PermitRootLogin`, `MaxAuthTries`, `LoginGraceTime`, `ClientAlive*`, `X11Forwarding`, `AllowGroups`, dll.) dan §3.5/§4 (Host Based Firewall: nftables / ufw / firewalld).
- **CIS Red Hat Enterprise Linux 9 Benchmark** — padanan §SSH dan §firewalld untuk RHEL/Rocky/AlmaLinux.
- **OpenSSH manual:** `man sshd_config`, `man ssh-keygen` (Ed25519), `man sshd` (`-t`, `-T`). Catatan: `ChallengeResponseAuthentication` adalah alias usang dari `KbdInteractiveAuthentication`.
- **Mozilla Infosec — OpenSSH Guidelines** (rekomendasi KEX/Cipher/MAC modern) dan tool **`ssh-audit`** (jtesta/ssh-audit).
- **nftables wiki** (`man nft`, `/etc/nftables.conf`), **ufw** (`man ufw`), **firewalld** (`man firewall-cmd`, zones & rich rules).
- **Redis Security** (`protected-mode`, `bind`, `requirepass`); **MySQL `bind-address`**, **PostgreSQL `listen_addresses`**.
- **fail2ban** (`man jail.conf`, `fail2ban-client`).
- **CVE-2024-6387 (regreSSHion)** — race pada signal handler `sshd` (SIGALRM saat `LoginGraceTime` habis); mitigasi utama: **patch OpenSSH**. Workaround non-patch satu-satunya yang menutup celah adalah `LoginGraceTime 0` (mematikan trigger SIGALRM, dengan tradeoff DoS) — menurunkan grace time ke nilai pendek non-nol **tidak** memitigasi.
- **MITRE ATT&CK:** T1046 (Network Service Discovery), T1190 (Exploit Public-Facing Application), T1110 (Brute Force), T1210 (Exploitation of Remote Services), T1557/T1040 (AiTM / Network Sniffing), T1021.004 (Remote Services: SSH), T1563.001 (SSH Hijacking), T1572 (Protocol Tunneling), T1078 (Valid Accounts).
- **Lintas modul:** Modul 01 (PAM/sudo/root login & 2FA stack), Modul 02 (inventaris service berbahaya & default credential), Modul 03 (SUID/capabilities/permission), Modul 05 (auditd/journald, sentralisasi log auth & fail2ban). Padanan konsep Windows: [../windows/04-network-service-security.md](../windows/04-network-service-security.md) (firewall default-deny, service exposure, legacy protocol/crypto).

---

> **Catatan etika:** Semua teknik di atas — termasuk `nmap`, `hydra`, `redis-cli` ke host orang lain, dan `ssh-audit` — hanya untuk **lab milik sendiri, sistem dengan izin tertulis, atau arena CTF/LKSN resmi**. Memindai, brute force, atau mengakses layanan tanpa otorisasi adalah pelanggaran hukum (di Indonesia: UU ITE) dan kode etik lomba. Fokus modul ini adalah **pertahanan**: memahami serangan hanya untuk menutupnya.
