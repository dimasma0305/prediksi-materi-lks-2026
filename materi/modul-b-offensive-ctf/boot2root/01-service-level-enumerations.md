# 1. Service Level Enumerations

> Service Level Enumeration adalah fase **pertama** sebuah serangan Boot2Root: dari *nol akses*, kita memetakan permukaan serang sebuah host — port mana yang terbuka, layanan apa yang berjalan, **versi** persisnya, dan informasi yang bisa diambil dari tiap layanan (share, direktori, user, banner). Di CTF LKSN 2026 fase ini menentukan segalanya: rantai *enumeration → foothold → privesc* hanya berhasil jika peta awalnya benar. Pepatah pentester berlaku penuh di sini: **"enumeration is key"** — kebanyakan soal yang "buntu" sebenarnya kurang dienumerasi, bukan kurang exploit.

## Konsep

Enumerasi layanan adalah proses mengubah sebuah IP kosong menjadi **daftar permukaan serang yang konkret**. Tujuannya bukan langsung meng-exploit, melainkan mengumpulkan fakta sebanyak mungkin agar pemilihan exploit di fase berikutnya akurat dan tidak menebak.

Ada beberapa lapisan yang berbeda dan harus dikerjakan berurutan:

- **Host discovery** — apakah host hidup? (relevan saat diberi subnet, bukan satu IP).
- **Port scanning** — port TCP/UDP mana yang `open`.
- **Service & version detection** — layanan apa di balik port itu, dan **versi**-nya (kunci untuk mencocokkan CVE).
- **Service-specific enumeration** — menggali tiap layanan: share SMB, **export NFS** (RPC/portmapper `111` + `2049`), direktori HTTP & fingerprint CMS, user via RPC/LDAP, anonymous FTP, community SNMP, zone transfer DNS.

Karena target lomba bisa **Windows/AD maupun Linux**, enumerasi Windows (SMB `445`, RPC `135`, LDAP `389`, Kerberos `88`) sama pentingnya dengan layanan klasik Unix — dan justru sering jadi jalan masuk utama di soal ber-Active Directory.

## Cara Kerja

Port scan bekerja dengan mengirim paket dan menyimpulkan status port dari respons:

- **TCP SYN scan** (`-sS`, default bila root): kirim `SYN`; balasan `SYN/ACK` = `open`, `RST` = `closed`. Cepat dan *half-open* (tak menuntaskan handshake).
- **TCP connect scan** (`-sT`): three-way handshake penuh; dipakai bila bukan root.
- **UDP scan** (`-sU`): lambat & ambigu (tak ada handshake) — tetapi layanan penting seperti **SNMP (161)**, **DNS (53)**, **Kerberos** bisa hanya muncul di UDP.

Setelah port diketahui, **version detection** (`-sV`) mengirim serangkaian *probe* dan mencocokkan respons ke database signature `nmap`. **NSE** (`-sC` = script default, `--script ...`) menjalankan skrip Lua untuk menggali lebih dalam: `smb-os-discovery`, `http-title`, `ftp-anon`, `ssl-cert`, dll. Banyak banner & metadata (versi OpenSSH, IIS/Apache, hostname domain, OS build) bocor di tahap ini — inilah bahan untuk `searchsploit`/CVE.

## Indikator / Cara Mengenali

Yang dicari dari hasil scan, dan apa artinya:

- **Banner versi spesifik** (`vsftpd 2.3.4`, `OpenSSH 7.2`, `Apache 2.4.49`, `Microsoft IIS 7.5`) → langsung dicek ke `searchsploit`/CVE; versi lawas = kandidat exploit.
- **SMB `445`/`139` terbuka + null session diterima** → bisa enum share, user, dan kebijakan password tanpa kredensial.
- **HTTP default page / direktori listing / `robots.txt`** → ada aplikasi web; lanjut brute direktori & vhost.
- **HTTP menjalankan CMS** (`wp-login.php`, `/administrator` Joomla, header `X-Drupal-*`, meta `generator`) → fingerprint dengan `whatweb`/`wpscan`/`joomscan` untuk versi + plugin/tema rentan & user.
- **RPC/portmapper `111` terbuka + `showmount` mengembalikan export** → ada **NFS share**; perhatikan `no_root_squash` (vektor privesc di 03) dan export yang bisa di-mount tanpa auth.
- **Anonymous FTP `230 Login successful`** → baca/tulis file tanpa kredensial.
- **SNMP community `public` merespons** → bocoran proses, user, tabel ARP, bahkan kredensial.
- **DNS membolehkan AXFR** → seluruh record subdomain/host internal terbongkar.
- **Port AD lengkap (`88,135,139,389,445,464,636,3268`)** → ini **Domain Controller**; arahkan ke enum user/LDAP/Kerberos.

## Langkah Eksploitasi

Fase enumerasi yang menyiapkan eksploitasi — kerjakan berurutan, jangan loncat:

1. **Host discovery** (bila diberi range): `nmap -sn` untuk menyaring host hidup.
2. **Full TCP port scan** semua 65535 port dengan rate tinggi → daftar port `open`.
3. **Targeted service/version + NSE** hanya pada port yang terbuka (`-sC -sV`) → versi & metadata.
4. **UDP scan top-ports** → tangkap SNMP/DNS/Kerberos yang tak terlihat di TCP.
5. **Per-service deep enum** sesuai port yang muncul (SMB, **NFS/RPC**, HTTP/CMS, FTP, SNMP, RPC/LDAP, DNS).
6. **Catat semua artefak**: versi, hostname/domain, username, share, path, kredensial → simpan untuk fase exploit & privesc.
7. **Cocokkan ke exploit**: `searchsploit <produk versi>`; tandai kandidat RCE/auth-bypass untuk halaman *Service Level Exploitation* (02).

## Tools

| Tool | Fungsi singkat |
|---|---|
| **nmap** | Inti: port scan, `-sV` version detection, NSE (`-sC`/`--script`), output `-oA` |
| **rustscan / masscan** | Port discovery sangat cepat; rustscan bisa pipe hasil langsung ke `nmap` |
| **enum4linux-ng** | Enum SMB/RPC menyeluruh: user, group, share, password policy, OS |
| **smbclient / smbmap** | List & akses share SMB, cek hak baca/tulis (`-N` null session) |
| **netexec (nxc)** | Penerus `crackmapexec`; enum SMB/LDAP/WinRM massal: `--shares`, `--users`, `--pass-pol` |
| **rpcclient / ldapsearch / kerbrute** | Enum user domain via MS-RPC, LDAP, dan user-enumeration Kerberos (AD) |
| **gobuster / ffuf / feroxbuster** | Brute direktori, file, dan **vhost/subdomain** pada web (mode `dir`/`vhost`/`dns`) |
| **whatweb / nikto** | Fingerprint stack web & scan misconfig/file berisiko |
| **wpscan / joomscan / droopescan** | Fingerprint & enumerasi CMS (WordPress/Joomla/Drupal): versi, plugin/tema rentan, user |
| **showmount / rpcinfo / nfs-common** | Enum RPC (portmapper `111`) & list export NFS (`2049`); cek `no_root_squash` |
| **snmpwalk / onesixtyone** | Walk MIB SNMP & brute community string |
| **dnsrecon / dig** | Enum DNS, brute subdomain, uji zone transfer (AXFR) |
| **searchsploit** | Cari PoC/exploit lokal (Exploit-DB) berdasarkan produk & versi |

## Contoh / Payload

```bash
# 1) Host discovery (bila diberi subnet, bukan satu IP)
nmap -sn 10.10.10.0/24 -oN hosts.txt

# 2) Full TCP port scan cepat → ambil port yang open
nmap -p- --min-rate 10000 -T4 10.10.10.10 -oN ports.txt
rustscan -a 10.10.10.10 --ulimit 5000 -- -sC -sV    # alternatif: scan + service detect sekaligus

# 3) Service/version + script default HANYA pada port open
nmap -sC -sV -p 22,80,135,139,389,445 10.10.10.10 -oA scan_services

# 4) UDP top-ports (SNMP/DNS/Kerberos sering hanya di UDP) — perlu root
sudo nmap -sU --top-ports 50 --open 10.10.10.10 -oN udp.txt
```

```bash
# ── SMB / Windows (445,139) ──────────────────────────────────
smbclient -L //10.10.10.10/ -N                       # list share via null session
smbmap -H 10.10.10.10 -u guest -p ''                 # cek hak akses tiap share
enum4linux-ng -A 10.10.10.10                          # enum lengkap user/group/policy
nxc smb 10.10.10.10 -u '' -p '' --shares --users      # netexec: share + user (null auth)
nmap --script "smb-os-discovery,smb-enum-shares,smb-enum-users" -p445 10.10.10.10

# ── RPC / LDAP / Kerberos (AD: 135,389,88) ───────────────────
rpcclient -U "" -N 10.10.10.10 -c "enumdomusers;querydominfo"
ldapsearch -x -H ldap://10.10.10.10 -s base namingcontexts   # ambil base DN domain
kerbrute userenum -d target.htb --dc 10.10.10.10 users.txt   # validasi user via Kerberos
```

```bash
# ── HTTP/HTTPS (80,443) ──────────────────────────────────────
whatweb http://10.10.10.10                                   # fingerprint stack & versi
nikto -h http://10.10.10.10                                  # misconfig & file berisiko
# Brute direktori/file — gobuster (dinamai kisi-kisi) & alternatif feroxbuster
gobuster dir -u http://10.10.10.10 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,txt,html -t 50
feroxbuster -u http://10.10.10.10 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,txt
# Virtual host / subdomain discovery
gobuster vhost -u http://target.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain
ffuf -u http://10.10.10.10 -H "Host: FUZZ.target.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs 1234   # -fs saring ukuran respons default

# ── Fingerprint CMS (WordPress / Joomla / Drupal) ────────────
wpscan --url http://10.10.10.10 --enumerate u,vp,vt          # versi + plugin/tema rentan + user (tambah --api-token utk DB CVE)
wpscan --url http://10.10.10.10 -e u --passwords /usr/share/wordlists/rockyou.txt   # brute login wp-admin
joomscan -u http://10.10.10.10                               # versi Joomla + komponen rentan
droopescan scan drupal -u http://10.10.10.10                 # versi Drupal + module

# ── NFS / RPC (111, 2049) ────────────────────────────────────
rpcinfo -p 10.10.10.10                                       # daftar layanan RPC via portmapper (cari mountd/nfs)
showmount -e 10.10.10.10                                     # list export NFS + subnet/host yang diizinkan
nmap --script "nfs-ls,nfs-showmount,nfs-statfs" -p111,2049 10.10.10.10   # enum NFS via NSE
# Mount & periksa izin export (butuh root di mesin attacker)
mkdir -p /mnt/nfs && mount -o vers=3 10.10.10.10:/srv/share /mnt/nfs && ls -la /mnt/nfs
# Perhatikan flag export di /etc/exports target: no_root_squash → jalur privesc (lihat 03)

# ── FTP (21) / SNMP (161/udp) / DNS (53) ─────────────────────
nmap --script ftp-anon -p21 10.10.10.10                      # uji anonymous login
snmpwalk -v2c -c public 10.10.10.10                          # walk MIB bila community 'public'
dig axfr target.htb @10.10.10.10                             # coba zone transfer (AXFR)

# 5) Cocokkan versi temuan ke exploit (untuk fase 02)
searchsploit vsftpd 2.3.4
searchsploit "Apache 2.4.49"
```

> **Catatan akurasi.** Selalu kerjakan `-sC -sV` **hanya pada port yang sudah terbukti open** (dari scan `-p-`) agar cepat. Simpan output dengan `-oA <nama>` (menyimpan format `.nmap/.gnmap/.xml` sekaligus) supaya bisa di-*grep* dan dipakai ulang tanpa scan berkali-kali ke target lomba.

## Deteksi & Mitigasi

Enumerasi terhadap layanan yang memang terekspos **tidak bisa "diblokir" sepenuhnya** — selama port terbuka, ia bisa diintip. Karena itu pertahanan bertumpu pada **pengurangan permukaan serang** + **deteksi**, bukan pencegahan mutlak. Ini bersikap jujur sesuai realita blue-team.

**Surface reduction (hardening — kaitan langsung ke Modul A):**

- **Matikan layanan yang tak dipakai** dan tutup port-nya di host firewall + segmentasi jaringan → lihat Modul A *Windows — `04-network-service-security.md`* dan *`07-hardening-checklist.md`*.
- **Nonaktifkan SMBv1 & null/anonymous session**, cabut anonymous FTP, dan ganti community SNMP default `public` (idealnya SNMPv3) — ini memutus jalur enum tanpa kredensial.
- **Kerasi export NFS**: batasi ke host/subnet tertentu (bukan `*`), pakai `root_squash`/`all_squash` + `nosuid` di `/etc/exports`, dan jangan ekspos `2049` ke jaringan tak tepercaya — menutup jalur privesc `no_root_squash` (lihat 03).
- **Batasi DNS zone transfer (AXFR)** hanya ke secondary yang sah; tolak AXFR dari publik.
- **Kurangi kebocoran versi/banner** dan kerasi konfigurasi AD/LDAP (anonymous bind off) → bertautan dengan *Active Directory Security* & *PAM* di Modul A.

**Detection (monitoring — kaitan ke Modul A & C):**

- Port/host scan meninggalkan pola khas: **burst koneksi**, banyak `RST`, akses port berurutan dalam waktu singkat. IDS/IPS (Suricata/Snort) punya signature *port scan*; firewall & **Windows Event Log** (logon anonim SMB, koneksi gagal) merekam jejaknya → lihat Modul A *`06-logging-auditing.md`*.
- Analisis paskakejadian: korelasi paket scan di **Modul C — `02-network-forensic.md`** dan jejak log di **Modul C — `03-log-forensic.md`** untuk merekonstruksi tahap *recon* penyerang.

## Mini-Lab

**Skenario:** Diberi satu host `10.10.10.10` (Windows) tanpa kredensial. Lakukan enumerasi layanan untuk menemukan sebuah share SMB yang dapat dibaca anonim, lalu ambil **flag** di dalamnya.

1. `nmap -p- --min-rate 10000 10.10.10.10` → temukan `445` open.
2. `nmap -sC -sV -p445 10.10.10.10` → konfirmasi `Windows`, dapat hostname/domain.
3. `smbclient -L //10.10.10.10/ -N` → daftar share; perhatikan share non-default (mis. `Backups`).
4. `smbmap -H 10.10.10.10 -u guest -p ''` → pastikan share itu `READ ONLY`.
5. `smbclient //10.10.10.10/Backups -N` → `ls`, `get flag.txt` → **buka file = flag.**

Target legal untuk reproduksi: HTB box *seri pemula* (mis. **Blue/Legacy** untuk SMB, **Bashed/Devel** untuk HTTP/FTP), atau room enumerasi di TryHackMe.

## Referensi & Latihan

- **HackTricks — Pentesting Network / Pentesting Services** (per-port: 445 SMB, 80 HTTP, 161 SNMP, 389 LDAP, 88 Kerberos) — referensi enumerasi paling lengkap.
- **Nmap Reference Guide & NSE docs** (`https://nmap.org/book/`) — flag scan, `-sV`, dan katalog skrip NSE.
- **TryHackMe — "Nmap", "Network Services", "Enumeration"** dan jalur *Jr Penetration Tester* (lab terpandu, legal).
- **HackTheBox — Starting Point** & modul Academy *"Network Enumeration with Nmap"*, *"Footprinting"* (enum SMB/FTP/DNS/SNMP bertingkat).
- **pwn.college** — modul *Intro to Cybersecurity / networking* untuk dasar protokol & service.
- **root-me** — kategori *Network* (analisis layanan & service fingerprinting).

> **Etika:** Teknik di halaman ini **hanya** untuk lab pribadi, platform latihan resmi (HTB/THM/pwn.college/root-me), target CTF LKSN, atau sistem dengan **izin tertulis eksplisit**. Memindai atau mengenumerasi sistem milik orang lain tanpa izin adalah pelanggaran hukum.
