# Modul 04 — Network Service Security

> Modul ini mengeraskan permukaan serang jaringan Windows: firewall berbasis profil, SMB, RDP, WinRM, resolusi nama, protokol legacy, dan layanan DNS. Setiap port yang terbuka dan setiap protokol usang adalah jalan masuk bagi penyerang — Responder yang meracuni LLMNR untuk mencuri NetNTLM hash, EternalBlue yang mengeksploitasi SMBv1, atau brute force RDP yang diekspos ke internet. Tujuannya satu: kurangi attack surface sampai hanya yang benar-benar dibutuhkan yang boleh berbicara di jaringan.

## Daftar Isi

1. [Konsep & Tujuan](#1-konsep--tujuan)
2. [Windows Defender Firewall with Advanced Security](#2-windows-defender-firewall-with-advanced-security)
3. [SMB Hardening](#3-smb-hardening)
4. [RDP Transport Hardening](#4-rdp-transport-hardening)
5. [Name Resolution Poisoning Defense (LLMNR/NBT-NS/mDNS/WPAD)](#5-name-resolution-poisoning-defense)
6. [WinRM Hardening](#6-winrm-hardening)
7. [Nonaktifkan Service & Fitur Tak Terpakai](#7-nonaktifkan-service--fitur-tak-terpakai)
8. [Legacy Protocol & Weak Cipher (TLS/SSL/PSv2)](#8-legacy-protocol--weak-cipher)
9. [DNS Service Security](#9-dns-service-security)
10. [IPsec / Domain Isolation (Kontrol Lanjutan)](#10-ipsec--domain-isolation)
- [Serangan Umum & Mitigasi](#serangan-umum--mitigasi)
- [Hardening Checklist (Modul Ini)](#hardening-checklist-modul-ini)
- [Lab Praktik](#lab-praktik)
- [Perintah Audit/Verifikasi](#perintah-auditverifikasi)
- [Referensi](#referensi)

---

## 1. Konsep & Tujuan

Filosofi inti modul ini adalah **attack surface reduction** di lapisan jaringan. Tiga prinsip yang dipegang:

1. **Default-deny inbound.** Semua koneksi masuk diblokir secara default; hanya layanan yang dibutuhkan yang dibuka secara eksplisit, dengan scope alamat seketat mungkin. Outbound umumnya allow, tetapi pada lingkungan high-security bisa diperketat menjadi default-deny outbound.
2. **Nonaktifkan yang tidak dipakai.** Setiap service, role, protokol, atau cipher yang tidak dibutuhkan adalah liability. Service yang mati tidak bisa dieksploitasi (mis. Print Spooler di Domain Controller → PrintNightmare).
3. **Hanya protokol modern & terautentikasi.** SMBv1, NTLMv1, TLS 1.0/1.1, SSL 3.0, NetBIOS, dan LLMNR adalah protokol yang dirancang sebelum model ancaman modern. Matikan, dan paksa pengganti yang menandatangani serta mengenkripsi trafik (SMB signing/encryption, NLA+TLS untuk RDP, HTTPS untuk WinRM).

**Mengapa penting dari sudut pandang penyerang:** fase awal serangan internal hampir selalu melibatkan jaringan — discovery port (T1046), poisoning resolusi nama untuk mencuri kredensial (T1557), relay NTLM ke host lain (T1557.001), atau eksploitasi service yang terekspos (T1210). Mengeraskan lapisan ini memutus rantai serangan sebelum penyerang mendapat kredensial atau foothold pertama.

Mekanisme **pembuatan & linking GPO, security filtering, dan User Rights Assignment** dimiliki Modul 03 — modul ini hanya menyebut "terapkan via GPO di [path] → lihat Modul 03". Nilai **password/lockout policy** dimiliki Modul 02. **Audit policy, Event ID, dan logging** dimiliki Modul 06.

---

## 2. Windows Defender Firewall with Advanced Security

### 2.1 Tiga Profile

**APA:** Windows Defender Firewall (WDFW) menerapkan rule berbeda tergantung tipe jaringan tempat host terhubung.

| Profile | Kapan aktif | Default rekomendasi |
|---------|-------------|---------------------|
| **Domain** | NIC ter-autentikasi ke domain AD | Inbound: Block, Outbound: Allow |
| **Private** | Jaringan tepercaya non-domain (mis. home) | Inbound: Block, Outbound: Allow |
| **Public** | Jaringan tidak tepercaya (hotspot, internet) | Inbound: Block (paling ketat) |

**KENAPA:** Server domain hampir selalu memakai profile Domain; memastikan ketiga profile menyala dan inbound-nya Block mencegah host "terbuka" saat berpindah jaringan atau saat deteksi profil salah.

**CARA:**

- **GUI/MMC:** `wf.msc` → klik kanan "Windows Defender Firewall with Advanced Security" → Properties → tab Domain/Private/Public → Firewall state = On, Inbound = Block, Outbound = Allow.
- **PowerShell:**

```powershell
# Status & default action tiap profile
Get-NetFirewallProfile | Format-Table Name,Enabled,DefaultInboundAction,DefaultOutboundAction

# Nyalakan semua profile + default-deny inbound
Set-NetFirewallProfile -Name Domain,Private,Public -Enabled True `
  -DefaultInboundAction Block -DefaultOutboundAction Allow `
  -AllowInboundRules True -NotifyOnListen False
```

- **cmd/netsh (legacy, tetap valid):**

```cmd
netsh advfirewall set allprofiles state on
netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound
```

### 2.2 Inbound / Outbound Rules + Scope

**APA:** Rule eksplisit yang mengizinkan port/aplikasi tertentu, dibatasi dengan **scope** alamat remote.

**KENAPA:** Default-deny tidak ada artinya bila rule allow terlalu lebar. Membatasi `RemoteAddress` ke subnet management mencegah port admin (RDP/WinRM) diakses dari segmen user atau internet (membatasi T1021).

**CARA (PowerShell `New-NetFirewallRule`):**

```powershell
# Izinkan RDP HANYA dari subnet jump host / PAW (lihat Modul 01)
New-NetFirewallRule -DisplayName "Allow RDP from Admin Subnet" `
  -Direction Inbound -Action Allow -Protocol TCP -LocalPort 3389 `
  -RemoteAddress 10.10.0.0/24 -Profile Domain

# Izinkan HTTPS app dari mana saja di profile Domain
New-NetFirewallRule -DisplayName "Allow HTTPS Web App" `
  -Direction Inbound -Action Allow -Protocol TCP -LocalPort 443 -Profile Domain

# Blok outbound ke port SMB keluar (cegah relay/eksfil via 445) - opsional high-sec
New-NetFirewallRule -DisplayName "Block Outbound SMB" `
  -Direction Outbound -Action Block -Protocol TCP -RemotePort 445 -Profile Domain
```

- **GUI:** `wf.msc` → Inbound Rules → New Rule → Port/Program → tentukan Action, Profile, dan tab Scope untuk Remote IP.
- **netsh:** `netsh advfirewall firewall add rule name="Allow RDP Admin" dir=in action=allow protocol=TCP localport=3389 remoteip=10.10.0.0/24`

### 2.3 Terapkan via GPO (rujuk Modul 03)

**APA:** Konfigurasi firewall sebaiknya dikelola terpusat lewat GPO, bukan per-host.

**KENAPA:** Konsistensi, tahan-tamper (user lokal tidak bisa mematikan), dan auditability.

**CARA:** Buat/link GPO → **lihat Modul 03**. Path setting:
`Computer Configuration > Policies > Windows Settings > Security Settings > Windows Defender Firewall with Advanced Security > Windows Defender Firewall with Advanced Security`. Di sini tersedia Profile properties + Inbound/Outbound/Connection Security Rules yang identik dengan `wf.msc`.

> Catatan: rule yang dibuat via GPO dan rule lokal **bergabung (merge)**. Untuk lingkungan ketat, set "Apply local firewall rules = No" pada properties profile agar hanya rule GPO yang berlaku.

### 2.4 Logging Dropped Packets

**APA:** Catat paket yang di-drop (dan opsional yang sukses) ke file log firewall.

**KENAPA:** Memberi visibilitas atas scan, percobaan koneksi tertolak, dan misconfig rule. Berguna untuk forensik & deteksi (korelasi event → Modul 06).

**CARA:**

```powershell
Set-NetFirewallProfile -Name Domain,Private,Public `
  -LogBlocked True -LogAllowed False `
  -LogFileName "%systemroot%\system32\LogFiles\Firewall\pfirewall.log" `
  -LogMaxSizeKilobytes 16384
```

**Anchor nilai:** CIS Microsoft Windows Server 2022 Benchmark merekomendasikan **LogMaxSizeKilobytes ≥ 16384 KB** dan **LogBlocked = Yes** untuk tiap profile. (Sumber: CIS Benchmark §Windows Defender Firewall; Microsoft Security Baseline.)

---

## 3. SMB Hardening

### 3.1 Nonaktifkan SMBv1

**APA:** Hapus/nonaktifkan protokol SMBv1 (CIFS) di server dan client.

**KENAPA:** SMBv1 tidak punya signing modern dan rentan EternalBlue (MS17-010 / CVE-2017-0144, vektor WannaCry & NotPetya, T1210). Tidak ada alasan operasional memakainya di Windows modern.

> **Delta versi:** Sejak Windows 10 1709 dan Windows Server 2019, fitur SMB1 **tidak terinstal secara default**. Windows Server 2022 juga default tanpa SMB1. Tetap verifikasi karena bisa aktif via migrasi/legacy NAS.

**CARA:**

```powershell
# Cek status
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol

# Matikan di sisi server
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force

# Hapus fitur SMB1 sepenuhnya (server & client) - butuh restart
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart

# (Opsional) audit dulu siapa yang masih pakai SMB1 sebelum mematikan total
Set-SmbServerConfiguration -AuditSmb1Access $true -Force
```

- **Registry (server):** `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters` → `SMB1` (DWORD) = `0`.

### 3.2 Wajibkan SMB Signing

**APA:** Paksa penandatanganan digital pada komunikasi SMB (server dan client).

**KENAPA:** Tanpa signing, SMB rentan **SMB relay / AiTM** (T1557.001) — penyerang me-relay autentikasi NTLM korban ke server lain. Signing mengikat sesi sehingga relay gagal.

> **Delta versi:** Windows 11 24H2 dan Windows Server 2025 **mewajibkan SMB signing secara default** untuk semua koneksi. Di Server 2022 / Win10/11 lama, signing harus dipaksa eksplisit.

**CARA:**

```powershell
# Server: wajib signing
Set-SmbServerConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -Force
# Client: wajib signing
Set-SmbClientConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -Force
```

- **GPO (Security Options → lihat Modul 03):**

| Setting (Security Options) | Nilai | Registry |
|----------------------------|-------|----------|
| Microsoft network server: Digitally sign communications (always) | Enabled | `...\LanmanServer\Parameters\RequireSecuritySignature=1` |
| Microsoft network client: Digitally sign communications (always) | Enabled | `...\LanmanWorkstation\Parameters\RequireSecuritySignature=1` |

(Path registry lengkap: `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters` dan `...\LanmanWorkstation\Parameters`.)

### 3.3 SMB Encryption

**APA:** Enkripsi data SMB in-transit (AES-128-GCM/CCM), per-share atau global. Membutuhkan SMB 3.0+.

**KENAPA:** Melindungi kerahasiaan data di jaringan dan menggagalkan sniffing/relay. Lebih kuat dari signing (sekaligus menyediakan integritas).

**CARA:**

```powershell
# Global (semua share)
Set-SmbServerConfiguration -EncryptData $true -Force
# Tolak koneksi yang tidak terenkripsi (klien lama akan gagal - uji dulu!)
Set-SmbServerConfiguration -RejectUnencryptedAccess $true -Force
# Per-share saja
Set-SmbShare -Name "SensitiveData" -EncryptData $true -Force
```

### 3.4 Nonaktifkan Guest & Insecure Guest Auth

**APA:** Larang fallback ke akun Guest dan insecure guest logon pada SMB client.

**KENAPA:** Insecure guest logon memungkinkan koneksi ke share berbahaya tanpa autentikasi/penandatanganan — vektor untuk man-in-the-middle dan eksekusi file berbahaya.

> **Delta versi:** Sejak Windows 10 1709 (Enterprise/Education) dan Windows 11, insecure guest logons **diblokir secara default**. Verifikasi tetap, terutama edisi Pro/legacy.

**CARA:**

```powershell
Set-SmbClientConfiguration -EnableInsecureGuestLogons $false -Force
```

- **GPO:** `Computer Configuration > Policies > Administrative Templates > Network > Lanman Workstation > Enable insecure guest logons = Disabled`.

### 3.5 Batasi Null Session & Anonymous Shares

**APA:** Cegah enumerasi anonim (null session) atas SAM, share, dan named pipes.

**KENAPA:** Null session memungkinkan penyerang tanpa kredensial mengenumerasi user, group, dan share (recon, T1087/T1135).

**CARA:** Setting ini adalah **Security Options** — konfigurasikan via GPO → **lihat Modul 03**. Ringkasan nilai:

| Security Option | Nilai | Registry (HKLM\...\Lsa) |
|-----------------|-------|--------------------------|
| Network access: Do not allow anonymous enumeration of SAM accounts | Enabled | `RestrictAnonymousSAM=1` |
| Network access: Do not allow anonymous enumeration of SAM accounts and shares | Enabled | `RestrictAnonymous=1` |
| Network access: Restrict anonymous access to Named Pipes and Shares | Enabled | `RestrictNullSessAccess=1` |
| Network access: Let Everyone permissions apply to anonymous users | Disabled | `EveryoneIncludesAnonymous=0` |

> Catatan path registry: `RestrictAnonymousSAM`, `RestrictAnonymous`, dan `EveryoneIncludesAnonymous` berada di `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`. **`RestrictNullSessAccess` berada di `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`** (bukan di Lsa).

---

## 4. RDP Transport Hardening

### 4.1 Wajibkan Network Level Authentication (NLA/CredSSP)

**APA:** Paksa autentikasi pengguna **sebelum** sesi RDP penuh terbentuk (NLA menggunakan CredSSP).

**KENAPA:** Tanpa NLA, host mengekspos stack RDP pra-autentikasi — persis permukaan yang dieksploitasi **BlueKeep (CVE-2019-0708, T1210)**. NLA juga mengurangi DoS dan mempersulit brute force.

**CARA:**

- **GUI:** System Properties → Remote → "Allow connections only from computers running Remote Desktop with Network Level Authentication".
- **GPO:** `Computer Configuration > Policies > Administrative Templates > Windows Components > Remote Desktop Services > Remote Desktop Session Host > Security > Require user authentication for remote connections by using Network Level Authentication = Enabled`.
- **Registry/PowerShell:**

```powershell
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
  -Name UserAuthentication -Value 1
```

### 4.2 Wajibkan TLS (SSL) Security Layer + Encryption Level High

**APA:** Set SecurityLayer = SSL/TLS dan minimum encryption level = High.

**KENAPA:** Mencegah fallback ke RDP Security Layer (RC4 lemah) yang rentan MITM. TLS menyediakan server authentication + enkripsi kuat.

**CARA:**

| Setting | Registry value (`...\WinStations\RDP-Tcp`) | Arti |
|---------|---------------------------------------------|------|
| SecurityLayer = 2 | `SecurityLayer` (DWORD) = `2` | Paksa SSL/TLS |
| Encryption = High | `MinEncryptionLevel` (DWORD) = `3` | 128-bit |
| NLA on | `UserAuthentication` = `1` | Lihat 4.1 |

- **GPO:** RDS → Security → "Require use of specific security layer for remote (RDP) connections = SSL" dan "Set client connection encryption level = High Level".

### 4.3 Batasi User yang Boleh RDP

**APA:** Hanya akun yang perlu yang masuk grup "Remote Desktop Users" / diberi User Right RDP.

**KENAPA:** Mengurangi jumlah identitas yang bisa dipakai untuk lateral movement (T1021.001). Domain Admin **tidak boleh** RDP ke workstation Tier-2 (lihat tiered model Modul 01).

**CARA:** User Right `Allow log on through Remote Desktop Services` (SeRemoteInteractiveLogonRight) dan `Deny log on through Remote Desktop Services` — keduanya **User Rights Assignment**, konfigurasikan via GPO → **lihat Modul 03**.

### 4.4 Account Lockout, RD Gateway, dan Eksposur Port

- **Account lockout** untuk melawan RDP brute force (T1110) → nilai threshold/duration dimiliki Modul 02 (Account Lockout Policy). **Lihat Modul 02.**
- **RD Gateway**: terminasikan RDP lewat HTTPS (443) terbungkus TLS dan kebijakan CAP/RAP, alih-alih mengekspos 3389 langsung.
- **Jangan ekspos 3389 ke internet.** Jika akses jarak jauh dibutuhkan, gunakan RD Gateway atau VPN. Batasi inbound RDP via firewall ke subnet management (lihat §2.2).
- **Catatan penting — "ganti port = security by obscurity":** memindah RDP dari 3389 ke port lain **bukan** kontrol keamanan nyata; scanner menemukannya dalam hitungan menit (T1046). Tetap wajibkan NLA+TLS+firewall scope.
- **Restricted Admin mode / Remote Credential Guard** untuk mencegah kredensial tertinggal di host tujuan → **lihat Modul 01**.

---

## 5. Name Resolution Poisoning Defense

Ketika DNS gagal, Windows fallback ke protokol broadcast/multicast yang **tidak terautentikasi**: LLMNR, NBT-NS, dan mDNS. Tools seperti **Responder** menjawab query ini, menipu korban agar mengirim **NetNTLM hash** ke penyerang (T1557 / T1557.001). Hash bisa di-crack offline (T1110) atau di-relay ke host lain (SMB relay). Matikan ketiganya plus WPAD.

### 5.1 Nonaktifkan LLMNR

**APA:** Matikan Link-Local Multicast Name Resolution.

**CARA:**

- **GPO:** `Computer Configuration > Policies > Administrative Templates > Network > DNS Client > Turn off multicast name resolution = Enabled`.
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient` → `EnableMulticast` (DWORD) = `0`.

```powershell
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Force | Out-Null
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name EnableMulticast -Value 0
```

### 5.2 Nonaktifkan NBT-NS / NetBIOS over TCP/IP

**APA:** Matikan NetBIOS over TCP/IP per-adapter (atau via DHCP option).

**CARA:**

- **GUI:** NIC Properties → IPv4 → Advanced → tab WINS → "Disable NetBIOS over TCP/IP".
- **Registry (per interface):** `HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_{GUID}` → `NetbiosOptions` (DWORD) = `2`.
- **PowerShell/WMI:**

```powershell
# Set untuk semua adapter yang ber-IP
$nics = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE"
$nics | ForEach-Object { $_.SetTcpipNetbios(2) }   # 2 = Disable NetBIOS over TCP/IP
```

> **Catatan:** Cara skala besar yang rapi adalah mendistribusikan opsi "Disable NetBIOS" via DHCP (Microsoft vendor option) atau startup script via GPO → lihat Modul 03.

### 5.3 Nonaktifkan mDNS

**APA:** Matikan Multicast DNS yang ditangani service Dnscache.

**CARA:**

- **Registry:** `HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters` → `EnableMDNS` (DWORD) = `0`.

```powershell
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' -Name EnableMDNS -Value 0
```

### 5.4 WPAD

**APA:** Cegah penyalahgunaan Web Proxy Auto-Discovery, yang juga bisa di-poison untuk mencuri kredensial atau menyuntik proxy berbahaya.

**CARA:**

- Nonaktifkan service **WinHTTP Web Proxy Auto-Discovery Service** (`WinHttpAutoProxySvc`):

```powershell
Stop-Service WinHttpAutoProxySvc -Force -ErrorAction SilentlyContinue
Set-Service  WinHttpAutoProxySvc -StartupType Disabled
```

- Buat **DNS sinkhole**: tambahkan record `wpad` (dan `isatap`) yang menunjuk ke alamat tidak valid, atau masukkan ke Global Query Block List DNS Server (default sudah memblok `wpad` & `isatap` — lihat §9).
- Matikan "Automatically detect settings" di pengaturan proxy via GPO.
- **Registry (nonaktifkan WPAD via WinHTTP):** sejak Windows 10 1809 / Windows Server 2019, set machine-wide `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp` → `DisableWpad` (DWORD) = `1`. Padanan per-user-nya adalah `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad` → `WpadOverride` (DWORD) = `1`. Ini menghentikan deteksi WPAD lewat WinHTTP API; aplikasi yang me-resolve nama `wpad` langsung via DNS tetap perlu mitigasi service + DNS GQBL di atas.

---

## 6. WinRM Hardening

WinRM (PowerShell Remoting, T1021.006) berguna untuk administrasi, tetapi default-nya bisa berbahaya bila Basic auth/HTTP polos diaktifkan.

**APA & KENAPA:**

| Hardening | Kenapa |
|-----------|--------|
| Gunakan listener **HTTPS (5986)**, bukan HTTP (5985) | Enkripsi transport, server authentication via sertifikat |
| Nonaktifkan **Basic authentication** | Basic mengirim kredensial mudah dipulihkan; paksa Kerberos/Negotiate |
| Nonaktifkan **AllowUnencrypted** | Cegah trafik manajemen polos di jaringan |
| Batasi **TrustedHosts** & scope firewall | Kurangi siapa yang bisa diajak bicara WinRM |

**CARA:**

```powershell
# Buat listener HTTPS dengan sertifikat (thumbprint dari Get-ChildItem Cert:\LocalMachine\My)
New-Item -Path WSMan:\localhost\Listener -Transport HTTPS -Address * `
  -Hostname "dc01.lab.local" -CertificateThumbPrint "<THUMBPRINT>" -Force

# Matikan Basic auth & trafik tidak terenkripsi (sisi Service)
Set-Item -Path WSMan:\localhost\Service\Auth\Basic        -Value $false
Set-Item -Path WSMan:\localhost\Service\AllowUnencrypted  -Value $false

# (Client) hindari Basic & unencrypted juga
Set-Item -Path WSMan:\localhost\Client\Auth\Basic         -Value $false
Set-Item -Path WSMan:\localhost\Client\AllowUnencrypted   -Value $false

# Batasi TrustedHosts (jangan pakai '*')
Set-Item -Path WSMan:\localhost\Client\TrustedHosts -Value "dc01.lab.local,mgmt01.lab.local" -Force
```

- **GPO:** `Computer Configuration > Policies > Administrative Templates > Windows Components > Windows Remote Management (WinRM) > WinRM Service`:
  - `Allow Basic authentication = Disabled`
  - `Allow unencrypted traffic = Disabled`
  - `Allow remote server management through WinRM` → batasi IPv4/IPv6 filter ke subnet management.
- Tutup port 5985 (HTTP) di firewall dan hanya izinkan 5986 (HTTPS) dari subnet admin (lihat §2.2).

---

## 7. Nonaktifkan Service & Fitur Tak Terpakai

**APA:** Audit service yang berjalan, terapkan **role minimal**, dan matikan service tidak terpakai.

**KENAPA:** Service yang mati bukan attack surface. Contoh paling kritis: **Print Spooler** di Domain Controller.

**CARA — inventaris & matikan:**

```powershell
# Lihat service yang berjalan otomatis
Get-Service | Where-Object {$_.Status -eq 'Running'} | Sort-Object Name

# Contoh: matikan Print Spooler di DC (PrintNightmare, CVE-2021-34527 / CVE-2021-1675, T1210)
Stop-Service Spooler -Force
Set-Service  Spooler -StartupType Disabled
```

| Service | Rekomendasi pada DC/Server | Alasan |
|---------|----------------------------|--------|
| `Spooler` (Print Spooler) | Disabled (kecuali print server) | PrintNightmare RCE/LPE |
| `WinHttpAutoProxySvc` (WPAD) | Disabled bila tak dipakai | Poisoning proxy (§5.4) |
| `RemoteRegistry` | Disabled/Manual | Recon & remote tampering |
| `SSDPSRV` / `upnphost` | Disabled di server | Tidak relevan, menambah surface |
| `lmhosts` (TCP/IP NetBIOS Helper) | Disabled bila NBT-NS off | Lihat §5.2 |
| `Fax`, `XblGameSave`, dll. | Disabled di server | Tidak dibutuhkan |

> Pakai **Microsoft Security Baseline** (Security Compliance Toolkit, dimiliki Modul 03) untuk daftar service yang direkomendasikan disabled secara terstandar, dan **AppLocker/WDAC** untuk membatasi eksekusi (juga Modul 03).

---

## 8. Legacy Protocol & Weak Cipher

### 8.1 Nonaktifkan TLS 1.0/1.1 & SSL 2.0/3.0 (SCHANNEL)

**APA:** Matikan protokol SChannel usang di sisi Server dan Client.

**KENAPA:** TLS 1.0/1.1 dan SSL 3.0 rentan (POODLE, BEAST, downgrade). Hanya TLS 1.2+ (idealnya 1.3) yang boleh.

> **Delta versi:** TLS 1.0/1.1 sudah **disabled by default** sejak Windows 11 dan update Windows Server 2022 terbaru, tetapi tetap set eksplisit untuk jaminan & host lama.

**CARA (Registry SCHANNEL):** untuk setiap protokol, buat subkey `Server` dan `Client` lalu set:

```reg
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server]
"Enabled"=dword:00000000
"DisabledByDefault"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client]
"Enabled"=dword:00000000
"DisabledByDefault"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server]
"Enabled"=dword:00000000
"DisabledByDefault"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server]
"Enabled"=dword:00000000
"DisabledByDefault"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server]
"Enabled"=dword:00000000
"DisabledByDefault"=dword:00000001
```

(Ulangi pasangan `Server`+`Client` untuk TLS 1.1, SSL 3.0, SSL 2.0. Restart diperlukan.)

### 8.2 Nonaktifkan Weak Cipher (RC4, DES, 3DES)

**APA:** Matikan cipher lemah di subkey `...\SCHANNEL\Ciphers`.

**KENAPA:** RC4 rentan dan dipakai pada serangan Kerberoasting downgrade (RC4 Kerberos → kebijakan Kerberos/RC4 dimiliki Modul 02). 3DES rentan SWEET32.

```reg
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128]
"Enabled"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168]
"Enabled"=dword:00000000
```

> Cara terkelola yang lebih bersih: GPO `Computer Configuration > Policies > Administrative Templates > Network > SSL Configuration Settings > SSL Cipher Suite Order`, atau cmdlet `Disable-TlsCipherSuite -Name <suite>`.

### 8.3 Nonaktifkan PowerShell v2

**APA:** Hapus engine PowerShell 2.0.

**KENAPA:** PSv2 **tidak mendukung** Script Block Logging, AMSI, maupun Constrained Language Mode — sering dipakai sebagai **downgrade attack** untuk bypass logging (T1059.001). Detail logging PowerShell dimiliki Modul 06.

```powershell
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2     -NoRestart
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart
```

---

## 9. DNS Service Security

Berlaku untuk Windows DNS Server (umumnya di DC).

### 9.1 Secure Dynamic Updates

**APA:** Set zona AD-integrated agar hanya menerima update terotentikasi.

**KENAPA:** Dynamic update non-secure memungkinkan host jahat menimpa record (mis. membajak record sensitif, mendukung spoofing/relay).

```powershell
Set-DnsServerPrimaryZone -Name "lab.local" -DynamicUpdate Secure
```

- **GUI:** `dnsmgmt.msc` → zona → Properties → General → Dynamic updates = **Secure only**.

### 9.2 Batasi / Nonaktifkan Recursion

**APA:** Bila DNS server hanya authoritative (bukan resolver untuk klien internet), nonaktifkan recursion.

**KENAPA:** Open resolver rentan **cache poisoning** dan **DNS amplification DDoS** (T1498). DC yang me-resolve untuk klien internal tetap butuh recursion — sesuaikan peran.

```powershell
Set-DnsServerRecursion -Enable $false   # hanya jika server bukan resolver klien
```

### 9.3 Cache Locking, Socket Pool, & Global Query Block List

**APA & KENAPA:**

| Kontrol | Cmdlet | Tujuan |
|---------|--------|--------|
| Cache Locking 100% | `Set-DnsServerCache -LockingPercent 100` | Cegah overwrite cache sebelum TTL (anti cache poisoning) |
| Socket Pool besar | `dnscmd /config /socketpoolsize 10000` | Acak source port → persulit poisoning |
| Global Query Block List | `Get-DnsServerGlobalQueryBlockList` | Default memblok `wpad` & `isatap` (mendukung §5.4) |

> Default socket pool size adalah 2500; maksimum 10000. (Sumber: Microsoft Learn — DNS server security.)

### 9.4 Response Rate Limiting (RRL)

**APA:** Batasi laju respons identik untuk meredam penyalahgunaan amplifikasi.

```powershell
Set-DnsServerResponseRateLimiting -Mode Enable
```

### 9.5 DNSSEC & Logging

- **DNSSEC** menandatangani zona untuk integritas resolusi (anti-tamper jawaban). Tanda-tangani via `dnsmgmt.msc` atau `Invoke-DnsServerZoneSign`.
- **Logging query DNS** (analytic/audit) untuk deteksi tunneling/eksfil (T1071.004) → konfigurasi & Event ID dimiliki **Modul 06**.

---

## 10. IPsec / Domain Isolation

**APA:** Connection Security Rules (WFAS) yang memaksa autentikasi+integritas (opsional enkripsi) antar-host domain, sehingga host non-domain tidak bisa berkomunikasi (Domain Isolation / Server Isolation).

**KENAPA:** Kontrol lanjutan yang mempersempit lateral movement dan blocking perangkat rogue di segmen sensitif — efektif melengkapi firewall L3/L4 dengan autentikasi identitas mesin.

**CARA (ringkas):**

```powershell
New-NetIPsecRule -DisplayName "Domain Isolation - Require Inbound Auth" `
  -InboundSecurity Require -OutboundSecurity Request -Profile Domain
# Main mode default memakai Kerberos v5 (computer auth). Untuk auth/crypto kustom,
# buat set dulu (New-NetIPsecPhase1AuthSet / New-NetIPsecQuickModeCryptoSet) lalu
# rujuk via -Phase1AuthSet / -QuickModeCryptoSet dengan NAMA set (string), bukan objek.
```

- **GUI/GPO:** `wf.msc` → Connection Security Rules → New Rule → Isolation → "Require authentication for inbound, request for outbound". Distribusikan via GPO → **lihat Modul 03**. Uji bertahap (Request dulu, baru Require) agar tidak memutus konektivitas.

---

## Serangan Umum & Mitigasi

| Serangan | Teknik / CVE | MITRE | Mitigasi di modul ini |
|----------|--------------|-------|------------------------|
| **LLMNR/NBT-NS poisoning (Responder)** | Spoof respons multicast, curi NetNTLM | T1557.001 | §5.1–5.3 matikan LLMNR/NBT-NS/mDNS |
| **SMB relay / NTLM relay** | Relay NetNTLM ke host lain | T1557.001 | §3.2 SMB signing, §3.3 encryption, §6 WinRM HTTPS |
| **Forced authentication (PetitPotam)** | Paksa DC autentikasi lalu relay | T1187 | SMB signing + LDAP signing (Modul 02), batasi anonim (§3.5) |
| **EternalBlue** | MS17-010 / CVE-2017-0144 di SMBv1 | T1210 | §3.1 hapus SMBv1 |
| **BlueKeep** | CVE-2019-0708 RDP pra-auth | T1210 | §4.1 NLA wajib, patch, firewall scope |
| **RDP brute force** | Tebak kredensial 3389 | T1110 / T1021.001 | §4.3 batasi user, lockout (Modul 02), §2.2 scope, RD Gateway |
| **PrintNightmare** | CVE-2021-34527 Spooler RCE/LPE | T1210 / T1068 | §7 disable Spooler di DC |
| **DNS cache poisoning / amplification** | Open resolver, spoof | T1498 / T1584 | §9.2–9.4 disable recursion, cache locking, RRL, socket pool |
| **Network discovery / port scan** | Enumerasi service terbuka | T1046 | §2 default-deny inbound + scope, §7 matikan service |
| **Cleartext mgmt sniffing** | Tangkap kredensial WinRM/RDP polos | T1040 | §6 HTTPS, §4.2 TLS, §8 matikan cipher lemah |

---

## Hardening Checklist (Modul Ini)

- [ ] Ketiga firewall profile (Domain/Private/Public) **On**, Inbound = **Block**, Outbound = Allow.
- [ ] Rule inbound hanya untuk port yang dibutuhkan, dengan **RemoteAddress scope** ke subnet management.
- [ ] Firewall **logging dropped packets** aktif, `LogMaxSizeKilobytes ≥ 16384`.
- [ ] Firewall dikelola via **GPO** (Modul 03), bukan per-host.
- [ ] **SMBv1 dinonaktifkan/dihapus** (`EnableSMB1Protocol $false` + feature removed).
- [ ] **SMB signing wajib** di server & client (`RequireSecuritySignature $true`).
- [ ] **SMB encryption** aktif untuk share sensitif (`EncryptData $true`).
- [ ] **Insecure guest logons disabled**; null session/anonymous dibatasi (Modul 03).
- [ ] **RDP: NLA wajib**, SecurityLayer = TLS (2), Encryption = High (3).
- [ ] User RDP dibatasi; **3389 tidak terekspos ke internet** (RD Gateway/VPN).
- [ ] **LLMNR off** (`EnableMulticast 0`), **NBT-NS off** (`NetbiosOptions 2`), **mDNS off** (`EnableMDNS 0`).
- [ ] **WPAD dimitigasi** (service disabled + GQBL/DNS sinkhole).
- [ ] **WinRM**: listener HTTPS, Basic auth & AllowUnencrypted **disabled**, TrustedHosts dibatasi.
- [ ] **Print Spooler disabled** di DC; service tak terpakai dimatikan.
- [ ] **TLS 1.0/1.1 & SSL 2.0/3.0 disabled**; **RC4/3DES disabled** (SCHANNEL).
- [ ] **PowerShell v2 dinonaktifkan**.
- [ ] **DNS**: secure dynamic updates, recursion sesuai peran, cache locking 100%, RRL aktif.

---

## Lab Praktik

**Topologi:** `DC01` (Windows Server 2022, AD DS + DNS), `CLIENT01` (Windows 11), `ATTACKER` (Kali/Linux untuk Responder & nmap). Semua di subnet lab `10.10.0.0/24`.

### Lab 1 — Firewall default-deny via GPO

1. Di `DC01`, buat GPO baru (lihat Modul 03) bernama `WS - Network Hardening`, link ke OU server.
2. Set profile properties: Inbound = Block, Outbound = Allow, Logging on (16384 KB).
3. Tambahkan inbound rule: izinkan TCP 3389 hanya dari `10.10.0.0/24`.
4. **Lakukan:** `gpupdate /force` di `CLIENT01`. **Konfirmasi dengan:**
   `Get-NetFirewallProfile | ft Name,Enabled,DefaultInboundAction` → semua `Block`.

### Lab 2 — Nonaktifkan SMBv1 + wajibkan signing

1. **Lakukan:**
   ```powershell
   Set-SmbServerConfiguration -EnableSMB1Protocol $false -RequireSecuritySignature $true -Force
   ```
2. **Konfirmasi dengan:**
   ```powershell
   Get-SmbServerConfiguration | Select EnableSMB1Protocol,RequireSecuritySignature
   ```
   Harapkan `EnableSMB1Protocol = False`, `RequireSecuritySignature = True`.

### Lab 3 — Matikan LLMNR/NBT-NS lalu uji Responder

1. Jalankan `Responder -I eth0` di `ATTACKER` **sebelum** hardening; trigger resolusi nama salah dari `CLIENT01` (`\\typoshare\x`) → amati hash tertangkap (NetNTLMv2).
2. **Lakukan** hardening: set `EnableMulticast=0` (LLMNR), `SetTcpipNetbios(2)` (NBT-NS), `EnableMDNS=0` di `CLIENT01`, lalu `gpupdate /force` / reboot.
3. **Konfirmasi dengan:** ulangi trigger; Responder **tidak** lagi menangkap hash. Verifikasi registry:
   ```powershell
   Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' EnableMulticast
   ```

### Lab 4 — Port scan dari mesin lain

1. Dari `ATTACKER`: `nmap -Pn -p 1-1024,3389,5985,5986,445 10.10.0.X`.
2. **Konfirmasi:** sebelum hardening banyak port `open`; setelah default-deny + scope, port admin tampak `filtered`/tertutup kecuali dari subnet yang diizinkan.

---

## Perintah Audit/Verifikasi

```powershell
# Firewall: profile aktif & default action (harapkan Inbound=Block)
Get-NetFirewallProfile | Format-Table Name,Enabled,DefaultInboundAction,DefaultOutboundAction,LogBlocked,LogMaxSizeKilobytes

# Firewall: daftar rule inbound yang Allow + scope-nya
Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True |
  Get-NetFirewallAddressFilter | Format-Table RemoteAddress

# SMB server config (harapkan SMB1=False, RequireSecuritySignature=True, EncryptData sesuai)
Get-SmbServerConfiguration | Select EnableSMB1Protocol,RequireSecuritySignature,EncryptData,RejectUnencryptedAccess
# SMB client
Get-SmbClientConfiguration | Select RequireSecuritySignature,EnableInsecureGuestLogons

# Cek apakah SMBv1 feature masih terpasang (harapkan State = Disabled)
Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol | Select FeatureName,State

# RDP: NLA/SecurityLayer/Encryption (harapkan 1 / 2 / 3)
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' |
  Select UserAuthentication,SecurityLayer,MinEncryptionLevel

# LLMNR / NBT-NS / mDNS
Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' EnableMulticast -EA SilentlyContinue
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' EnableMDNS -EA SilentlyContinue
Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE" | Select Description,TcpipNetbiosOptions

# WinRM service config (harapkan Basic=false, AllowUnencrypted=false)
winrm get winrm/config/service
Get-Item WSMan:\localhost\Service\Auth\Basic, WSMan:\localhost\Service\AllowUnencrypted

# Service yang harus mati (harapkan Status=Stopped, StartType=Disabled)
Get-Service Spooler,RemoteRegistry,WinHttpAutoProxySvc | Select Name,Status,StartType

# SCHANNEL: cek TLS 1.0 disabled (harapkan Enabled=0)
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -EA SilentlyContinue

# PowerShell v2 (harapkan State = Disabled)
Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 | Select State

# DNS server (harapkan RecursionEnabled sesuai peran; LockingPercent=100)
Get-DnsServerRecursion | Select Enable
Get-DnsServerCache | Select LockingPercent
Get-DnsServerGlobalQueryBlockList   # harapkan memuat 'wpad','isatap'

# Port listening aktual di host
Get-NetTCPConnection -State Listen | Select LocalAddress,LocalPort | Sort-Object LocalPort
```

---

## Referensi

- **Microsoft Security Baseline** (Windows Server 2022 & Windows 11) — Security Compliance Toolkit, Policy Analyzer, LGPO.exe (mekanisme di Modul 03).
- **CIS Microsoft Windows Server 2022 Benchmark** & **CIS Microsoft Windows 11 Enterprise Benchmark** — §Windows Defender Firewall, §MS Network Server/Client (SMB signing), §Network access (anonymous), §Administrative Templates (LLMNR, RDP, WinRM).
- **Microsoft Learn:**
  - "Stop using SMB1" / "Detect, enable and disable SMBv1, SMBv2, and SMBv3" (`Set-SmbServerConfiguration`).
  - "SMB signing and encryption overview" (delta default Win11 24H2 / Server 2025).
  - "Network security: configure encryption types / RDP security layer".
  - "Configure DNS server security" (cache locking, socket pool, RRL, Global Query Block List).
  - "Windows Defender Firewall with Advanced Security design guide" (profiles, Connection Security Rules / IPsec).
  - "WinRM / PowerShell Remoting security".
- **MITRE ATT&CK:** T1557 (Adversary-in-the-Middle), T1557.001 (LLMNR/NBT-NS Poisoning & SMB Relay), T1187 (Forced Authentication), T1210 (Exploitation of Remote Services), T1021.001/.002/.006 (RDP/SMB/WinRM), T1110 (Brute Force), T1046 (Network Service Discovery), T1498 (Network DoS).
- **Lintas modul:** Modul 01 (Restricted Admin/Remote Credential Guard, tiered RDP), Modul 02 (lockout, Kerberos/RC4, LDAP signing, anonymous restrictions sumber nilai), Modul 03 (GPO mechanism, Security Options, User Rights, AppLocker/WDAC, SCT), Modul 06 (audit policy, Event ID, DNS/PowerShell logging).
