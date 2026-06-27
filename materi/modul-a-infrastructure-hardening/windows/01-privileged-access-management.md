# Modul 01 — Privileged Access Management (PAM)

> Privileged Access Management adalah disiplin mengelola, membatasi, dan mengaudit akun berhak istimewa (admin domain, admin server, admin workstation, service account) sehingga kompromi satu host tidak otomatis menjadi kompromi seluruh domain. Dari sudut pandang penyerang, kredensial admin yang "menganggur" di memori (LSASS), cache logon, atau di SAM lokal adalah jalan tercepat menuju Domain Admin lewat Pass-the-Hash, Pass-the-Ticket, dan lateral movement — PAM dirancang khusus untuk menutup jalan itu dengan menghapus *standing access*, mengisolasi tier, dan merandomisasi password lokal per host.

## Daftar Isi

1. [Konsep & Tujuan](#1-konsep--tujuan)
2. [Tiered Administration Model (Enterprise Access Model)](#2-tiered-administration-model-enterprise-access-model)
3. [Privileged Access Workstation (PAW)](#3-privileged-access-workstation-paw)
4. [Protected Users Security Group](#4-protected-users-security-group)
5. [Authentication Policies & Authentication Policy Silos](#5-authentication-policies--authentication-policy-silos)
6. [Windows LAPS](#6-windows-laps)
7. [Just-In-Time (JIT) Access & Time-Based Group Membership](#7-just-in-time-jit-access--time-based-group-membership)
8. [Just Enough Administration (JEA)](#8-just-enough-administration-jea)
9. [Group Managed Service Accounts (gMSA)](#9-group-managed-service-accounts-gmsa)
10. [Mengamankan Built-in Administrator & Breakglass](#10-mengamankan-built-in-administrator--breakglass)
11. [Credential Guard & Remote Credential Guard / Restricted Admin](#11-credential-guard--remote-credential-guard--restricted-admin)
12. [Serangan Umum & Mitigasi](#serangan-umum--mitigasi)
13. [Hardening Checklist (Modul Ini)](#hardening-checklist-modul-ini)
14. [Lab Praktik](#lab-praktik)
15. [Perintah Audit/Verifikasi](#perintah-auditverifikasi)
16. [Referensi](#referensi)

---

## 1. Konsep & Tujuan

PAM bertumpu pada empat prinsip inti. Kuasai definisinya — penilai LKS sering menanyakan *kenapa*, bukan hanya *bagaimana*.

| Prinsip | Definisi singkat | Implikasi praktis |
|---|---|---|
| **Least Privilege** | Akun hanya diberi hak seminimal mungkin untuk menyelesaikan tugasnya. | Tidak ada helpdesk di Domain Admins; admin server tidak boleh admin di workstation. |
| **Standing Access vs Just-In-Time** | *Standing access* = keanggotaan grup berhak yang permanen. *JIT* = hak diberikan hanya saat dibutuhkan, dengan masa kedaluwarsa otomatis. | Hilangkan keanggotaan permanen Domain Admins; berikan via TTL/approval saat perlu saja. |
| **Assume Breach** | Anggap satu endpoint sudah dikuasai penyerang. Desain agar kompromi itu *tidak menyebar*. | Isolasi tier, randomisasi password lokal, batasi di mana kredensial admin boleh dipakai. |
| **Clean Source Principle** | Objek hanya boleh diamankan oleh objek yang minimal sama tepercayanya. Sumber kontrol harus lebih bersih dari target. | DC (Tier 0) tidak boleh dikelola dari workstation biasa (Tier 2); gunakan PAW. |

**Tujuan modul:** menghapus kredensial berhak istimewa dari permukaan serang yang mudah dijangkau, dan memastikan setiap penggunaan hak istimewa bersifat sementara, terbatas lokasi, dan terverifikasi. Kebijakan password/lockout dan policy Kerberos (lifetime tiket, RC4, KRBTGT) bukan milik modul ini — **-> lihat Modul 02**. Mekanisme membuat & me-link GPO serta User Rights Assignment (URA) **-> lihat Modul 03**. Daftar Event ID & audit policy detail **-> lihat Modul 06**.

---

## 2. Tiered Administration Model (Enterprise Access Model)

**APA.** Model yang membagi seluruh aset dan identitas administratif menjadi tiga lapisan tepercaya. Microsoft kini menyebutnya **Enterprise Access Model** (evolusi dari "Active Directory tier model" / "Tiering" lama).

| Tier | Cakupan | Contoh aset |
|---|---|---|
| **Tier 0** | Identity & control plane — kendali atas seluruh direktori. | Domain Controllers, AD CS (CA), Azure AD Connect / Entra Connect, akun & grup yang mengontrolnya (Domain Admins, Enterprise Admins, Schema Admins). |
| **Tier 1** | Server & aplikasi enterprise. | Member server, file server, database, aplikasi bisnis, admin server. |
| **Tier 2** | Workstation & device. | Klien Windows 10/11, perangkat pengguna, helpdesk / admin desktop. |

**KENAPA.** Aturan emas: **kredensial tier yang lebih tinggi tidak boleh terekspos di tier yang lebih rendah.** Jika seorang Domain Admin (Tier 0) login interaktif ke workstation Tier 2 yang sudah dikompromi, hash/tiket NT-nya tersimpan di memori host itu dan bisa dicuri (Pass-the-Hash → Domain Admin). Tiering menegakkan *clean source*: aset bernilai tinggi hanya dikelola dari sumber yang sama bersihnya.

**Aturan logon antar-tier (wajib hafal):**

- Akun Tier 0 **hanya** boleh logon ke aset Tier 0.
- Akun Tier 1 tidak boleh logon ke Tier 2; akun Tier 2 tidak boleh logon ke Tier 1/0.
- Tier yang lebih rendah **tidak pernah** mengontrol tier yang lebih tinggi (helpdesk tidak reset password admin domain).

**CARA — struktur OU untuk tiering.** Pisahkan akun, grup, dan komputer per tier agar bisa ditarget GPO dan delegasi terpisah:

```text
OU=Admin
├── OU=Tier 0
│   ├── OU=Accounts        (akun admin Tier 0)
│   ├── OU=Groups          (grup peran Tier 0)
│   └── OU=Devices         (DC, PAW Tier 0)
├── OU=Tier 1
│   ├── OU=Accounts
│   ├── OU=Groups
│   └── OU=Servers
└── OU=Tier 2
    ├── OU=Accounts
    ├── OU=Groups
    └── OU=Workstations
```

```powershell
# Membuat kerangka OU tiering (jalankan di DC, modul ActiveDirectory)
$base = "DC=lks,DC=local"
New-ADOrganizationalUnit -Name "Admin" -Path $base -ProtectedFromAccidentalDeletion $true
foreach ($t in 0..2) {
    $tierPath = "OU=Admin,$base"
    New-ADOrganizationalUnit -Name "Tier $t" -Path $tierPath -ProtectedFromAccidentalDeletion $true
    foreach ($sub in "Accounts","Groups","Devices") {
        New-ADOrganizationalUnit -Name $sub -Path "OU=Tier $t,$tierPath" -ProtectedFromAccidentalDeletion $true
    }
}
```

**CARA — penegakan logon.** Pemisahan tier ditegakkan dengan **User Rights Assignment** lewat GPO yang di-link ke tiap OU tier, menggunakan hak *deny*:

- `Deny log on locally`
- `Deny log on through Remote Desktop Services`
- `Deny access to this computer from the network`
- `Deny log on as a batch job`
- `Deny log on as a service`

Isi grup Tier 0 ke dalam hak *deny* pada GPO Tier 1 & Tier 2 (dan sebaliknya). Cara membuat GPO, mengisi URA, security filtering, dan loopback **-> lihat Modul 03**.

---

## 3. Privileged Access Workstation (PAW)

**APA.** Workstation khusus yang sudah dihardening, dipakai **hanya** untuk tugas administratif terhadap satu tier tertentu (idealnya satu PAW per tier). PAW tidak dipakai untuk browsing web, email, atau aplikasi produktivitas umum.

**KENAPA.** Mayoritas kompromi endpoint datang dari email (phishing) dan web (drive-by, malicious script). Jika admin membuka email/web dari host yang sama tempat ia mengetik kredensial Domain Admin, satu klik berbahaya = pencurian kredensial Tier 0. PAW memisahkan permukaan serang berisiko tinggi (internet) dari kredensial bernilai tinggi. Ini implementasi langsung dari *clean source principle* dan *assume breach*.

**Prinsip dasar PAW:**

| Aspek | Aturan |
|---|---|
| Penggunaan | Hanya administrasi; tidak ada browsing/email/Office umum dari host PAW. |
| Arah pemisahan | Model yang dianjurkan: pekerjaan harian di VM/perangkat terpisah, administrasi di host PAW bersih (bukan sebaliknya — host admin lebih tepercaya dari VM user). |
| Internet | Diblok kecuali endpoint manajemen yang diperlukan (Windows Update, AD, log). |
| Hardening | Application control: AppLocker/WDAC -> Modul 03 (integrasi Defender/Device Guard -> Modul 05), Credential Guard aktif (bagian 11), firewall ketat (-> Modul 04). |
| Akun | Hanya akun tier yang sesuai boleh logon ke PAW tier itu. |

Model hardware: PAW fisik terpisah (paling kuat), atau model "user VM di atas host PAW" di mana host adalah PAW bersih dan pekerjaan berisiko berjalan di dalam VM tamu yang tidak tepercaya.

**CARA — hardening PAW (command konkret).** Lima kontrol di bawah mengubah prinsip di atas menjadi konfigurasi yang dapat dijalankan & diverifikasi. Jalankan di host PAW (lewat GPO yang di-link ke OU `Devices` Tier 0 → mekanisme link milik **Modul 03**, atau lokal via `LGPO.exe`/registry untuk PAW standalone).

**(a) Application control allow-list (AppLocker).** PAW hanya boleh menjalankan tool admin yang disetujui. Default-deny: izinkan hanya `Windows` + `Program Files` + tool admin ber-signature, blokir sisanya.

```powershell
# Susun allow-list berbasis Publisher dari tool admin tepercaya, plus default rules OS
$ref = Get-ChildItem "C:\Program Files\AdminTools\*.exe" -Recurse | Get-AppLockerFileInformation
New-AppLockerPolicy -RuleType Publisher,Hash -User "PAW-Admins" -FileInformation $ref `
    -Optimize -Xml | Out-File C:\PAW\paw-applocker.xml
# Import & set Enforce (mulai dari Audit only lebih dulu — lihat Modul 03 Bagian 8)
Set-AppLockerPolicy -XmlPolicy C:\PAW\paw-applocker.xml -Merge
Set-Service AppIDSvc -StartupType Automatic; Start-Service AppIDSvc
```

> **Caveat bypass (penting):** *default Path rules* AppLocker mengizinkan seluruh `%WINDIR%`, padahal beberapa sub-folder di bawahnya **writable oleh user non-admin** (mis. `C:\Windows\Tasks`, `C:\Windows\Temp`, `C:\Windows\System32\spool\drivers\color`, `C:\Windows\tracing`). Penyerang men-drop EXE/script ke sana dan lolos. Untuk PAW: andalkan **Publisher rules** (bukan path lebar), atau tambahkan **deny rule** eksplisit untuk sub-folder writable tersebut. Penegakan kernel anti-tamper yang paling kuat untuk Tier 0 adalah **WDAC/App Control for Business** (-> Modul 03 Bagian 8). Detail caveat ini juga dirujuk di Modul 03.

**(b) Blokir outbound internet, izinkan hanya endpoint manajemen (`New-NetFirewallRule`).** PAW tidak boleh browsing. Pakai *default-deny outbound* TAPI **wajib** disertai allow-rule untuk DC/Kerberos/LDAP, DNS, Windows Update/WSUS, dan log collector — tanpa itu logon domain & fungsi PAW mati total.

```powershell
# 1) Allow dulu endpoint manajemen yang vital (ganti subnet/IP dengan milik lab).
#    Daftar port di bawah BUKAN exhaustive — sesuaikan dengan service yang dipakai lab.
$dc = "10.0.0.10"        # DC: Kerberos 88, LDAP 389/636, GC 3268/3269, SMB 445, kpasswd 464, RPC 135
$wsus = "10.0.0.20"      # WSUS/Update
$siem = "10.0.0.30"      # Log collector / WEC
New-NetFirewallRule -DisplayName "PAW-Allow-DC-TCP" -Direction Outbound -Action Allow `
    -RemoteAddress $dc -Protocol TCP -RemotePort 88,135,389,636,445,464,3268,3269
# UDP WAJIB: 123 = NTP (tanpa ini jam melenceng → Kerberos GAGAL setelah beberapa jam/hari),
#            53 = DNS, 88 = Kerberos, 464 = kpasswd
New-NetFirewallRule -DisplayName "PAW-Allow-DC-UDP" -Direction Outbound -Action Allow `
    -RemoteAddress $dc -Protocol UDP -RemotePort 53,88,123,464
New-NetFirewallRule -DisplayName "PAW-Allow-WSUS" -Direction Outbound -Action Allow `
    -RemoteAddress $wsus -RemotePort 8530,8531 -Protocol TCP
New-NetFirewallRule -DisplayName "PAW-Allow-SIEM" -Direction Outbound -Action Allow `
    -RemoteAddress $siem -RemotePort 5985,5986 -Protocol TCP

# 2) BARU set default-deny outbound pada profil Domain (allow-rule di atas tetap menang)
Set-NetFirewallProfile -Profile Domain -DefaultOutboundAction Block -DefaultInboundAction Block
```

> Urutan penting: buat allow-rule **sebelum** mengaktifkan `-DefaultOutboundAction Block`, agar PAW tidak kehilangan jalur ke DC saat aturan diterapkan. Transport firewall lanjutan -> **Modul 04**.

**(c) Tolak removable storage** (cegah exfil/drop malware dari/ke USB di host bernilai tinggi):

```reg
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices]
"Deny_All"=dword:00000001
```

> Setara GPO `Computer Configuration > Administrative Templates > System > Removable Storage Access > All Removable Storage classes: Deny all access` (detail di **Modul 03 Bagian 9.1**).

**(d) Aktifkan Credential Guard (`LsaCfgFlags=1`)** agar secret LSASS PAW terisolasi VBS — kunci, karena di PAW-lah kredensial Tier 0 diketik:

```reg
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa]
"LsaCfgFlags"=dword:00000001
```

> `1` = ON dengan UEFI lock. Konfigurasi VBS lengkap & verifikasi `SecurityServicesRunning` ada di **Bagian 11**.

**(e) URA deny-logon — kunci PAW hanya untuk akun tier-nya.** Hanya admin Tier 0 boleh logon ke PAW Tier 0; semua akun lain (termasuk user biasa & Tier 1/2) ditolak. Set via GPO `Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > User Rights Assignment` (mekanisme INF/secedit milik **Modul 03 Bagian 6.2**):

```ini
; Cuplikan GptTmpl.inf untuk GPO PAW (replace, bukan append — sertakan akun sah!)
[Privilege Rights]
; Izinkan logon lokal HANYA Administrators + grup admin Tier 0
SeInteractiveLogonRight = *S-1-5-32-544,LKS\Tier0-Admins
; Tolak akses jaringan & RDP untuk akun non-Tier0 dan Guest
SeDenyNetworkLogonRight = LKS\Tier1-Admins,LKS\Tier2-Admins,LKS\Domain Users
SeDenyRemoteInteractiveLogonRight = LKS\Tier1-Admins,LKS\Tier2-Admins,LKS\Domain Users
```

**Langkah konfirmasi PAW (jalankan di host PAW):**

```powershell
# AppLocker efektif & service jalan
Get-AppLockerPolicy -Effective -Xml; Get-Service AppIDSvc | Select Status,StartType   # Running/Automatic
# Firewall default-deny outbound aktif + allow-rule terdaftar
(Get-NetFirewallProfile -Profile Domain).DefaultOutboundAction                          # Block
Get-NetFirewallRule -DisplayName "PAW-Allow-*" | Select DisplayName,Enabled,Direction,Action
# Removable storage tertolak
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices" /v Deny_All  # 0x1
# Credential Guard berjalan
(Get-CimInstance Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).SecurityServicesRunning  # memuat 1
# URA deny-logon efektif
secedit /export /cfg C:\paw-eff.inf   # periksa SeDenyNetworkLogonRight / SeInteractiveLogonRight
```

---

## 4. Protected Users Security Group

**APA.** Grup keamanan domain bawaan (`Protected Users`) yang memberi proteksi kredensial agresif bagi anggotanya — ditujukan untuk akun admin bernilai tinggi.

**KENAPA.** Memaksa anggotanya hanya memakai mekanisme autentikasi modern (Kerberos AES) dan mematikan jalur yang bisa di-replay/dicuri (NTLM hash, cached logon, delegasi). Ini menutup Pass-the-Hash dan banyak teknik pencurian kredensial pada akun yang paling diincar.

**Efek persis pada anggota (sisi klien butuh Windows 8.1 / Server 2012 R2+):**

| Proteksi | Efek |
|---|---|
| NTLM | Tidak bisa autentikasi via NTLM (hanya Kerberos). |
| Digest / CredSSP / WDigest | Kredensial tidak di-cache untuk Digest maupun CredSSP. |
| Cached logon | Tidak ada cached credential — **tidak bisa logon saat DC tidak terjangkau (offline)**. |
| Kerberos cipher | Hanya AES; **DES dan RC4 ditolak** untuk pre-authentication. |
| Delegasi | Akun tidak bisa didelegasikan (unconstrained maupun constrained). |
| TGT lifetime | TGT dibatasi **4 jam (non-renewable)** — nilai *fixed* milik fitur ini, bukan setting yang bisa diubah. |

**Syarat & risiko (PENTING):**

- **Syarat:** Domain Controller minimal Windows Server **2012 R2** (grup dibuat saat PDC emulator sudah 2012 R2+).
- **RISIKO LOCKOUT:** Karena NTLM, cached logon, dan RC4 dimatikan, memasukkan akun ke grup ini secara prematur dapat **mengunci akun**. Contoh: akun service yang masih bergantung NTLM, aplikasi yang butuh delegasi, atau admin yang biasa logon ke host tanpa konektivitas DC akan gagal. **Jangan masukkan built-in Administrator domain** ke Protected Users (risiko lockout total/breakglass terhambat). Uji satu akun non-kritis dulu, validasi, baru perluas.

**CARA.**

```powershell
# Tambahkan akun admin (uji satu dulu!) ke Protected Users
Add-ADGroupMember -Identity "Protected Users" -Members "t0-admin01"

# Lihat anggota saat ini
Get-ADGroupMember -Identity "Protected Users" | Select-Object SamAccountName
```

GUI: Active Directory Users and Computers (ADUC) → container `Users` → grup `Protected Users` → Members.

---

## 5. Authentication Policies & Authentication Policy Silos

**APA.** Mekanisme AD untuk membatasi **di mana** akun privileged boleh autentikasi (host mana yang boleh menerima TGT-nya) dan menetapkan TGT lifetime per kelompok akun. *Authentication Policy* mendefinisikan kondisi; *Authentication Policy Silo* mengelompokkan user, komputer, dan service account yang saling terikat.

**KENAPA.** Protected Users mengeraskan *cara* akun autentikasi; Silo mengeraskan *lokasi*. Dengan silo, akun Tier 0 hanya bisa autentikasi dari PAW/DC Tier 0 — meskipun penyerang mencuri kredensialnya, kredensial itu tidak dapat dipakai dari host lain. Ini menutup lateral movement dengan kredensial curian.

**Syarat:**

- Domain functional level minimal **Windows Server 2012 R2**.
- **Kerberos armoring (FAST)** dan *compound authentication* harus didukung DC dan klien (diaktifkan via GPO -> lihat Modul 02/03).

**CARA (GUI).** Active Directory Administrative Center (ADAC) → **Authentication** → **Authentication Policies** (buat policy, set TGT lifetime, mis. 240 menit, dan untuk audit centang **"Only audit policy restrictions"**) lalu **Authentication Policy Silos** (buat silo, assign akun **dan komputer DC/PAW**, tautkan policy).

> **FOOTGUN LOCKOUT (wajib paham sebelum eksekusi).** `UserAllowedToAuthenticateFrom` **membatasi dari host mana** seorang user boleh memperoleh TGT. Kondisi SDDL di bawah mengizinkan autentikasi **hanya dari device yang menjadi anggota silo**. Karena itu **komputer Tier 0 (DC dan PAW) WAJIB dimasukkan ke silo** — kalau tidak, mereka tidak membawa klaim `AuthenticationSilo`, sehingga admin Tier 0 **tidak bisa logon ke mana pun** (lockout total). Maka: (1) buat silo **audit-only** dulu, (2) assign user **dan** computer DC/PAW, (3) validasi log gagal kosong, baru (4) `-Enforce $true`. Catatan penyelamat: **built-in Administrator (RID 500) selalu dikecualikan** dari Authentication Policy meski di-assign ke silo — jalur breakglass tetap hidup.

**Prasyarat tambahan untuk `AllowedToAuthenticateFrom`:** butuh **Dynamic Access Control / Kerberos armoring (FAST)** aktif di DC & klien (klaim/compound auth) — kondisi device tidak dapat diterapkan ke akun *system* tanpa armoring. Setelah konfigurasi, **ganti password akun terproteksi** agar cache kredensial lama tak bisa dipakai.

```powershell
# === FASE 1 — AUDIT-ONLY (belum mengunci siapa pun) ===
# SDDL: izinkan TGT hanya dari device anggota "T0-Silo" (device = "User" dalam konteks ini)
$sddl = 'O:SYG:SYD:(XA;OICI;CR;;;WD;(@USER.ad://ext/AuthenticationSilo == "T0-Silo"))'
#   (alternatif: muat dari file → (Get-Acl .\paw-sddl.txt).sddl )

# Policy: TGT 240 menit + kondisi device; -Enforce:$false = hanya audit (Event di
# "Authentication Policy Failures - Domain Controller" log, TANPA benar-benar memblokir)
New-ADAuthenticationPolicy -Name "T0-Auth-Policy" `
    -UserTGTLifetimeMins 240 `
    -UserAllowedToAuthenticateFrom $sddl `
    -Enforce:$false

# Silo (default audit-only). Catatan: kondisi device di policy bersifat USER-scoped
# (UserAllowedToAuthenticateFrom), jadi TIDAK membatasi akun komputer DC/PAW itu sendiri —
# DC/PAW dimasukkan ke silo HANYA agar memancarkan klaim AuthenticationSilo (Fase assign).
New-ADAuthenticationPolicySilo -Name "T0-Silo" `
    -UserAuthenticationPolicy "T0-Auth-Policy" `
    -ComputerAuthenticationPolicy "T0-Auth-Policy" `
    -ServiceAuthenticationPolicy "T0-Auth-Policy"

# Assign + grant akses: user admin Tier 0 DAN komputer DC/PAW (tanpa ini → lockout)
foreach ($u in "t0-admin01","t0-admin02") {
    Grant-ADAuthenticationPolicySiloAccess -Identity "T0-Silo" -Account $u
    Set-ADAccountAuthenticationPolicySilo -Identity $u -AuthenticationPolicySilo "T0-Silo"
}
foreach ($c in "DC01$","DC02$","PAW-T0-01$") {            # akhiran $ = akun komputer
    Grant-ADAuthenticationPolicySiloAccess -Identity "T0-Silo" -Account $c
    Set-ADAccountAuthenticationPolicySilo -Identity $c -AuthenticationPolicySilo "T0-Silo"
}

# === FASE 2 — ENFORCE (setelah log audit bersih ≥ beberapa hari) ===
Set-ADAuthenticationPolicy     -Identity "T0-Auth-Policy" -Enforce $true
Set-ADAuthenticationPolicySilo -Identity "T0-Silo"        -Enforce $true
```

> **Urutan aman:** jangan pernah langsung membuat policy/silo dengan `-Enforce` lalu hanya assign user — itu persis resep lockout Tier 0. Audit dulu → assign user **+ computer DC/PAW** → validasi → baru enforce.

Verifikasi assignment & status enforce sebelum dan sesudah:

```powershell
Get-ADAuthenticationPolicy -Identity "T0-Auth-Policy" | Select Name,Enforce,UserTGTLifetimeMins
Get-ADAuthenticationPolicySilo -Identity "T0-Silo" | Select Name,Enforce
# Pastikan DC & PAW benar-benar masuk silo (kalau kosong → akan lockout saat enforce)
Get-ADComputer -Filter * -Properties msDS-AssignedAuthNPolicySilo |
    Where-Object { $_.'msDS-AssignedAuthNPolicySilo' -like '*T0-Silo*' } | Select Name
```

---

## 6. Windows LAPS

**APA.** **Windows LAPS** (Local Administrator Password Solution) merandomisasi dan merotasi password akun **local Administrator** menjadi unik per host, lalu menyimpannya di Active Directory (atau Microsoft Entra ID). Sejak **April 2023** Windows LAPS sudah **bawaan (built-in)** pada Windows 11, Windows 10, dan Windows Server 2022/2019 (via security update), tidak perlu MSI terpisah.

**KENAPA.** Tanpa LAPS, banyak organisasi memakai **satu password local Administrator yang sama** di seluruh host. Jika penyerang mencuri hash local admin dari satu mesin (dari SAM), ia bisa Pass-the-Hash ke ribuan host lain (lateral movement). LAPS membuat tiap host punya password unik & berputar, sehingga satu hash curian hanya berlaku untuk satu host. Ini mitigasi langsung Pass-the-Hash (T1550.002) dan credential dumping dari SAM (T1003.002).

**Legacy vs Windows LAPS (wajib paham bedanya):**

| Aspek | Legacy Microsoft LAPS (AdmPwd) | Windows LAPS (baru, April 2023) |
|---|---|---|
| Distribusi | MSI terpisah (`LAPS.x64.msi`) | Built-in OS |
| Module PowerShell | `AdmPwd.PS` | `LAPS` |
| Ambil password | `Get-AdmPwdPassword` | `Get-LapsADPassword` |
| Reset | `Reset-AdmPwdPassword` | `Reset-LapsPassword` |
| Extend schema | `Update-AdmPwdADSchema` | `Update-LapsADSchema` |
| Self-permission | `Set-AdmPwdComputerSelfPermission` | `Set-LapsADComputerSelfPermission` |
| Atribut AD | `ms-Mcs-AdmPwd`, `ms-Mcs-AdmPwdExpirationTime` | `msLAPS-Password`, `msLAPS-PasswordExpirationTime`, `msLAPS-EncryptedPassword`, `msLAPS-EncryptedPasswordHistory` |
| Enkripsi password | Tidak (plaintext di atribut, dilindungi ACL) | **Ya** (opsional, butuh DFL 2016+) |
| Target backup | AD | AD **atau** Entra ID |

**Jalur migrasi:** legacy & Windows LAPS bisa hidup berdampingan. Aktifkan mode **"Legacy Microsoft LAPS emulation"** sementara, lalu jalankan `Update-LapsADSchema` untuk menambah atribut baru dan pindahkan policy. Setelah semua host pakai Windows LAPS, hentikan emulasi.

**CARA — langkah deploy.**

1. **Update schema AD** (sekali per forest, jalankan sebagai Schema Admin):

```powershell
Update-LapsADSchema
```

2. **Beri komputer izin menulis password-nya sendiri** ke atribut (per OU komputer):

```powershell
Set-LapsADComputerSelfPermission -Identity "OU=Workstations,OU=Tier 2,OU=Admin,DC=lks,DC=local"
```

3. **(Opsional) Beri grup admin izin membaca/decrypt password** — jika tidak pakai enkripsi, gunakan read permission:

```powershell
Set-LapsADReadPasswordPermission -Identity "OU=Workstations,OU=Tier 2,OU=Admin,DC=lks,DC=local" `
    -AllowedPrincipals "LKS\Tier2-LAPS-Readers"
```

4. **Konfigurasi via GPO.** Path: `Computer Configuration > Policies > Administrative Templates > System > LAPS`.

| Setting GPO | Nilai contoh | Catatan |
|---|---|---|
| Configure password backup directory | `Active Directory` | (atau Azure AD) |
| Password Settings → Password Complexity | Large letters + small + numbers + specials | Default kompleks penuh. |
| Password Settings → Password Length | 14 (default Microsoft, range 8–64) | CIS Benchmark (Level 1) menetapkan **Enabled: 15 atau lebih**. |
| Password Settings → Password Age (Days) | 30 (default) | Frekuensi rotasi otomatis. |
| Name of administrator account to manage | (nama akun lokal yang dikelola) | Jika local admin di-rename, isi nama barunya. |
| Enable password encryption | Enabled | **Butuh Domain Functional Level Windows Server 2016+.** |
| Configure authorized password decryptors | `LKS\Tier2-LAPS-Readers` | Grup yang boleh decrypt password terenkripsi. |
| Post-authentication actions | Reset password & logoff | Tindakan setelah password dipakai. |

Registry policy yang setara dengan GPO (untuk verifikasi/LGPO): `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS`. (Catatan penting: `HKLM\Software\Microsoft\Policies\LAPS` adalah root untuk **LAPS CSP** (Intune/MDM), **bukan** Group Policy — jangan tertukar.) Untuk perangkat Intune/MDM gunakan **LAPS CSP**: `./Device/Vendor/MSFT/LAPS`.

5. **Terapkan policy & ambil password:**

```powershell
# Paksa klien memproses policy LAPS sekarang (jalankan di klien)
Invoke-LapsPolicyProcessing

# Ambil password dari AD (jalankan di DC/PAW, butuh izin baca/decrypt)
Get-LapsADPassword -Identity "WKS-01" -AsPlainText

# Paksa kedaluwarsa supaya rotasi terjadi pada siklus berikutnya
Set-LapsADPasswordExpirationTime -Identity "WKS-01"

# Reset password segera
Reset-LapsPassword
```

> **Enkripsi:** atribut `msLAPS-EncryptedPassword` hanya bisa dipakai bila domain berada pada DFL **Windows Server 2016 atau lebih tinggi**. Jika DFL lebih rendah, password disimpan plaintext di `msLAPS-Password` (dilindungi ACL saja) — kurang aman.

---

## 7. Just-In-Time (JIT) Access & Time-Based Group Membership

**APA.** Mekanisme memberi keanggotaan grup berhak yang **otomatis kedaluwarsa** setelah TTL (Time-To-Live) tertentu. Ini AD DS native JIT, mengganti *standing membership*.

**KENAPA.** Jika seseorang permanen di Domain Admins, hak itu menjadi target 24/7 dan tetap ada saat tidak dibutuhkan. Dengan TTL, admin mendapat hak hanya untuk, mis., 1 jam saat menangani tugas, lalu keanggotaan hilang otomatis — mengecilkan window of exposure dan menghapus *standing access*.

**Syarat:**

- **PAM Optional Feature** harus diaktifkan.
- **Forest functional level Windows Server 2016**. (Fitur ini **tidak dapat dimatikan** setelah diaktifkan — pahami sebelum mengeksekusi di lab.)

**CARA.**

```powershell
# Aktifkan PAM optional feature (sekali per forest)
Enable-ADOptionalFeature 'Privileged Access Management Feature' `
    -Scope ForestOrConfigurationSet `
    -Target 'lks.local'

# Tambah anggota grup dengan TTL 1 jam
Add-ADGroupMember -Identity "Domain Admins" -Members "t0-admin01" `
    -MemberTimeToLive (New-TimeSpan -Hours 1)

# Lihat sisa TTL keanggotaan
Get-ADGroup "Domain Admins" -Property member -ShowMemberTimeToLive
```

Output `ShowMemberTimeToLive` menampilkan `<TTL=3600>` (detik tersisa) di samping DN anggota. Saat TTL habis, AD menghapus anggota dari grup secara otomatis (memakai *expiring link* pada nilai-link keanggotaan).

**Efek native pada lifetime TGT (single-forest, lingkup modul ini).** Dengan **PAM Optional Feature** aktif, KDC **memangkas lifetime TGT** yang diterbitkan agar **tidak melebihi sisa TTL terpendek** dari keanggotaan grup berhak yang akan kedaluwarsa. Jadi bila admin diberi keanggotaan Domain Admins ber-TTL 30 menit, TGT-nya pun hanya berlaku ~30 menit — begitu keanggotaan hilang, tiket berhak tidak lagi memberi akses. Ini fitur **AD DS native**, tidak membutuhkan MIM maupun Shadow Principal.

**Gambaran MIM PAM + bastion/PRIV forest (arsitektur cross-forest, BUKAN native).** Untuk lingkungan besar, Microsoft Identity Manager (MIM) PAM membangun **forest administratif terpisah (bastion / PRIV forest)** yang sangat dihardening. Di sinilah — **dan hanya di sini** — konsep **Shadow Principal** berlaku: akun harian ada di forest produksi tanpa hak; saat butuh hak, user *request* akses, MIM menambahkannya sebagai anggota TTL ke **Shadow Principal** di forest bastion yang dipetakan (SID-history) ke grup berhak di forest produksi melalui **PAM trust** (one-way trust dari produksi ke bastion). Hasilnya: akun berhak tidak pernah "diam" di forest produksi, dan hanya hidup di forest bastion yang bersih. Bedakan tegas: **TTL link-value + pemangkasan TGT = native single-forest; Shadow Principal + PAM trust = MIM/bastion cross-forest.**

---

## 8. Just Enough Administration (JEA)

**APA.** Fitur PowerShell yang membuat **constrained endpoint** (session configuration) di mana user hanya boleh menjalankan **sekumpulan command/parameter terbatas**, dieksekusi sebagai **virtual account** sementara — bukan sebagai akun admin penuh.

**KENAPA.** Banyak tugas operasi (restart service, baca log, kelola DNS) butuh hak admin lokal/khusus, tapi tidak butuh akses penuh. JEA memberi *least privilege* nyata: operator bisa menjalankan tugasnya tanpa pernah menjadi admin penuh dan tanpa kredensial admin tersimpan di mesinnya. Mengurangi jumlah akun yang perlu hak tinggi (mengecilkan permukaan serang Tier 1/2).

**Dua file kunci:**

| File | Dibuat dengan | Isi |
|---|---|---|
| **Role Capability (`.psrc`)** | `New-PSRoleCapabilityFile` | Daftar cmdlet/fungsi/command yang diizinkan untuk satu peran. Harus diletakkan di folder `RoleCapabilities` sebuah module. |
| **Session Configuration (`.pssc`)** | `New-PSSessionConfigurationFile` | Mendefinisikan endpoint: siapa boleh connect (RoleDefinitions), jalankan sebagai virtual account, mode `RestrictedRemoteServer`. |

**CARA — contoh endpoint yang hanya boleh restart service tertentu.**

```powershell
# 1) Buat struktur module untuk role capability
$mod = "C:\Program Files\WindowsPowerShell\Modules\JEAOps"
New-Item -Path "$mod\RoleCapabilities" -ItemType Directory -Force | Out-Null

# 2) Role capability: hanya izinkan Get-Service & Restart-Service (Spooler)
New-PSRoleCapabilityFile -Path "$mod\RoleCapabilities\OpsRole.psrc" `
    -VisibleCmdlets @(
        'Get-Service',
        @{ Name='Restart-Service'; Parameters=@{ Name='Name'; ValidateSet='Spooler' } }
    )

# 3) Session configuration: jalankan sebagai virtual account, mode terbatas
New-PSSessionConfigurationFile -Path "C:\JEA\OpsEndpoint.pssc" `
    -SessionType RestrictedRemoteServer `
    -RunAsVirtualAccount `
    -RoleDefinitions @{ 'LKS\Tier1-Operators' = @{ RoleCapabilities = 'OpsRole' } } `
    -TranscriptDirectory 'C:\JEA\Transcripts'

# 4) Validasi & daftarkan endpoint
Test-PSSessionConfigurationFile -Path "C:\JEA\OpsEndpoint.pssc"
Register-PSSessionConfiguration -Name "OpsEndpoint" -Path "C:\JEA\OpsEndpoint.pssc" -Force
```

Connect dari klien (operator tidak perlu kredensial admin):

```powershell
Enter-PSSession -ComputerName SRV-01 -ConfigurationName OpsEndpoint
# Operator hanya bisa Get-Service & Restart-Service -Name Spooler; selain itu ditolak.
```

> `RunAsVirtualAccount` membuat akun virtual (anggota Administrators lokal, atau Domain Admins di DC) yang hanya hidup selama sesi. Hak tinggi tetap dibatasi oleh daftar command di role capability. `TranscriptDirectory` merekam seluruh aktivitas untuk audit (-> korelasi logging lanjutan lihat Modul 06).

---

## 9. Group Managed Service Accounts (gMSA)

**APA.** Akun service domain yang **password-nya dikelola & dirotasi otomatis oleh AD** (default tiap 30 hari), dan bisa dipakai oleh beberapa host (group). Tidak ada manusia yang tahu password-nya.

**KENAPA.** Service account tradisional sering punya password statis yang lemah, jarang diganti, dan disimpan di skrip/konfigurasi — target empuk Kerberoasting (T1558.003) dan credential theft. gMSA menghapus password manual: AD menghasilkan password 240-byte acak yang dirotasi otomatis, sehingga tidak ada password untuk dicuri atau di-crack secara praktis, dan tidak ada lagi password kedaluwarsa yang membuat service tumbang.

**CARA.**

```powershell
# 1) Buat KDS root key (sekali per forest). Di produksi tunggu replikasi 10 jam.
Add-KdsRootKey -EffectiveImmediately
# Di LAB satu DC, percepat agar bisa langsung dipakai:
# Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10))

# 2) Buat gMSA dan tentukan host yang boleh mengambil password
New-ADServiceAccount -Name "gmsa-web01" `
    -DNSHostName "gmsa-web01.lks.local" `
    -PrincipalsAllowedToRetrieveManagedPassword "WebServers"

# 3) Di host target (anggota grup di atas), install & uji
Install-ADServiceAccount -Identity "gmsa-web01"
Test-ADServiceAccount -Identity "gmsa-web01"   # harus mengembalikan True
```

Gunakan akun sebagai identitas service dengan format `LKS\gmsa-web01$` (akhiran `$`) tanpa password. gMSA juga ideal sebagai identitas untuk grup `RunAsVirtualAccountGroups` pada JEA dan untuk service yang sebelumnya pakai akun domain berhak.

**Varian Managed Service Account (jangan tertukar):**

| Tipe | Cmdlet/cara | Cakupan host | Catatan keamanan |
|---|---|---|---|
| **sMSA** (standalone, 2008 R2) | `New-ADServiceAccount -RestrictToSingleComputer` | **Satu host** | Pendahulu gMSA; password tetap dikelola AD, tapi tak bisa dibagi banyak host. Pakai gMSA bila >1 host. |
| **gMSA** (group, 2012) | `New-ADServiceAccount ... -PrincipalsAllowedToRetrieveManagedPassword` | **Banyak host** (grup) | Default modul ini. Password 240-byte, rotasi 30 hari. |
| **dMSA** (delegated, Server 2025) | dibuat via `New-ADServiceAccount` di Server 2025, lalu **migrasi** dari akun service lama | Banyak host, **menggantikan** akun service lama | Baru di Windows Server 2025; dirancang anti-Kerberoasting. **Awas BadSuccessor**: bila ACL `OU`/atribut `msDS-ManagedAccountPrecededByLink` & `msDS-DelegatedMSAState` bisa ditulis penyerang, dMSA dapat "mewarisi" hak akun korban → privilege escalation. Batasi siapa boleh membuat/menautkan dMSA. |

**SPN & Kerberoasting:** gMSA/dMSA boleh memegang **SPN** (mis. `MSSQLSvc/host:1433`) agar service-nya bisa diautentikasi Kerberos. Karena password-nya acak 240-byte & dirotasi otomatis, tiket layanan yang di-Kerberoast (`T1558.003`) **praktis tak bisa di-crack** — inilah keunggulan utamanya dibanding akun service manual ber-SPN. Kelola SPN dengan `setspn -L gmsa-web01$` (lihat) / `setspn -S MSSQLSvc/host.lks.local gmsa-web01$` (tambah), dan pastikan akun ber-SPN lama yang berpassword lemah diganti gMSA. Audit akun ber-SPN rentan → **lihat Modul 02** (`ServicePrincipalName -like '*'`).

---

## 10. Mengamankan Built-in Administrator & Breakglass

**APA & KENAPA.** Akun built-in Administrator (RID 500) adalah target utama: tidak bisa di-lockout secara default dan dikenal semua penyerang. Mengamankannya menutup salah satu jalur paling klasik.

**CARA.**

| Tindakan | Cara | Catatan |
|---|---|---|
| Rename built-in Administrator (lokal) | Security Options `Accounts: Rename administrator account` (via GPO -> Modul 03) | Memperlambat password-guessing yang menyasar nama "Administrator". |
| Disable built-in Administrator (lokal) di klien | `Disable-LocalUser -Name "Administrator"` atau Security Options `Accounts: Administrator account status` = Disabled | Local admin lokal dikelola LAPS, bukan dipakai harian. |
| Hapus *standing membership* | Kosongkan keanggotaan permanen `Domain Admins`, `Enterprise Admins`, `Schema Admins` — gunakan JIT/TTL (bagian 7) | Schema/Enterprise Admins idealnya **kosong** kecuali saat operasi terjadwal. |
| Lindungi grup berhak | Privileged group hygiene & AdminSDHolder **-> lihat Modul 02** | — |

```powershell
# Audit keanggotaan grup paling berbahaya (harus minimal)
'Domain Admins','Enterprise Admins','Schema Admins' | ForEach-Object {
    "=== $_ ==="
    Get-ADGroupMember $_ -ErrorAction SilentlyContinue | Select-Object SamAccountName
}
```

**Breakglass account (akun darurat):**

- Buat **minimal satu** akun darurat di Domain Admins/Enterprise Admins untuk skenario di mana semua mekanisme lain (silo, JIT, MFA) gagal.
- Password sangat panjang & acak, dicetak/disimpan **offline** (amplop tersegel di brankas), **tidak** dipakai harian.
- **Dokumentasikan** dan **monitor** secara khusus: setiap logon breakglass harus memicu alert (deteksi & alert -> lihat Modul 06).
- **Jangan** masukkan akun breakglass ke Protected Users atau Authentication Silo (risiko membuatnya tidak bisa dipakai saat darurat — justru saat paling dibutuhkan).

---

## 11. Credential Guard & Remote Credential Guard / Restricted Admin

**APA.** **Windows Defender Credential Guard** menggunakan Virtualization-Based Security (VBS) untuk mengisolasi secret LSASS (hash NTLM, TGT, kredensial cached) di dalam **LSAIso** terpisah yang tidak bisa diakses meski penyerang punya admin/SYSTEM. **Remote Credential Guard** dan **Restricted Admin mode** melindungi kredensial admin saat melakukan **RDP** ke server lain.

**KENAPA.** Tool seperti Mimikatz membaca secret dari memori LSASS untuk Pass-the-Hash/Pass-the-Ticket (T1003.001). Credential Guard membuat secret itu tak terbaca dari OS biasa. Saat RDP, normalnya kredensial Anda terkirim/tersimpan di server remote — jika server itu dikompromi, kredensial admin ikut tercuri; Remote Credential Guard & Restricted Admin mencegah kredensial mendarat di host remote.

**Versi & default:**

- Credential Guard butuh **Windows 10/11 Enterprise** atau **Windows Server 2016+** dengan VBS aktif (UEFI, Secure Boot, virtualization).
- **Default-on**: aktif secara default pada **Windows 11 22H2+ edisi Enterprise pada hardware yang memenuhi syarat** — bukan default di Windows Server dan bukan di semua edisi/hardware. Jangan overstate.

**CARA — Credential Guard via GPO.** Path: `Computer Configuration > Policies > Administrative Templates > System > Device Guard > Turn On Virtualization Based Security`.

| Setting | Nilai |
|---|---|
| Select Platform Security Level | Secure Boot (and DMA Protection) |
| Credential Guard Configuration | **Enabled with UEFI lock** (paling kuat; perlu prosedur khusus untuk dimatikan) |

Registry yang setara:

```reg
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard]
"EnableVirtualizationBasedSecurity"=dword:00000001
"RequirePlatformSecurityFeatures"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa]
"LsaCfgFlags"=dword:00000001
```

> `LsaCfgFlags`: `1` = Credential Guard ON dengan UEFI lock, `2` = ON tanpa lock, `0` = OFF.

**CARA — Remote Credential Guard / Restricted Admin.** GPO: `Computer Configuration > Policies > Administrative Templates > System > Credentials Delegation > Restrict delegation of credentials to remote servers` → pilih **Require Remote Credential Guard** atau **Restrict Credential Delegation**.

```cmd
:: RDP dengan Remote Credential Guard (single sign-on, kredensial tidak mendarat di host remote)
mstsc.exe /remoteGuard

:: RDP dengan Restricted Admin mode (tidak mengirim kredensial sama sekali)
mstsc.exe /restrictedAdmin
```

Aktifkan Restricted Admin mode di server target lewat registry:

```reg
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa]
"DisableRestrictedAdmin"=dword:00000000
```

> `DisableRestrictedAdmin` = `0` berarti Restricted Admin **diizinkan**. RDP transport hardening (NLA/TLS) -> lihat Modul 04.

> **Caveat Pass-the-Hash (jangan dilewati).** Restricted Admin mode **bukan** kontrol bebas-risiko: karena kredensial tidak dikirim, otentikasi RDP dilakukan dengan **network logon memakai derivasi kredensial (hash/tiket) milik klien**. Akibatnya mode ini justru **memungkinkan Pass-the-Hash via RDP** — penyerang yang sudah memegang hash admin bisa RDP `/restrictedAdmin` tanpa tahu password plaintext, dan host target yang dikompromi dapat menyalahgunakan logon tersebut untuk lateral movement. Karena itu **utamakan Remote Credential Guard** (`/remoteGuard`): ia menjaga TGT/kredensial tetap di klien (single sign-on lewat Kerberos) tanpa meninggalkan kredensial yang bisa di-reuse di host remote, sekaligus menutup PtH. Pakai Restricted Admin hanya bila Remote Credential Guard tidak tersedia (mis. logon non-domain), dan batasi ketat siapa yang boleh.

---

## Serangan Umum & Mitigasi

| Teknik penyerang | MITRE ATT&CK | Setting di modul ini yang memitigasi |
|---|---|---|
| OS Credential Dumping (LSASS) | T1003.001 | Credential Guard (11), Protected Users (4), PAW (3) |
| OS Credential Dumping (SAM) | T1003.002 | Windows LAPS (6) — password local admin unik per host |
| DCSync | T1003.006 | Tiering & hapus standing Domain/Enterprise Admins (2,10); detail AD -> Modul 02 |
| Pass-the-Hash | T1550.002 | LAPS (6), Protected Users tanpa NTLM (4), Credential Guard (11) |
| Pass-the-Ticket | T1550.003 | Protected Users AES-only + TGT 4 jam (4), Auth Silo (5) |
| Steal/Forge Kerberos Ticket — Golden/Silver | T1558.001 / T1558.002 | Lindungi Tier 0 & service identity (gMSA), tiering (2,9); KRBTGT -> Modul 02 |
| Kerberoasting | T1558.003 | gMSA (9) — password acak 240-byte, praktis tak bisa di-crack |
| Valid Accounts | T1078 | JIT/TTL hapus standing access (7), Auth Silo batasi lokasi (5) |
| Remote Services (RDP) | T1021.001 | Remote Credential Guard / Restricted Admin (11) |
| Account Manipulation | T1098 | Privileged group hygiene + audit (10); AdminSDHolder -> Modul 02 |

---

## Hardening Checklist (Modul Ini)

- [ ] Struktur OU tiering (Tier 0/1/2: Accounts/Groups/Devices) dibuat & terlindungi dari penghapusan.
- [ ] GPO logon-restriction (URA deny) di-link agar akun lintas-tier tidak bisa logon silang (-> Modul 03).
- [ ] PAW disiapkan untuk Tier 0 (tanpa email/browsing umum): AppLocker/WDAC allow-list (Publisher, bukan path lebar), firewall default-deny outbound + allow endpoint manajemen, removable storage Deny_All, `LsaCfgFlags=1`, URA deny-logon non-Tier0.
- [ ] Akun admin bernilai tinggi masuk `Protected Users` (setelah diuji, tanpa breakglass/akun NTLM-dependent).
- [ ] Authentication Policy Silo membatasi akun Tier 0 hanya logon dari DC/PAW Tier 0 — **audit-only dulu, assign user + komputer DC/PAW**, baru `-Enforce $true` (hindari lockout).
- [ ] Windows LAPS: schema di-extend, self-permission diset, GPO aktif, password terambil & terenkripsi (DFL 2016+).
- [ ] PAM optional feature aktif (forest 2016) & keanggotaan grup berhak diberikan via TTL, bukan permanen.
- [ ] Minimal satu JEA endpoint constrained (RestrictedRemoteServer + RunAsVirtualAccount) untuk operator.
- [ ] Service account berhak diganti gMSA (KDS root key dibuat, Test-ADServiceAccount = True).
- [ ] Built-in Administrator di-rename/disable sesuai kebutuhan; standing Domain/Enterprise/Schema Admins dikosongkan.
- [ ] Akun breakglass dibuat, password offline, dimonitor; tidak masuk Protected Users/Silo.
- [ ] Credential Guard (Enabled with UEFI lock) & Remote Credential Guard/Restricted Admin diaktifkan.

---

## Lab Praktik

**Prasyarat:** DC Windows Server 2022 (`lks.local`), satu klien Windows 10/11 (`WKS-01`), modul `ActiveDirectory` & `LAPS` tersedia, login sebagai akun dengan hak Schema/Domain Admin untuk langkah schema.

**Langkah 1 — Bangun struktur OU tiering.**
- Lakukan: jalankan skrip OU di [bagian 2](#2-tiered-administration-model-enterprise-access-model).
- Konfirmasi dengan: `Get-ADOrganizationalUnit -Filter * -SearchBase "OU=Admin,DC=lks,DC=local" | Select Name` → tampil `Tier 0/1/2` beserta sub-OU `Accounts/Groups/Devices`.

**Langkah 2 — Deploy Windows LAPS.**
- Lakukan: `Update-LapsADSchema` (extend schema).
- Konfirmasi dengan: `Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext -Filter {name -like 'ms-LAPS*' -or name -like 'msLAPS*'} | Select Name` → muncul atribut `msLAPS-Password`, `msLAPS-EncryptedPassword`, dll.
- Lakukan: `Set-LapsADComputerSelfPermission -Identity "OU=Workstations,OU=Tier 2,OU=Admin,DC=lks,DC=local"`.
- Lakukan: buat & link GPO LAPS (-> Modul 03) dengan backup directory = Active Directory, lalu di `WKS-01` jalankan `Invoke-LapsPolicyProcessing`.
- Konfirmasi dengan: `Get-LapsADPassword -Identity "WKS-01" -AsPlainText` di DC → mengembalikan password acak + waktu kedaluwarsa. Bila kosong, paksa `Set-LapsADPasswordExpirationTime -Identity "WKS-01"` lalu ulang `Invoke-LapsPolicyProcessing`.

**Langkah 3 — Buat satu JEA endpoint terbatas.**
- Lakukan: ikuti skrip [bagian 8](#8-just-enough-administration-jea) di `SRV-01` (role capability + .pssc + `Register-PSSessionConfiguration`).
- Konfirmasi dengan: `Get-PSSessionConfiguration -Name OpsEndpoint` (endpoint terdaftar), lalu `Enter-PSSession -ComputerName SRV-01 -ConfigurationName OpsEndpoint` dan jalankan `Get-Command` → hanya command yang diizinkan tampil; mencoba `Stop-Computer` harus ditolak.

**Langkah 4 — Tambah anggota grup dengan TTL.**
- Lakukan: `Enable-ADOptionalFeature 'Privileged Access Management Feature' -Scope ForestOrConfigurationSet -Target 'lks.local'` (sekali; ingat tidak bisa dibatalkan), lalu `Add-ADGroupMember -Identity "Tier 1 Server Admins" -Members "t1-op01" -MemberTimeToLive (New-TimeSpan -Minutes 15)`.
- Konfirmasi dengan: `Get-ADGroup "Tier 1 Server Admins" -Property member -ShowMemberTimeToLive` → DN `t1-op01` muncul dengan `<TTL=...>`; tunggu 15 menit lalu cek lagi → anggota hilang otomatis.

---

## Perintah Audit/Verifikasi

Semua perintah di bawah dijamin bisa dijalankan dan menyebut output yang diharapkan.

```powershell
# 1) Anggota Protected Users (verifikasi akun berhak sudah dilindungi)
Get-ADGroupMember -Identity "Protected Users" | Select-Object SamAccountName
#   Harapan: daftar akun admin yang sengaja dimasukkan; breakglass TIDAK ada di sini.

# 2) PAM optional feature aktif?
Get-ADOptionalFeature -Filter {Name -like 'Privileged*'} | Select-Object Name,EnabledScopes
#   Harapan: 'Privileged Access Management Feature' dengan EnabledScopes terisi (tidak kosong).

# 3) gMSA bisa dipakai host ini?
Test-ADServiceAccount -Identity "gmsa-web01"
#   Harapan: True.

# 4) Password LAPS tersimpan & bisa diambil?
Get-LapsADPassword -Identity "WKS-01"
#   Harapan: objek berisi Account, Password (atau terenkripsi), ExpirationTimestamp di masa depan.

# 5) Credential Guard berjalan?
(Get-CimInstance -ClassName Win32_DeviceGuard `
    -Namespace 'root\Microsoft\Windows\DeviceGuard').SecurityServicesRunning
#   Harapan: koleksi memuat nilai 1 (1 = Credential Guard running).

# 6) Keanggotaan grup paling berbahaya minimal?
Get-ADGroupMember "Domain Admins" | Select-Object SamAccountName
#   Harapan: hanya breakglass + (sementara) akun JIT; bukan akun harian.

# 7) JEA endpoint terdaftar & terbatas?
Get-PSSessionConfiguration -Name OpsEndpoint | Select-Object Name,RunAsVirtualAccount
#   Harapan: Name=OpsEndpoint, RunAsVirtualAccount=True.

# 8) TTL keanggotaan grup aktif?
Get-ADGroup "Tier 1 Server Admins" -Property member -ShowMemberTimeToLive
#   Harapan: anggota tampil dengan anotasi <TTL=...> (detik tersisa).
```

```cmd
:: 9) Verifikasi LsaCfgFlags Credential Guard via registry
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LsaCfgFlags
::   Harapan: REG_DWORD 0x1 (UEFI lock) atau 0x2 (tanpa lock).
```

---

## Referensi

- **Microsoft Security Baseline** (Windows Server 2022 & Windows 11) — Security Compliance Toolkit; nilai default Credential Guard, Device Guard, dan setting LAPS. Tooling baseline (LGPO.exe, Policy Analyzer) -> lihat Modul 03.
- **CIS Microsoft Windows Server 2022 Benchmark** & **CIS Windows 11 Enterprise Benchmark** — rujukan tunggal untuk nilai numerik (panjang & umur password LAPS, status akun Administrator). Catatan: CIS Level 1 menetapkan LAPS Password Length **15 atau lebih** (default Microsoft 14). Selalu cek ulang nilai numerik ke teks benchmark versi terbaru sebelum dipakai di lomba.
- **Microsoft Learn — Windows LAPS** (`Get-LapsADPassword`, `Update-LapsADSchema`, `Set-LapsADComputerSelfPermission`, GPO/CSP, password encryption & syarat DFL 2016).
- **Microsoft Learn — Enterprise Access Model / Securing Privileged Access** (tier model, PAW, clean source principle).
- **Microsoft Learn — Protected Users Security Group**, **Authentication Policies and Authentication Policy Silos**.
- **Microsoft Learn — Just Enough Administration (JEA)**, **Group Managed Service Accounts Overview**, **PAM / time-based group membership** & **MIM Privileged Access Management**.
- **Microsoft Learn — Windows Defender Credential Guard** & **Remote Credential Guard**.
- **MITRE ATT&CK** (attack.mitre.org) — referensi teknik T1003, T1550, T1558, T1078, T1021, T1098.

> Catatan modul terkait: kebijakan password/lockout & Kerberos (Modul 02), GPO/URA/AppLocker (Modul 03), firewall/RDP/SMB (Modul 04), Defender/ASR (Modul 05), audit policy & Event ID & Sysmon (Modul 06).
