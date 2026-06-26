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
| Hardening | Application control (AppLocker/WDAC -> Modul 05/03), Credential Guard aktif (bagian 11), firewall ketat (-> Modul 04). |
| Akun | Hanya akun tier yang sesuai boleh logon ke PAW tier itu. |

Model hardware: PAW fisik terpisah (paling kuat), atau model "user VM di atas host PAW" di mana host adalah PAW bersih dan pekerjaan berisiko berjalan di dalam VM tamu yang tidak tepercaya.

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

**CARA (GUI).** Active Directory Administrative Center (ADAC) → **Authentication** → **Authentication Policies** (buat policy, set TGT lifetime, mis. 240 menit) lalu **Authentication Policy Silos** (buat silo, assign akun & komputer, tautkan policy).

```powershell
# Buat authentication policy: TGT 240 menit, hanya boleh logon ke device dalam silo
New-ADAuthenticationPolicy -Name "T0-Auth-Policy" `
    -UserTGTLifetimeMins 240 `
    -Enforce

# Buat silo dan tautkan policy
New-ADAuthenticationPolicySilo -Name "T0-Silo" `
    -UserAuthenticationPolicy "T0-Auth-Policy" `
    -ComputerAuthenticationPolicy "T0-Auth-Policy" `
    -ServiceAuthenticationPolicy "T0-Auth-Policy" `
    -Enforce

# Assign akun & DC/PAW ke silo, lalu grant akses
Grant-ADAuthenticationPolicySiloAccess -Identity "T0-Silo" -Account "t0-admin01"
Set-ADAccountAuthenticationPolicySilo -Identity "t0-admin01" -AuthenticationPolicySilo "T0-Silo"
```

> Tip uji aman: buat policy dengan mode **audit-only** (tanpa `-Enforce`) dulu, pantau apakah ada logon yang akan gagal, baru aktifkan `-Enforce`.

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

Output `ShowMemberTimeToLive` menampilkan `<TTL=3600>` (detik tersisa) di samping DN anggota. Saat TTL habis, AD menghapus anggota dari grup secara otomatis (menggunakan TTL link-value, sehingga selama berlaku, keanggotaan dilindungi juga oleh Kerberos via mekanisme *Shadow Principals* di skenario bastion).

**Gambaran MIM PAM + bastion/PRIV forest.** Untuk lingkungan besar, Microsoft Identity Manager (MIM) PAM membangun **forest administratif terpisah (bastion / PRIV forest)** yang sangat dihardening. Akun harian ada di forest produksi tanpa hak; saat butuh hak, user *request* akses, MIM menambahkannya sebagai anggota TTL ke **Shadow Principal** yang dipetakan ke grup berhak di forest produksi melalui **PAM trust** (one-way trust dari produksi ke bastion). Hasilnya: akun berhak tidak pernah "diam" di forest produksi, dan hanya hidup di forest bastion yang bersih.

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
- [ ] PAW disiapkan untuk Tier 0 (tanpa email/browsing umum), Credential Guard aktif di atasnya.
- [ ] Akun admin bernilai tinggi masuk `Protected Users` (setelah diuji, tanpa breakglass/akun NTLM-dependent).
- [ ] Authentication Policy Silo membatasi akun Tier 0 hanya logon dari DC/PAW Tier 0.
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
