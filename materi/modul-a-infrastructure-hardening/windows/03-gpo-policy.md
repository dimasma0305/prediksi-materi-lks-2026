# Modul 03 — GPO: Local & Active Directory Policy

> Group Policy adalah mesin konfigurasi terpusat Windows: satu tempat untuk memaksakan ribuan setting keamanan ke ratusan host. Modul ini memiliki *mekanisme* GPO — cara membuat, men-scope, dan memverifikasi kebijakan — sementara modul lain hanya menunjuk path-nya ke sini. Dari sudut pandang penyerang, GPO adalah target bernilai tinggi: siapa pun yang bisa memodifikasi satu GPO ber-link ke OU privileged dapat menjalankan kode di setiap mesin dalam scope itu (T1484.001), sehingga memahami precedence dan delegasi GPO adalah pertahanan sekaligus deteksi.

## Daftar Isi

1. [Konsep & Tujuan](#1-konsep--tujuan)
2. [Local Group Policy vs Domain GPO & MLGPO](#2-local-group-policy-vs-domain-gpo--mlgpo)
3. [Anatomi GPO](#3-anatomi-gpo)
4. [Urutan Pemrosesan & Precedence (LSDOU)](#4-urutan-pemrosesan--precedence-lsdou)
5. [Tooling GPO: GPMC, PowerShell, gpupdate, gpresult, RSoP](#5-tooling-gpo-gpmc-powershell-gpupdate-gpresult-rsop)
6. [Area Kebijakan Keamanan Kunci](#6-area-kebijakan-keamanan-kunci)
7. [Security Compliance Toolkit (SCT)](#7-security-compliance-toolkit-sct)
8. [Application Control via GPO: AppLocker & WDAC](#8-application-control-via-gpo-applocker--wdac)
9. [Contoh GPO Hardening Praktis](#9-contoh-gpo-hardening-praktis)
10. [Best Practice & Mengamankan GPO Itu Sendiri](#10-best-practice--mengamankan-gpo-itu-sendiri)
11. [Serangan Umum & Mitigasi](#serangan-umum--mitigasi)
12. [Hardening Checklist (Modul Ini)](#hardening-checklist-modul-ini)
13. [Lab Praktik](#lab-praktik)
14. [Perintah Audit/Verifikasi](#perintah-auditverifikasi)
15. [Referensi](#referensi)

---

## 1. Konsep & Tujuan

Group Policy adalah kerangka kerja untuk menerapkan konfigurasi (registry, security settings, script, software) ke **computer** dan **user** secara terpusat. Setiap kumpulan setting tersimpan sebagai **Group Policy Object (GPO)**.

Secara fisik sebuah Domain GPO terdiri dari dua bagian:

| Komponen | Lokasi | Isi |
|----------|--------|-----|
| **Group Policy Container (GPC)** | Objek di AD: `CN=Policies,CN=System,DC=...` | Metadata, versi, status, atribut |
| **Group Policy Template (GPT)** | `\\<domain>\SYSVOL\<domain>\Policies\{GUID}\` | File aktual: `registry.pol`, `GptTmpl.inf`, script, ADM |

Memahami pembagian ini penting: replikasi GPC mengikuti replikasi AD, sedangkan GPT direplikasi via **DFS-R** (SYSVOL). Versi GPC dan GPT yang tidak sinkron menyebabkan setting tidak diterapkan.

**Tujuan modul:** menguasai *mekanisme* — membuat, men-scope (link/filter), memproses, dan memverifikasi GPO — serta menerapkan baseline keamanan secara konsisten ke Domain Controller, member server, dan klien Windows 10/11.

> Catatan ownership: nilai numerik password/lockout dan Kerberos -> **lihat Modul 02**; firewall/SMB/RDP transport -> **lihat Modul 04**; Defender/ASR -> **lihat Modul 05**; Advanced Audit Policy, daftar Event ID, dan PowerShell logging -> **lihat Modul 06**. Modul ini hanya menyediakan path GPO dan cara penerapannya.

---

## 2. Local Group Policy vs Domain GPO & MLGPO

### APA

- **Local Group Policy** — kebijakan yang tersimpan di mesin itu sendiri (`%SystemRoot%\System32\GroupPolicy`), diedit dengan `gpedit.msc`. Berlaku tanpa domain.
- **Domain GPO** — tersimpan di AD + SYSVOL, dikelola dengan **GPMC** (`gpmc.msc`), di-link ke Site/Domain/OU.
- **Multiple Local Group Policy (MLGPO)** — sejak Windows Vista / Server 2008, mesin non-DC mendukung beberapa layer Local GPO untuk *User Configuration*: (1) Local Computer Policy, (2) Administrators/Non-Administrators, (3) user-specific. MLGPO **tidak tersedia di Domain Controller**.

### KENAPA

Di lingkungan domain, Domain GPO adalah mekanisme utama karena terpusat dan ter-audit. **Local GPO tetap penting** untuk: mesin workgroup/standalone (tidak ada DC), DMZ/host terisolasi, image dasar (golden image), dan sebagai *fallback* terendah dalam precedence. MLGPO memungkinkan hardening berbeda untuk admin vs non-admin pada satu mesin standalone (mis. kiosk).

### CARA

```cmd
:: Buka editor Local Group Policy (mesin tunggal)
gpedit.msc

:: Buka MLGPO untuk user/grup spesifik (mesin non-DC): tambahkan snap-in
mmc.exe
:: File > Add/Remove Snap-in > Group Policy Object Editor >
:: Browse > tab "Users" > pilih Administrators / Non-Administrators / user tertentu
```

- GUI Domain: **Server Manager > Tools > Group Policy Management** (`gpmc.msc`).
- File Local GPO computer: `%SystemRoot%\System32\GroupPolicy\Machine\registry.pol`.
- File MLGPO user: `%SystemRoot%\System32\GroupPolicyUsers\{SID}\`.

> Untuk menerapkan baseline ke mesin **standalone** tanpa AD, gunakan **LGPO.exe** (Bagian 7) untuk meng-import GPO backup ke Local GPO.

---

## 3. Anatomi GPO

Setiap GPO terbagi dua node besar:

| Node | Diterapkan ke | Diproses saat |
|------|---------------|---------------|
| **Computer Configuration** | objek komputer dalam scope | boot + refresh periodik |
| **User Configuration** | objek user dalam scope | logon + refresh periodik |

Di bawah masing-masing terdapat tiga kategori:

### 3.1 Administrative Templates (ADMX) + Central Store

### APA
Administrative Templates adalah setting berbasis registry yang didefinisikan oleh file **`.admx`** (definisi) + **`.adml`** (bahasa). Lokasi default di tiap mesin: `C:\Windows\PolicyDefinitions`. **Central Store** adalah salinan terpusat di SYSVOL sehingga semua admin memakai versi ADMX yang sama.

### KENAPA
Tanpa Central Store, setiap workstation admin memuat ADMX lokalnya sendiri — versi berbeda menyebabkan setting "Extra Registry Settings" atau hilang. Central Store membuat GPMC selalu memuat definisi dari satu sumber.

### CARA
Path Central Store (dibuat manual sekali):

```
\\<domain>\SYSVOL\<domain>\Policies\PolicyDefinitions
\\<domain>\SYSVOL\<domain>\Policies\PolicyDefinitions\en-US   (file .adml)
```

```powershell
# Buat Central Store dengan menyalin ADMX dari salah satu DC (jalankan dari DC)
$dst = "\\corp.local\SYSVOL\corp.local\Policies\PolicyDefinitions"
New-Item -ItemType Directory -Path $dst -Force
Copy-Item "C:\Windows\PolicyDefinitions\*" $dst -Recurse -Force
```

> ADMX **bukan** untuk Office/Edge/produk pihak ketiga secara otomatis — unduh paket ADMX masing-masing (mis. Microsoft 365 Apps ADMX) dan salin ke Central Store. Setelah Central Store ada, GPMC menampilkan tag "(central store)" saat mengedit Administrative Templates.

### 3.2 Security Settings

Node `Computer Configuration > Policies > Windows Settings > Security Settings` berisi: Account Policies, Local Policies (URA, Security Options, Audit Policy), Windows Defender Firewall, Application Control Policies (AppLocker), dan lainnya. Setting ini ditulis ke `GptTmpl.inf` dan diproses oleh `scecli`/`secedit` — inilah inti hardening (Bagian 6).

### 3.3 Group Policy Preferences (GPP)

### APA
**Preferences** (`Computer/User Configuration > Preferences`) menyediakan konfigurasi yang dahulu manual: Drive Maps, Registry, Scheduled Tasks, Local Users and Groups, Files, Shortcuts, Power Options, Printers.

### KENAPA & PERINGATAN KEAMANAN
Berbeda dari Policy Settings, banyak Preferences bersifat **tattooing** — nilai tetap tertinggal di mesin meski GPO dihapus (kecuali opsi "Remove this item when it is no longer applied" diaktifkan). Lebih penting: **JANGAN gunakan GPP untuk menyetel password** (mis. lewat "Local Users and Groups" atau "Scheduled Tasks"). Password GPP disimpan di `Groups.xml` SYSVOL dalam atribut **`cpassword`** yang dienkripsi AES dengan **kunci publik yang dipublikasikan Microsoft** — siapa pun yang bisa membaca SYSVOL bisa mendekripsinya. Microsoft menutup celah pembuatan baru lewat **MS14-025**, tetapi file lama yang sudah ada **tidak** dihapus otomatis.

### CARA (pembersihan)
```powershell
# Cari sisa cpassword di SYSVOL (harus tidak ada hasil)
Get-ChildItem "\\corp.local\SYSVOL" -Recurse -Include *.xml -ErrorAction SilentlyContinue |
  Select-String -Pattern "cpassword"
```
Untuk mengelola password admin lokal, gunakan **Windows LAPS** -> **lihat Modul 01**, bukan GPP.

---

## 4. Urutan Pemrosesan & Precedence (LSDOU)

### APA
GPO diproses berurutan **L-S-D-OU**: **Local -> Site -> Domain -> OU** (OU induk lalu OU anak). Aturan dasar: **GPO yang diproses terakhir menang** untuk setting yang bentrok. Karena OU anak diproses paling akhir, GPO terdekat dengan objek biasanya menang.

### KENAPA
Memahami precedence menentukan apakah setting hardening benar-benar diterapkan atau tertimpa. Salah scope = lubang keamanan diam-diam.

### Modifier Precedence

| Mekanisme | Path/Tindakan | Efek |
|-----------|---------------|------|
| **Link Order** | GPMC > OU > tab *Linked Group Policy Objects* | Link order **1 = prioritas tertinggi** dalam container yang sama (diproses terakhir) |
| **Block Inheritance** | klik kanan OU > *Block Inheritance* | Menghentikan pewarisan GPO dari atas (Site/Domain) |
| **Enforced (No Override)** | klik kanan link GPO > *Enforced* | Memaksa GPO menang **dan menembus Block Inheritance**; membalik precedence normal |
| **Security Filtering** | tab *Scope* > Security Filtering | GPO hanya diterapkan ke user/computer dalam grup tertentu |
| **WMI Filtering** | tab *Scope* > WMI Filtering | GPO hanya diterapkan jika query WQL bernilai TRUE |
| **Loopback Processing** | Administrative Templates setting | User Configuration mengikuti komputer, bukan user |

### CARA — Block & Enforced
```powershell
# Block Inheritance pada sebuah OU
Set-GPInheritance -Target "OU=Servers,DC=corp,DC=local" -IsBlocked Yes

# Enforce sebuah link (menembus block inheritance)
Set-GPLink -Name "Baseline - Domain Security" -Target "DC=corp,DC=local" -Enforced Yes
```

### CARA — Security Filtering (dengan gotcha MS16-072)
Default Security Filtering = **Authenticated Users** (mencakup akun komputer). Sejak patch **MS16-072 (Juni 2016)**, GPO diproses dalam konteks **akun komputer**, sehingga komputer **wajib** punya hak *Read* atas GPO. Jika kamu mengganti Authenticated Users dengan grup user kustom, **tambahkan kembali `Domain Computers` (atau `Authenticated Users`) dengan izin Read** agar GPO tetak diproses.

```powershell
# Filter GPO hanya untuk grup tertentu, tetap beri Read ke Domain Computers (MS16-072)
Set-GPPermission -Name "Hardening - RDP Servers" -TargetName "RDP-Admins" `
  -TargetType Group -PermissionLevel GpoApply
Set-GPPermission -Name "Hardening - RDP Servers" -TargetName "Domain Computers" `
  -TargetType Group -PermissionLevel GpoRead
```

### CARA — WMI Filtering
WMI Filter memakai query WQL terhadap `root\CIMv2`. `ProductType`: **1 = workstation**, **2 = Domain Controller**, **3 = member server**.

```wql
-- Hanya member server (bukan DC, bukan klien)
SELECT * FROM Win32_OperatingSystem WHERE ProductType = "3"

-- Hanya Windows 11 build 22xxx (21H2–23H2); untuk 24H2/25H2 (build 26xxx) sesuaikan pola Version
SELECT * FROM Win32_OperatingSystem WHERE ProductType = "1" AND Version LIKE "10.0.22%"
```

### CARA — Loopback Processing

### APA
**Loopback** memaksa *User Configuration* dari GPO yang ber-link ke OU **komputer** diterapkan, mengabaikan/menggabung GPO user normal. Mode **Merge** (GPO user normal lalu GPO loopback ditimpa di atas) atau **Replace** (hanya GPO loopback user).

### KENAPA
Wajib untuk lingkungan terkunci di mana pengaturan user harus bergantung pada *mesin* yang dipakai, bukan siapa user-nya: server RDS/jump host, kiosk, PAW (-> lihat Modul 01), lab ujian.

### Path
```
Computer Configuration > Policies > Administrative Templates > System > Group Policy >
"Configure user Group Policy loopback processing mode"  ->  Enabled (Merge / Replace)
```
Registry: `HKLM\SOFTWARE\Policies\Microsoft\Windows\System\UserPolicyMode` (1=Merge, 2=Replace).

---

## 5. Tooling GPO: GPMC, PowerShell, gpupdate, gpresult, RSoP

### 5.1 Membuat & Men-link GPO (GroupPolicy module)

```powershell
Import-Module GroupPolicy

# Buat GPO baru (belum ter-link)
New-GPO -Name "Hardening - Member Servers" -Comment "CIS L1 baseline, owner: secops"

# Link ke OU dan aktifkan
New-GPLink -Name "Hardening - Member Servers" -Target "OU=Servers,DC=corp,DC=local" `
  -LinkEnabled Yes -Order 1

# Ubah urutan/enforce/enable link yang sudah ada
Set-GPLink -Name "Hardening - Member Servers" -Target "OU=Servers,DC=corp,DC=local" -Order 1

# Set sebuah registry-based policy langsung dari PowerShell
Set-GPRegistryValue -Name "Hardening - Member Servers" `
  -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
  -ValueName "DontDisplayLastUserName" -Type DWord -Value 1
```

### 5.2 Backup, Restore, Import/Export (change control)

```powershell
Backup-GPO -Name "Hardening - Member Servers" -Path "D:\GPO-Backups"
Backup-GPO -All -Path "D:\GPO-Backups"            # backup semua GPO

# Import isi backup ke GPO (mis. dari baseline Microsoft)
Import-GPO -BackupGpoName "MSFT Windows Server 2022 - Member Server" `
  -TargetName "Hardening - Member Servers" -Path "C:\Baselines\Server2022\GPOs" -CreateIfNeeded

Restore-GPO -Name "Hardening - Member Servers" -Path "D:\GPO-Backups"
```

### 5.3 Refresh & Laporan

```cmd
:: Paksa refresh kebijakan (computer + user) tanpa menunggu interval
gpupdate /force

:: Refresh lalu logoff/reboot bila perlu untuk setting yang butuh itu
gpupdate /force /boot /logoff
```

```cmd
:: Resultant Set of Policy untuk mesin/user saat ini
gpresult /r                              :: ringkasan teks
gpresult /h C:\rsop.html /f              :: laporan HTML lengkap (paling berguna)
gpresult /scope computer /v              :: hanya computer scope, verbose
gpresult /user CORP\siswa /h C:\u.html   :: RSoP user lain (butuh elevasi)
```

```powershell
# Laporan GPO tunggal & RSoP via PowerShell
Get-GPOReport -Name "Hardening - Member Servers" -ReportType Html -Path "C:\gpo.html"
Get-GPOReport -All -ReportType Xml -Path "C:\all-gpos.xml"
Get-GPResultantSetOfPolicy -ReportType Html -Path "C:\rsop.html"
```

> **RSoP modes:** `rsop.msc` menjalankan **Logging Mode** (apa yang benar-benar diterapkan pada mesin ini). GPMC juga punya **Planning Mode** (simulasi "what-if" sebelum link, dijalankan di DC) — berguna menguji dampak sebelum produksi.

---

## 6. Area Kebijakan Keamanan Kunci

Semua path di bawah relatif terhadap:
`Computer Configuration > Policies > Windows Settings > Security Settings > ...`

### 6.1 Account Policies (mekanisme di sini, nilai -> Modul 02)

| Sub-area | Path GPO |
|----------|----------|
| Password Policy | `Account Policies > Password Policy` |
| Account Lockout Policy | `Account Policies > Account Lockout Policy` |
| Kerberos Policy | `Account Policies > Kerberos Policy` |

> Account Policies untuk **domain user** hanya efektif bila di-link pada **Domain root** (Default Domain Policy historisnya). Untuk pengecualian per-grup gunakan **Fine-Grained Password Policy**, bukan GPO di OU. Semua **nilai numerik (panjang password, threshold lockout, lifetime tiket Kerberos) -> lihat Modul 02.**

### 6.2 Local Policies > User Rights Assignment (URA)

### APA & KENAPA
URA mengontrol *siapa boleh melakukan apa* di tingkat logon dan privilege. Ini adalah inti **tier separation** (-> lihat Modul 01): mencegah akun Tier 0 (Domain Admin) logon ke host Tier 1/2 dan sebaliknya, sehingga kredensial high-value tidak pernah ter-cache di mesin yang lebih mudah dikompromikan (membatasi credential theft, T1003 / T1078).

Path: `Local Policies > User Rights Assignment`. Tiap right memiliki nama konstan (`Se*Right`) yang dipakai di `secedit`/INF/LGPO.

| User Right | Konstanta | Tujuan hardening |
|------------|-----------|------------------|
| Deny access to this computer from the network | `SeDenyNetworkLogonRight` | Blok logon jaringan (SMB/RPC) untuk akun privileged & local admin; lawan lateral movement |
| Deny log on through Remote Desktop Services | `SeDenyRemoteInteractiveLogonRight` | Cegah RDP oleh akun yang tidak seharusnya (mis. Domain Admins ke workstation) |
| Allow log on locally | `SeInteractiveLogonRight` | Batasi siapa boleh logon console; di DC hanya admin |
| Access this computer from the network | `SeNetworkLogonRight` | Whitelist akun yang boleh akses jaringan; buang `Everyone` |
| Debug programs | `SeDebugPrivilege` | Hanya Administrators; dipakai untuk dump LSASS (T1003.001) — batasi ketat |
| Back up files and directories | `SeBackupPrivilege` | Bypass ACL untuk baca file (termasuk `ntds.dit`); batasi ke operator backup |
| Restore files and directories | `SeRestorePrivilege` | Bypass ACL untuk tulis; bisa untuk persistence — batasi |
| Impersonate a client after authentication | `SeImpersonatePrivilege` | Default untuk service account; penyalahgunaan = Potato-style privesc (T1134) |
| Log on as a service | `SeServiceLogonRight` | Whitelist akun service; pakai gMSA (-> Modul 01) |
| Log on as a batch job | `SeBatchLogonRight` | Whitelist akun scheduled task |

Contoh penerapan tiering (Tier 0 dilarang logon ke Tier 2):

```ini
; Cuplikan GptTmpl.inf / template secedit
[Privilege Rights]
SeDenyNetworkLogonRight = *S-1-5-32-544,CORP\Tier0-Admins
SeDenyRemoteInteractiveLogonRight = CORP\Tier0-Admins,CORP\Tier1-Admins
SeDebugPrivilege = *S-1-5-32-544
```

> URA bersifat **replace, bukan append** — saat GPO mendefinisikan sebuah right, ia **menggantikan** seluruh daftar, bukan menambah. Selalu sertakan akun yang sah (mis. `Administrators`) agar tidak mengunci diri sendiri.

### 6.3 Local Policies > Security Options

Path: `Local Policies > Security Options`. Setiap entri memetakan ke registry — berguna untuk verifikasi (Bagian 14) dan untuk LGPO di mesin standalone.

| Security Option | Registry | Nilai hardening | Sumber |
|-----------------|----------|-----------------|--------|
| Network security: LAN Manager authentication level | `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LmCompatibilityLevel` | `5` (Send NTLMv2 only, refuse LM & NTLM) — detail NTLM **-> Modul 02** | MS Baseline / CIS |
| Network access: Do not allow anonymous enumeration of SAM accounts | `...\Control\Lsa\RestrictAnonymousSAM` | `1` | CIS |
| Network access: Do not allow anonymous enumeration of SAM accounts **and shares** | `...\Control\Lsa\RestrictAnonymous` | `1` | CIS |
| Microsoft network server: Digitally sign communications (always) | `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\RequireSecuritySignature` | `1` — SMB signing detail **-> Modul 04** | MS Baseline / CIS |
| LSA Protection (RunAsPPL) | `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL` | `1` — proteksi LSASS dari dump (T1003.001) | MS Baseline |
| Interactive logon: Do not display last user name | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUserName` | `1` | CIS |
| Accounts: Limit local account use of blank passwords to console logon only | `...\Control\Lsa\LimitBlankPasswordUse` | `1` | CIS |

**User Account Control (UAC)** — sub-set Security Options, registry di `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:

| Setting | Registry value | Nilai | Sumber |
|---------|----------------|-------|--------|
| Run all administrators in Admin Approval Mode | `EnableLUA` | `1` | MS Baseline / CIS |
| Switch to the secure desktop when prompting for elevation | `PromptOnSecureDesktop` | `1` | MS Baseline / CIS |
| Admin Approval Mode for the built-in Administrator account | `FilterAdministratorToken` | `1` (Enabled) | CIS |
| Behavior of the elevation prompt for administrators | `ConsentPromptBehaviorAdmin` | `2` (Prompt for consent on the secure desktop) | CIS L1 = 2 |
| Behavior of the elevation prompt for standard users | `ConsentPromptBehaviorUser` | `0` (Automatically deny elevation requests) | CIS L1 = 0 |
| Detect application installations and prompt for elevation | `EnableInstallerDetection` | `1` | CIS |

```reg
Windows Registry Editor Version 5.00

; Contoh hasil yang diharapkan dari GPO (jangan edit registry manual di produksi — pakai GPO)
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa]
"RunAsPPL"=dword:00000001
"LmCompatibilityLevel"=dword:00000005
"RestrictAnonymous"=dword:00000001
```

---

## 7. Security Compliance Toolkit (SCT)

### APA
**Microsoft Security Compliance Toolkit (SCT)** adalah kumpulan resmi untuk menerapkan & mengaudit baseline keamanan. Komponennya:

| Tool | Fungsi |
|------|--------|
| **Security Baselines** | Set GPO backup + spreadsheet + script per OS (Windows 11, Windows Server 2022, Edge, Office) |
| **PolicyAnalyzer.exe** | Bandingkan beberapa baseline / GPO backup / kebijakan lokal efektif; sorot konflik & selisih |
| **LGPO.exe** | Import/export GPO backup, `registry.pol`, security template (INF), dan tweak registry ke/dari **Local GPO** |
| **SetObjectSecurity.exe** | Set security descriptor pada objek (registry/file) sebagai bagian baseline |

### KENAPA
Baseline Microsoft sudah memetakan ratusan setting ke nilai yang diuji. Mengimpornya jauh lebih cepat & akurat daripada menyetel manual. **PolicyAnalyzer** menjawab pertanyaan lomba klasik: "apa selisih kebijakan mesin ini terhadap baseline?". **LGPO.exe** adalah jembatan untuk mesin **standalone/workgroup** yang tidak punya DC.

### CARA — Policy Analyzer (compare)
1. Jalankan `PolicyAnalyzer.exe`.
2. *Add* > pilih folder `GPOs` baseline (mis. `\Windows Server 2022 Security Baseline\GPOs`).
3. *Add* > *Import* > pilih **Effective State** / `LocalPolicy` mesin saat ini.
4. *Compare* > kolom merah menandai selisih; ekspor ke Excel sebagai bukti.

### CARA — LGPO.exe ke mesin standalone

```cmd
:: Terapkan satu folder GPO backup ke Local GPO
LGPO.exe /g "C:\Baselines\Server2022\GPOs\{GUID}"

:: Terapkan registry.pol langsung
LGPO.exe /m "C:\Baselines\Server2022\GPOs\{GUID}\DomainSysvol\GPO\Machine\registry.pol"

:: Terapkan security template (URA + Security Options) dari INF
LGPO.exe /s "C:\Baselines\hardening.inf"

:: Backup Local GPO saat ini (sebelum perubahan!) lalu refresh
LGPO.exe /b "C:\LocalGPO-Backup"
gpupdate /force
```

> Flag penting LGPO: `/g` (GPO backup dir), `/m` (machine `registry.pol`), `/u` (user `registry.pol`), `/s` (security INF), `/b` (backup local policy), `/parse` (parse pol -> teks). Selalu `/b` dulu agar bisa rollback.

---

## 8. Application Control via GPO: AppLocker & WDAC

### 8.1 AppLocker

### APA
**AppLocker** membatasi binary/script mana yang boleh dieksekusi, berdasarkan **Publisher** (signature), **Path**, atau **File Hash**. Path GPO:
`Computer Configuration > Policies > Windows Settings > Security Settings > Application Control Policies > AppLocker`.

Rule collections:

| Collection | Tipe file |
|------------|-----------|
| Executable Rules | `.exe`, `.com` |
| Windows Installer Rules | `.msi`, `.msp`, `.mst` |
| Script Rules | `.ps1`, `.bat`, `.cmd`, `.vbs`, `.js` |
| Packaged app Rules | `.appx` (Store/UWP) |
| DLL Rules | `.dll`, `.ocx` (opsional, biaya performa) |

### KENAPA
Application control adalah salah satu mitigasi paling efektif terhadap eksekusi tools penyerang, LOLBins yang di-drop, dan ransomware (T1204, T1059). Memblok eksekusi dari folder yang bisa ditulis user (mis. `%TEMP%`, `Downloads`) memutus banyak rantai serangan.

### CARA
1. **Aktifkan service Application Identity (`AppIDSvc`)** — AppLocker tidak menegakkan tanpa ini. Set via GPO: `Computer Configuration > Preferences > Control Panel Settings > Services`, atau:
   ```powershell
   Set-Service -Name AppIDSvc -StartupType Automatic
   Start-Service AppIDSvc
   ```
   > Di Windows 10/11 terkini `AppIDSvc` adalah service yang dilindungi/trigger-started; `Set-Service` bisa mengembalikan *Access Denied* meski sebagai admin. Bila demikian, set startup-nya lewat GPO **System Services** (`Computer Configuration > Policies > Windows Settings > Security Settings > System Services > Application Identity -> Automatic`).
2. Buat **Default Rules** dulu (klik kanan tiap collection > *Create Default Rules*) — mengizinkan `Program Files`, `Windows`, dan Administrators penuh, agar OS tidak rusak.
3. Set **Enforcement mode**: mulai dari **Audit only** (logging tanpa blokir) sebelum **Enforce rules**, agar tahu apa yang akan terblokir.
   ```
   AppLocker > klik kanan AppLocker > Properties > tab tiap collection > Configured: Audit only / Enforce rules
   ```
4. PowerShell:
   ```powershell
   Get-AppLockerPolicy -Effective -Xml
   New-AppLockerPolicy -RuleType Publisher,Hash -User Everyone `
     -FileInformation (Get-ChildItem "C:\Program Files\App\*.exe" | Get-AppLockerFileInformation)
   Test-AppLockerPolicy -XmlPolicy C:\policy.xml -Path "C:\Temp\evil.exe" -User Everyone
   ```

> **CAVEAT bypass default Path rules (sering diuji).** Default Rules mengizinkan **seluruh** `%WINDIR%` (`%SYSTEM32%` dan `C:\Windows\*`) lewat rule berbasis path. Masalahnya, sejumlah sub-folder di bawah `%WINDIR%` **writable oleh user non-admin**, sehingga penyerang men-drop EXE/script ke sana dan **lolos** dari allow-list path. Folder klasik yang harus diwaspadai:
>
> ```text
> C:\Windows\Tasks
> C:\Windows\Temp
> C:\Windows\tracing
> C:\Windows\Registration\CRMLog
> C:\Windows\System32\spool\drivers\color
> C:\Windows\System32\Tasks (writable via beberapa konfigurasi)
> C:\Windows\System32\com\dmp  &  C:\Windows\System32\spool\PRINTERS
> ```
>
> Mitigasi: (1) **utamakan Publisher rules** (signature) daripada path lebar; (2) tambahkan **deny rule eksplisit** untuk folder-folder di atas (deny menang atas allow di AppLocker); (3) untuk host bernilai tinggi (Tier 0/PAW) gunakan **WDAC/App Control for Business** yang ditegakkan kernel (Bagian 8.2). Verifikasi celah ini dengan `Test-AppLockerPolicy -Path "C:\Windows\Temp\evil.exe" -User Everyone` — bila hasilnya *Allowed*, path rule Anda masih rawan.

> Event AppLocker (allowed/blocked) berada di log `Microsoft-Windows-AppLocker/*` — **daftar Event ID & audit -> lihat Modul 06.**

### 8.2 WDAC (App Control for Business) — ringkasan

### APA & KENAPA
**Windows Defender Application Control (WDAC)** — di Windows 11 disebut **App Control for Business** — adalah application control yang **lebih kuat**: ditegakkan oleh **kernel/Code Integrity (CI)**, lebih tahan bypass, dan dapat dikunci sehingga **admin lokal pun tidak bisa menonaktifkannya**. Cocok untuk Tier 0 / PAW (-> Modul 01).

| Aspek | AppLocker | WDAC |
|-------|-----------|------|
| Penegakan | user-mode (`AppIDSvc`) | kernel (Code Integrity) |
| Bypass admin lokal | bisa | sangat sulit (signed policy) |
| Granularitas | per-user collection | per-mesin, plus driver/kernel |
| Kompleksitas | rendah-menengah | tinggi |

### CARA (ringkas)
```powershell
# Buat policy dari scan referensi, lalu konversi ke biner
New-CIPolicy -FilePath C:\WDAC\policy.xml -Level Publisher -ScanPath "C:\Program Files" -UserPEs
Merge-CIPolicy -PolicyPaths C:\WDAC\policy.xml, C:\WDAC\base.xml -OutputFilePath C:\WDAC\merged.xml
ConvertFrom-CIPolicy -XmlFilePath C:\WDAC\merged.xml -BinaryFilePath C:\WDAC\policy.cip
```
Deploy WDAC via GPO (`Computer Configuration > ... > System > Device Guard > Deploy Windows Defender Application Control`), Intune, atau script. **Detail integrasi Defender/Device Guard -> lihat Modul 05.**

**Kapan pilih mana:** AppLocker untuk penerapan cepat & granular per-user di klien terkelola; WDAC untuk host bernilai tinggi yang butuh penegakan kernel anti-tamper. Keduanya bisa dipakai bersamaan (WDAC menetapkan batas keras, AppLocker mengatur per-user).

---

## 9. Contoh GPO Hardening Praktis

Setiap baris: APA -> KENAPA -> CARA (path/registry).

### 9.1 Blokir Removable Storage
- **APA:** tolak akses ke USB mass storage. **KENAPA:** mencegah exfiltrasi (T1052) & drop malware (T1091).
- **CARA:** `Computer Configuration > Policies > Administrative Templates > System > Removable Storage Access > "All Removable Storage classes: Deny all access" -> Enabled`.
- Registry: `HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\Deny_All = 1`.

### 9.2 Batasi RDP
- **APA:** wajibkan NLA & batasi siapa boleh RDP. **KENAPA:** lawan brute force & lateral movement (T1021.001).
- **CARA URA:** `Deny log on through Remote Desktop Services` -> isi grup non-admin/Tier mismatch (Bagian 6.2).
- **CARA NLA:** `Computer Configuration > Policies > Administrative Templates > Windows Components > Remote Desktop Services > Remote Desktop Session Host > Security > "Require user authentication for remote connections by using Network Level Authentication" -> Enabled`. **Transport/TLS RDP detail -> lihat Modul 04.**

### 9.3 Blokir Macro Office dari Internet
- **APA:** cegah macro berjalan pada file Office yang berasal dari internet (Mark-of-the-Web). **KENAPA:** vektor phishing klasik (T1566.001 / T1204.002).
- **CARA:** butuh ADMX Microsoft 365 Apps di Central Store. `User Configuration > Policies > Administrative Templates > Microsoft Word 2016 > Word Options > Security > Trust Center > "Block macros from running in Office files from the Internet" -> Enabled` (ulangi untuk Excel/PowerPoint).
- Registry: `HKCU\Software\Policies\Microsoft\Office\16.0\word\security\blockcontentexecutionfrominternet = 1`.

### 9.4 Nonaktifkan PowerShell v2
- **APA:** hapus engine PSv2 (tanpa AMSI/logging). **KENAPA:** downgrade attack (T1059.001) menghindari logging modern.
- **CARA:** kelola via GPO Preferences/script; mekanisme Optional Feature **-> lihat Modul 04.**

### 9.5 Aktifkan Audit
- **APA:** aktifkan Advanced Audit Policy. **KENAPA:** tanpa audit, tidak ada deteksi.
- **CARA:** `Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy Configuration`. **Subkategori, nilai Success/Failure, dan daftar Event ID -> lihat Modul 06.**

---

## 10. Best Practice & Mengamankan GPO Itu Sendiri

GPO bukan hanya alat hardening — ia juga **permukaan serangan**. Penyerang yang mengubah GPO ber-link mendapat eksekusi kode massal (**T1484.001 — Group Policy Modification**).

| Praktik | Detail |
|---------|--------|
| **Penamaan konsisten** | Awali dengan fungsi+scope, mis. `Hardening - Member Servers (CIS L1)`. Hindari nama generik. |
| **Satu tujuan per GPO** | GPO kecil & fokus lebih mudah di-audit, di-rollback, dan di-filter daripada satu GPO raksasa. |
| **Jangan link sembarangan di Domain root** | Hanya kebijakan yang benar-benar domain-wide (Account Policy) di root. Hardening spesifik di OU. |
| **Delegasi minimal** | Hanya grup admin GPO terbatas yang punya *Edit settings, delete, modify security*. Audit izin via GPMC > Delegation. |
| **Lindungi Tier 0 GPO** | GPO yang ber-link ke OU Domain Controllers / Tier 0 harus dianggap aset Tier 0 (-> Modul 01). |
| **Backup & change control** | `Backup-GPO -All` terjadwal; review perubahan sebelum apply (gunakan Planning Mode / PolicyAnalyzer). |
| **Audit perubahan GPO** | Pantau modifikasi GPC/GPT. **Mekanisme & Event ID deteksi -> lihat Modul 06.** |

```powershell
# Audit siapa yang bisa mengedit tiap GPO (cari izin berlebih)
Get-GPO -All | ForEach-Object {
  $gpo = $_
  Get-GPPermission -Guid $gpo.Id -All |
    Where-Object { $_.Permission -match "Edit|GpoEditDeleteModifySecurity" } |
    Select-Object @{n="GPO";e={$gpo.DisplayName}}, Trustee, Permission
}
```

---

## Serangan Umum & Mitigasi

| Teknik penyerang | MITRE ATT&CK | Mitigasi via GPO (modul ini) |
|------------------|--------------|------------------------------|
| Modifikasi GPO ber-link untuk eksekusi massal / scheduled task jahat | **T1484.001** | Delegasi minimal, GPO Tier 0 = aset Tier 0, backup + deteksi perubahan (-> Modul 06) |
| Mengubah Domain Policy / lockout untuk melemahkan auth | **T1484** | Lindungi Default Domain Policy, batasi siapa edit, Enforced pada baseline |
| Dump LSASS untuk kredensial | **T1003.001** | `RunAsPPL=1`, batasi `SeDebugPrivilege` ke Administrators, Credential Guard (-> Modul 01) |
| Pencurian & reuse kredensial admin lewat lateral movement | **T1003 / T1078** | URA Deny network/RDP logon untuk tier mismatch (Bagian 6.2) |
| `cpassword` di Groups.xml SYSVOL | **T1552.006** | Jangan pakai GPP untuk password; bersihkan XML lama (Bagian 3.3); pakai Windows LAPS (-> Modul 01) |
| Eksekusi tools/LOLBins & ransomware | **T1204 / T1059** | AppLocker/WDAC, blok eksekusi dari folder writable user (Bagian 8) |
| Exfiltrasi / infeksi via USB | **T1052 / T1091** | Deny all removable storage (Bagian 9.1) |
| Phishing macro Office | **T1566.001 / T1204.002** | Block macros from the Internet (Bagian 9.3) |
| Downgrade PowerShell v2 hindari logging | **T1059.001** | Nonaktifkan PSv2 (-> Modul 04), aktifkan logging (-> Modul 06) |
| Enumerasi anonim SAM/share untuk recon | **T1087 / T1135** | `RestrictAnonymous(SAM)=1` (Bagian 6.3) |

---

## Hardening Checklist (Modul Ini)

- [ ] Central Store ADMX dibuat di `\\<domain>\SYSVOL\<domain>\Policies\PolicyDefinitions`
- [ ] GPO baseline Microsoft (Server 2022 / Windows 11) di-import via `Import-GPO` dan di-link ke OU yang benar — termasuk baseline **Domain Controller** ke OU `Domain Controllers` (bukan hanya Member Server)
- [ ] Baseline penting di-set **Enforced**; OU sensitif dipertimbangkan **Block Inheritance** dengan sadar
- [ ] Security Filtering kustom selalu menyertakan Read untuk `Domain Computers` (gotcha MS16-072)
- [ ] WMI Filter memisahkan DC (`ProductType=2`) / member server (`3`) / klien (`1`) bila perlu
- [ ] Loopback (Merge/Replace) aktif pada OU jump host / RDS / kiosk
- [ ] URA tier separation di-set (Deny network & RDP logon untuk tier mismatch)
- [ ] `SeDebugPrivilege`, `SeBackupPrivilege`, `SeImpersonatePrivilege` dibatasi ke grup minimal
- [ ] Security Options: `RunAsPPL=1`, `LmCompatibilityLevel=5`, `RestrictAnonymous(SAM)=1`, `DontDisplayLastUserName=1`, `LimitBlankPasswordUse=1`
- [ ] UAC: `EnableLUA=1`, `PromptOnSecureDesktop=1`, `FilterAdministratorToken=1`
- [ ] AppLocker default rules + Audit-only dulu, lalu Enforce; `AppIDSvc` Automatic; **utamakan Publisher rules** & deny sub-folder `%WINDIR%` writable (Tasks/Temp/tracing/spool) untuk tutup bypass path
- [ ] Removable storage Deny all (host sensitif), RDP NLA wajib, macro Office dari internet diblok
- [ ] Tidak ada `cpassword` tersisa di SYSVOL
- [ ] GPO dibackup (`Backup-GPO -All`), delegasi/permission GPO di-audit
- [ ] Verifikasi penerapan dengan `gpresult /h` dan `rsop.msc`

---

## Lab Praktik

**Skenario:** Terapkan Microsoft Security Baseline + GPO hardening kustom ke OU `Servers`, lalu verifikasi.

1. **Siapkan Central Store**
   - Lakukan: jalankan blok `Copy-Item` Bagian 3.1 di DC.
   - Konfirmasi dengan: edit Administrative Templates di GPMC -> muncul tag "(central store)".

2. **Import baseline ke GPO (Member Server DAN Domain Controller)**
   - Lakukan: unduh **Windows Server 2022 Security Baseline** (SCT), lalu import **kedua** baseline — member server untuk OU `Servers`, dan **Domain Controller** untuk OU bawaan `Domain Controllers` (jangan lewatkan DC: DC adalah Tier 0, baseline-nya berbeda dari member server):
     ```powershell
     # Member server baseline
     New-GPO -Name "MSFT - Server 2022 Member"
     Import-GPO -BackupGpoName "MSFT Windows Server 2022 - Member Server" `
       -TargetName "MSFT - Server 2022 Member" `
       -Path "C:\Baselines\Server2022\GPOs" -CreateIfNeeded

     # Domain Controller baseline (WAJIB untuk DC)
     New-GPO -Name "MSFT - Server 2022 Domain Controller"
     Import-GPO -BackupGpoName "MSFT Windows Server 2022 - Domain Controller" `
       -TargetName "MSFT - Server 2022 Domain Controller" `
       -Path "C:\Baselines\Server2022\GPOs" -CreateIfNeeded
     New-GPLink -Name "MSFT - Server 2022 Domain Controller" `
       -Target "OU=Domain Controllers,DC=corp,DC=local" -LinkEnabled Yes -Order 1

     # (Opsional) Domain-wide security baseline ke root domain
     # Import-GPO -BackupGpoName "MSFT Windows Server 2022 - Domain Security" ...
     ```
   - Konfirmasi dengan: `Get-GPOReport -Name "MSFT - Server 2022 Domain Controller" -ReportType Html -Path C:\dc.html` lalu buka HTML; dan `Get-GPInheritance -Target "OU=Domain Controllers,DC=corp,DC=local"` → GPO DC baseline terdaftar. Di DC jalankan `gpupdate /force` lalu `gpresult /scope computer /r` untuk memastikan baseline DC ter-apply.

3. **Buat GPO hardening kustom & link**
   - Lakukan:
     ```powershell
     New-GPO -Name "Hardening - Servers (Lab)"
     Set-GPRegistryValue -Name "Hardening - Servers (Lab)" `
       -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" -ValueName "RunAsPPL" -Type DWord -Value 1
     New-GPLink -Name "Hardening - Servers (Lab)" -Target "OU=Servers,DC=corp,DC=local" -LinkEnabled Yes -Order 1
     ```
   - Konfirmasi dengan: GPMC > OU `Servers` > tab *Group Policy Inheritance* menampilkan kedua GPO dengan precedence benar.

4. **Refresh & verifikasi pada member server**
   - Lakukan: di server target jalankan `gpupdate /force`.
   - Konfirmasi dengan: `gpresult /h C:\rsop.html /f` lalu buka — pastikan kedua GPO terdaftar di *Applied GPOs* dan `RunAsPPL` muncul.
   - Konfirmasi tambahan: `rsop.msc` (Logging Mode) menampilkan setting yang efektif.

5. **(Standalone) Terapkan baseline via LGPO**
   - Lakukan: di klien workgroup, `LGPO.exe /b C:\bak` lalu `LGPO.exe /g "...\GPOs\{GUID}"`, kemudian `gpupdate /force`.
   - Konfirmasi dengan: `secedit /export /cfg C:\eff.inf` lalu periksa `[Privilege Rights]` & registry pada Bagian 14.

6. **Uji precedence (opsional)**
   - Lakukan: buat GPO "Override Test" yang men-set `DontDisplayLastUserName=0`, link dengan Order lebih rendah; lalu set GPO hardening **Enforced**.
   - Konfirmasi dengan: `gpresult /h` menunjukkan nilai dari GPO Enforced yang menang meski ada override.

---

## Perintah Audit/Verifikasi

```cmd
:: 1) RSoP HTML lengkap — output: daftar "Applied GPOs" + nilai efektif
gpresult /h C:\rsop.html /f

:: 2) Ringkasan teks cepat — output: bagian "Applied Group Policy Objects"
gpresult /r /scope computer
```

```powershell
# 3) Verifikasi setting registry hasil GPO (output yang diharapkan di komentar)
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" |
  Select-Object RunAsPPL, LmCompatibilityLevel, RestrictAnonymous, RestrictAnonymousSAM, LimitBlankPasswordUse
# Diharapkan: RunAsPPL=1, LmCompatibilityLevel=5, RestrictAnonymous=1, RestrictAnonymousSAM=1, LimitBlankPasswordUse=1

Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" |
  Select-Object EnableLUA, PromptOnSecureDesktop, FilterAdministratorToken, DontDisplayLastUserName
# Diharapkan: EnableLUA=1, PromptOnSecureDesktop=1, FilterAdministratorToken=1, DontDisplayLastUserName=1

# 4) Verifikasi link & status GPO pada sebuah OU
Get-GPInheritance -Target "OU=Servers,DC=corp,DC=local" |
  Select-Object -ExpandProperty GpoLinks
# Diharapkan: GPO hardening terdaftar, Enabled=True, urutan sesuai

# 5) Verifikasi izin/delegasi GPO (cari trustee tak terduga)
Get-GPPermission -Name "Hardening - Servers (Lab)" -All |
  Select-Object Trustee, Permission

# 6) Verifikasi AppLocker efektif
Get-AppLockerPolicy -Effective -Xml
Get-Service AppIDSvc | Select-Object Name, Status, StartType   # Diharapkan: Running / Automatic

# 7) Pastikan tidak ada cpassword tersisa (output harus kosong)
Get-ChildItem "\\corp.local\SYSVOL" -Recurse -Include *.xml -ErrorAction SilentlyContinue |
  Select-String "cpassword"
```

```cmd
:: 8) Verifikasi URA & Security Options efektif via secedit (standalone/local)
secedit /export /cfg C:\eff.inf
:: Periksa [Privilege Rights] (SeDenyNetworkLogonRight dll.) dan nilai registry di C:\eff.inf
```

---

## Referensi

- **Microsoft Security Baselines / Security Compliance Toolkit (SCT)** — Microsoft Learn: "Microsoft Security Compliance Toolkit 1.0" (Security Baselines, Policy Analyzer, LGPO.exe, SetObjectSecurity.exe).
- **CIS Benchmarks** — *CIS Microsoft Windows Server 2022 Benchmark* & *CIS Microsoft Windows 11 Enterprise Benchmark* (Level 1/2): sumber tunggal nilai numerik & registry pada modul ini.
- **Microsoft Learn — Group Policy:** "Group Policy processing and precedence", "Loopback processing", "Create a Central Store for Group Policy Administrative Templates", "How to make Win32 changes for MS16-072".
- **Microsoft Learn — Security policy settings:** "User Rights Assignment", "Security Options", "User Account Control Group Policy and registry key settings".
- **Microsoft Learn — Application Control:** "AppLocker" (rule collections, Application Identity service) & "Windows Defender Application Control / App Control for Business".
- **MS14-025** — "Vulnerability in Group Policy Preferences could allow elevation of privilege" (cpassword).
- **MITRE ATT&CK** — T1484.001 (Group Policy Modification), T1003.001, T1552.006, T1059.001, T1052/T1091, T1566.001.
- Lihat juga: **Modul 01** (PAM/tiering/LAPS), **Modul 02** (Account & Kerberos & NTLM values), **Modul 04** (Firewall/SMB/RDP transport), **Modul 05** (Defender/WDAC), **Modul 06** (Advanced Audit Policy & Event ID).
