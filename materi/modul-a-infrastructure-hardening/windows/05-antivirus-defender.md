# Modul 05 — Antivirus: Microsoft Defender Antivirus & EDR

> Microsoft Defender Antivirus adalah lapisan pertahanan *endpoint* bawaan Windows yang menggabungkan signature, behavior monitoring, cloud protection, dan rangkaian Attack Surface Reduction. Modul ini penting karena hampir setiap intrusi modern berusaha **mematikan, mengakali (bypass AMSI), atau "membutakan" AV** sebelum menjalankan payload — sehingga menghardening Defender dan melindunginya dengan Tamper Protection sama pentingnya dengan mengaktifkannya. Dari sudut pandang penyerang, Defender yang dikonfigurasi lemah (exclusion berlebihan, cloud protection mati, ASR tidak aktif) adalah "lampu hijau" untuk eksekusi tooling seperti Mimikatz, Cobalt Strike, dan ransomware.

## Daftar Isi

1. [Konsep & Tujuan](#1-konsep--tujuan)
2. [Arsitektur Microsoft Defender Antivirus](#2-arsitektur-microsoft-defender-antivirus)
3. [Status & Manajemen Dasar (PowerShell, GPO, Intune)](#3-status--manajemen-dasar-powershell-gpo-intune)
4. [Real-time Protection & Behavior Monitoring](#4-real-time-protection--behavior-monitoring)
5. [Cloud-Delivered Protection (MAPS) & Block at First Sight](#5-cloud-delivered-protection-maps--block-at-first-sight)
6. [PUA Protection & Sample Submission](#6-pua-protection--sample-submission)
7. [Update Signature & Scan](#7-update-signature--scan)
8. [Attack Surface Reduction (ASR) Rules](#8-attack-surface-reduction-asr-rules)
9. [Controlled Folder Access (Anti-Ransomware)](#9-controlled-folder-access-anti-ransomware)
10. [Network Protection](#10-network-protection)
11. [Tamper Protection](#11-tamper-protection)
12. [Manajemen Exclusions](#12-manajemen-exclusions)
13. [Exploit Protection (Pengganti EMET)](#13-exploit-protection-pengganti-emet)
14. [SmartScreen (App & Browser Control)](#14-smartscreen-app--browser-control)
15. [AMSI (Antimalware Scan Interface)](#15-amsi-antimalware-scan-interface)
16. [WDAC vs AppLocker (Ringkas)](#16-wdac-vs-applocker-ringkas)
17. [Microsoft Defender for Endpoint (EDR)](#17-microsoft-defender-for-endpoint-edr)
- [Serangan Umum & Mitigasi](#serangan-umum--mitigasi)
- [Hardening Checklist (Modul Ini)](#hardening-checklist-modul-ini)
- [Lab Praktik](#lab-praktik)
- [Perintah Audit/Verifikasi](#perintah-auditverifikasi)
- [Panduan GUI (Langkah Klik)](#panduan-gui-langkah-klik)
- [Referensi](#referensi)

---

## 1. Konsep & Tujuan

Microsoft Defender Antivirus (sebelumnya "Windows Defender") adalah komponen anti-malware bawaan yang aktif secara default di Windows 10/11 dan Windows Server 2016+. Engine AV-nya sudah terinstal & aktif by default sejak **Windows Server 2016**; perbedaannya, Server 2016 **tidak** menyertakan antarmuka GUI Defender secara default (perlu ditambahkan via fitur `Windows-Defender-Gui`, mis. `Dism /Online /Enable-Feature /FeatureName:Windows-Defender-Gui`), sedangkan **Windows Server 2022** sudah menyertakan engine sekaligus antarmuka modern by default. Defender bekerja dalam beberapa **running mode**: `Normal` (AV utama), `Passive` (ada AV pihak ketiga, Defender hanya mendeteksi tanpa remediasi otomatis kecuali EDR block mode), dan `EDR Block Mode`.

Tujuan hardening Defender pada konteks LKS:

- **Memastikan semua lapisan proteksi aktif** (real-time, behavior, cloud, network) dan tidak dapat dimatikan oleh attacker (Tamper Protection).
- **Mengurangi attack surface** melalui ASR rules, Controlled Folder Access, dan Exploit Protection sebelum malware sempat dieksekusi.
- **Memastikan kebijakan dikelola terpusat** (GPO/Intune) sehingga konsisten antar host domain — cara membuat & me-link GPO **-> lihat Modul 03**.
- **Meminimalkan exclusion** karena exclusion adalah celah favorit attacker (T1562.001).

Defender adalah **defense-in-depth**, bukan satu-satunya kontrol. Ia berdampingan dengan firewall (**-> Modul 04**), application control/WDAC (**-> Modul 03**), dan logging/Sysmon (**-> Modul 06**).

---

## 2. Arsitektur Microsoft Defender Antivirus

**APA.** Defender terdiri dari beberapa engine yang bekerja berlapis:

| Komponen | Fungsi |
|----------|--------|
| **Real-time protection (RTP)** | Scan on-access setiap file yang dibuka/ditulis/dieksekusi |
| **IOAV protection** | Scan file yang di-download dari Internet/email attachment sebelum dibuka |
| **Behavior monitoring** | Deteksi pola perilaku mencurigakan (fileless, injeksi proses) secara runtime |
| **Cloud-delivered protection (MAPS)** | Reputasi & analisis cloud Microsoft untuk deteksi ancaman baru dalam milidetik |
| **Block at First Sight (BAFS)** | Blokir file baru/langka yang belum dikenal sampai cloud memberi verdict |
| **Network Inspection System (NIS)** | Deteksi eksploit berbasis jaringan |
| **PUA protection** | Blokir Potentially Unwanted Applications (adware, bundleware, miner) |
| **AMSI** | Antarmuka agar script/macro (PowerShell, VBA, JScript) discan saat runtime |

**KENAPA.** Signature-only AV mudah dilewati malware baru. Kombinasi behavior + cloud + ASR memberi deteksi *pre-execution* dan *post-execution*, menutup teknik fileless dan zero-day yang tidak punya signature.

**CARA (lihat status arsitektur).**

```powershell
# Ringkasan status seluruh engine
Get-MpComputerStatus | Select-Object `
  AMRunningMode, RealTimeProtectionEnabled, BehaviorMonitorEnabled, `
  IoavProtectionEnabled, OnAccessProtectionEnabled, NISEnabled, `
  IsTamperProtected, AntivirusSignatureLastUpdated
```

Output yang diharapkan pada host ter-harden: `AMRunningMode = Normal`, semua `*Enabled = True`, `IsTamperProtected = True`.

---

## 3. Status & Manajemen Dasar (PowerShell, GPO, Intune)

**APA.** Tiga jalur konfigurasi utama: PowerShell (`Set-MpPreference`/`Add-MpPreference`), GPO, dan Microsoft Intune.

**KENAPA.** Untuk lab/lomba, PowerShell paling cepat untuk demonstrasi & verifikasi. Di lingkungan domain, **GPO** atau **Intune** memastikan konsistensi dan tidak dapat diubah lokal oleh user biasa.

**CARA.**

- **PowerShell — baca konfigurasi & status:**

```powershell
Get-MpComputerStatus    # status runtime (engine aktif, versi, signature)
Get-MpPreference        # nilai konfigurasi (preferences) yang sedang berlaku
```

- **PowerShell — ubah konfigurasi:** `Set-MpPreference` menimpa nilai; `Add-MpPreference` menambah ke list (mis. exclusion, ASR). `Remove-MpPreference` menghapus dari list.

- **GUI:** `Windows Security` app > **Virus & threat protection** > *Manage settings*.

- **GPO path (induk untuk seluruh setting Defender):**
  `Computer Configuration > Policies > Administrative Templates > Windows Components > Microsoft Defender Antivirus`
  Cara membuat, me-link, dan filtering GPO ini **-> lihat Modul 03**.

- **Intune:** *Endpoint security > Antivirus* (profile **Microsoft Defender Antivirus**) dan *Attack surface reduction* untuk ASR/CFA/Network Protection/Exploit Protection.

> **Prioritas konflik:** setting Defender yang didorong **GPO/Intune** disimpan di hive kebijakan `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`, sedangkan perubahan lokal `Set-MpPreference` disimpan di `HKLM\SOFTWARE\Microsoft\Windows Defender`. Saat keduanya berbeda, **nilai kebijakan (Policies\...) menang** atas nilai lokal. `Get-MpPreference` menampilkan nilai **efektif gabungan** dari kedua hive — jadi keberadaan subkey di `Policies\Microsoft\Windows Defender` adalah indikator bahwa kebijakan dikelola terpusat, bukan sekadar `Set-MpPreference` lokal. (Untuk ASR, *Disable Local Admin Merge* dari Intune/GPO bahkan dapat membuat exclusion lokal **diabaikan** sepenuhnya — lihat bagian 8.)

---

## 4. Real-time Protection & Behavior Monitoring

**APA.** Real-time protection memindai file saat diakses; behavior monitoring memantau perilaku proses berjalan.

**KENAPA.** Mematikan RTP (`-DisableRealtimeMonitoring $true`) adalah salah satu langkah pertama attacker (T1562.001). Behavior monitoring menangkap teknik fileless yang tidak menyentuh disk.

**CARA (pastikan AKTIF — perhatikan logika "Disable*" bernilai `$false`).**

```powershell
Set-MpPreference -DisableRealtimeMonitoring  $false   # RTP aktif
Set-MpPreference -DisableBehaviorMonitoring  $false   # behavior monitoring aktif
Set-MpPreference -DisableIOAVProtection      $false   # scan file unduhan/attachment
Set-MpPreference -DisableScriptScanning      $false   # scan script
Set-MpPreference -DisableRemovableDriveScanning $false
```

> **Catatan penting:** Saat **Tamper Protection** aktif, upaya menonaktifkan RTP via `Set-MpPreference -DisableRealtimeMonitoring $true` akan **ditolak/diabaikan**. Ini sengaja — lihat bagian 11.

**GPO:** `... > Microsoft Defender Antivirus > Real-time Protection` → *Turn off real-time protection = Disabled* (artinya RTP tetap menyala).
**Registry (efek GPO):** `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring = 0`.

---

## 5. Cloud-Delivered Protection (MAPS) & Block at First Sight

**APA.** MAPS (Microsoft Active Protection Service, kini bagian dari **cloud-delivered protection**) mengirim metadata/sample mencurigakan ke cloud Microsoft untuk verdict cepat. **Block at First Sight (BAFS)** menahan file baru/langka sampai cloud menjawab.

**KENAPA.** Memberi deteksi ancaman baru tanpa menunggu signature update harian. Microsoft Security Baseline mewajibkan cloud-delivered protection & Block at First Sight aktif; CIS Benchmark menambahkan rekomendasi block level **High**.

**CARA.**

```powershell
Set-MpPreference -MAPSReporting Advanced          # 0=Disabled, 1=Basic, 2=Advanced
Set-MpPreference -SubmitSamplesConsent SendSafeSamples  # lihat tabel bagian 6
Set-MpPreference -DisableBlockAtFirstSeen $false  # BAFS aktif
Set-MpPreference -CloudBlockLevel High            # Default/Moderate/High/HighPlus/ZeroTolerance
Set-MpPreference -CloudExtendedTimeout 50         # detik tambahan menunggu cloud (maks 50)
```

**Prasyarat BAFS** (semua harus benar): `MAPSReporting=Advanced`, `SubmitSamplesConsent` mengizinkan kirim sample, `DisableIOAVProtection=$false`, `DisableRealtimeMonitoring=$false`, `DisableBlockAtFirstSeen=$false`.

| Setting | Nilai disarankan | Sumber anchor |
|---------|------------------|---------------|
| `MAPSReporting` | `Advanced` (2) | Microsoft Security Baseline; CIS Benchmark |
| `CloudBlockLevel` | `High` | CIS Benchmark |
| `CloudExtendedTimeout` | `50` detik | Microsoft Learn (rekomendasi BAFS) |
| `DisableBlockAtFirstSeen` | `$false` (BAFS on) | Microsoft Security Baseline |

**GPO:** `... > Microsoft Defender Antivirus > MAPS` → *Join Microsoft MAPS = Enabled (Advanced)* dan *Send file samples when further analysis is required = Enabled (Send safe samples)*.
**Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet\SpynetReporting = 2`, `SubmitSamplesConsent = 1`.

---

## 6. PUA Protection & Sample Submission

**APA.** PUA (Potentially Unwanted Application) protection memblokir adware, bundleware, crypto-miner, dan tooling abu-abu. Sample submission mengatur seberapa banyak file dikirim ke cloud.

**KENAPA.** Banyak "hacktool" dan dropper terdeteksi sebagai PUA. Memblokir PUA menutup vektor awal yang umum dipakai pada mesin lomba/korban.

**CARA.**

```powershell
Set-MpPreference -PUAProtection Enabled   # 0=Disabled, 1=Enabled (block), 2=AuditMode
```

**Tabel `SubmitSamplesConsent`:**

| Nilai | Nama | Arti |
|-------|------|------|
| 0 | AlwaysPrompt | Tanya user tiap kali |
| 1 | SendSafeSamples | Kirim otomatis sample yang dianggap aman (rekomendasi default) |
| 2 | NeverSend | Jangan kirim (melemahkan BAFS) |
| 3 | SendAllSamples | Kirim semua otomatis (proteksi maksimal, pertimbangkan privasi) |

**GPO:** `... > Microsoft Defender Antivirus > Configure detection for potentially unwanted applications = Enabled (Block)`.
**Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\PUAProtection = 1`.

---

## 7. Update Signature & Scan

**APA.** Pembaruan definisi (signature/intelligence) dan pemindaian on-demand.

**KENAPA.** Signature usang = deteksi buta terhadap ancaman terkini. Scan terjadwal + offline scan membersihkan ancaman persisten/rootkit yang aktif saat OS berjalan.

**CARA.**

```powershell
# Update signature
Update-MpSignature                       # ambil definisi terbaru
Update-MpSignature -UpdateSource MicrosoftUpdateServer

# Scan
Start-MpScan -ScanType QuickScan
Start-MpScan -ScanType FullScan
Start-MpScan -ScanType CustomScan -ScanPath "C:\Users\Public"

# Offline scan (reboot ke lingkungan minimal untuk rootkit/persisten)
Start-MpWDOScan                          # Windows Defender Offline scan

# Ancaman & riwayat
Get-MpThreat                             # ancaman yang pernah terdeteksi
Get-MpThreatDetection                    # detail tiap deteksi (waktu, file, action)
Get-MpThreatCatalog                      # katalog ancaman yang dikenal engine
```

**Quarantine.** File berbahaya dikarantina; kelola lewat CLI `MpCmdRun.exe`:

```cmd
"%ProgramFiles%\Windows Defender\MpCmdRun.exe" -Restore -ListAll
"%ProgramFiles%\Windows Defender\MpCmdRun.exe" -Restore -Name <ThreatName>
```

**GPO (interval scan/update):** `... > Microsoft Defender Antivirus > Signature Updates` dan `> Scan`. Anchor interval & jadwal ke CIS Benchmark (mis. cek update minimal harian) — **-> lihat CIS untuk nilai pasti**.

---

## 8. Attack Surface Reduction (ASR) Rules

**APA.** ASR adalah seperangkat aturan yang memblokir teknik serangan umum (Office spawn proses, kredensial dari LSASS, script obfuscated, dll.) di tingkat behavior — independen dari signature. Tiap aturan diidentifikasi oleh **GUID** dan punya **mode**.

**Mode ASR:**

| Mode | Nilai | Arti |
|------|-------|------|
| `Disabled` / NotConfigured | 0 | Tidak aktif |
| `Enabled` / Block | 1 | Blokir (enforce) |
| `AuditMode` | 2 | Catat saja, tidak blokir (untuk uji dampak) |
| `Warn` | 6 | Tampilkan peringatan, user bisa lanjut |

**KENAPA.** ASR menutup TTP yang dipakai hampir semua intrusi (Office macro → child process, dump LSASS, PsExec/WMI lateral movement). Praktik benar: **mulai `AuditMode` → analisis log → naikkan ke `Block`** agar tidak mematahkan aplikasi sah.

**CARA (set satu aturan).**

```powershell
# Aktifkan Block credential stealing from LSASS dalam mode Block
Add-MpPreference -AttackSurfaceReductionRules_Ids 9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2 `
                 -AttackSurfaceReductionRules_Actions Enabled

# Set banyak aturan sekaligus (urutan Ids ↔ Actions harus sejajar)
Set-MpPreference `
  -AttackSurfaceReductionRules_Ids @(
    'BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550',
    'D4F940AB-401B-4EFC-AADC-AD5F3C50688A',
    '9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2') `
  -AttackSurfaceReductionRules_Actions @('Enabled','Enabled','AuditMode')

# Lihat aturan yang aktif
(Get-MpPreference).AttackSurfaceReductionRules_Ids
(Get-MpPreference).AttackSurfaceReductionRules_Actions
```

**Tabel ASR rules penting (GUID terverifikasi dari Microsoft Learn).**

| Nama aturan | GUID | MITRE terkait |
|-------------|------|---------------|
| Block credential stealing from LSASS (lsass.exe) | `9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2` | T1003.001 |
| Block all Office applications from creating child processes | `D4F940AB-401B-4EFC-AADC-AD5F3C50688A` | T1059, T1203 |
| Block executable content from email client and webmail | `BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550` | T1566.001 |
| Block Office applications from creating executable content | `3B576869-A4EC-4529-8536-B80A7769E899` | T1204.002 |
| Block Office applications from injecting code into other processes | `75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84` | T1055 |
| Block JavaScript/VBScript from launching downloaded executable content | `D3E037E1-3EB8-44C8-A917-57927947596D` | T1059.007 |
| Block execution of potentially obfuscated scripts | `5BEB7EFE-FD9A-4556-801D-275E5FFC04CC` | T1027 |
| Block Win32 API calls from Office macros | `92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B` | T1559.001 |
| Block process creations originating from PSExec and WMI commands | `D1E49AAC-8F56-4280-B9BA-993A6D77406C` | T1569.002, T1047 |
| Block untrusted and unsigned processes that run from USB | `B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4` | T1091 |
| Block Adobe Reader from creating child processes | `7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C` | T1203 |
| Block persistence through WMI event subscription | `E6DB77E5-3DF2-4CF1-B95A-636979351E5B` | T1546.003 |
| Use advanced protection against ransomware | `C1DB55AB-C21A-4637-BB3F-A12568109D35` | T1486 |
| Block executable files unless they meet prevalence/age/trusted-list | `01443614-CD74-433A-B99E-2ECDC07BFC25` | T1204 |
| Block Office communication app (Outlook) from creating child processes | `26190899-1602-49E8-8B27-EB1D0A1CE869` | T1566 |
| Block abuse of exploited vulnerable signed drivers | `56A863A9-875E-4185-98A7-B882C64B5CE5` | T1068 (BYOVD) |
| Block Webshell creation for Servers (Exchange) | `A8F5898E-1DC8-49A9-9878-85004B8A61E6` | T1505.003 |
| Block use of copied or impersonated system tools | `C0033C00-D16D-4114-A5A0-DC9B3A7D2CEB` | T1036 |
| Block rebooting machine in Safe Mode | `33DDEDF1-C6E0-47CB-833E-DE6133960387` | T1562.009 |

> **Catatan Server:** beberapa aturan (mis. *Block Webshell creation for Servers*) memang ditujukan untuk Windows Server/Exchange. *Block process creations from PsExec & WMI* dapat memengaruhi tool administrasi sah — uji di `AuditMode` dulu, terutama di DC.

**ASR exclusions (global vs per-rule).** Bila sebuah aturan ASR memblokir aplikasi sah, **jangan** matikan seluruh aturannya — pasang **exclusion** sehemat mungkin. Ada dua tingkat:

```powershell
# (a) GLOBAL — berlaku untuk SEMUA aturan ASR (paling longgar, hindari bila bisa)
Add-MpPreference -AttackSurfaceReductionOnlyExclusions "C:\LOB\app1.exe"
(Get-MpPreference).AttackSurfaceReductionOnlyExclusions          # verifikasi

# (b) PER-RULE — hanya melonggarkan SATU GUID; aturan lain tetap penuh (lebih disukai)
#     Dikonfigurasi via Intune/GPO 24H2+ ("Apply a list of exclusions to specific
#     attack surface reduction (ASR) rules"); nilai efektif dibaca dari properti:
(Get-MpPreference).AttackSurfaceReductionRules_RuleSpecificExclusions
(Get-MpPreference).AttackSurfaceReductionRules_RuleSpecificExclusions_Id
```

> **Utamakan per-rule daripada global.** Global exclusion (`-AttackSurfaceReductionOnlyExclusions`) melubangi **semua** aturan ASR sekaligus — folder yang di-exclude global menjadi zona aman untuk semua TTP yang ditutup ASR (celah T1562.001). Per-rule hanya membuka satu aturan untuk path tertentu. Catatan: bila **Disable Local Admin Merge** aktif (dikelola Intune/GPO), exclusion lokal/`Add-MpPreference` **tidak diterapkan** — exclusion wajib didorong dari sumber pengelola yang sama (Intune/GPO).

**GPO:** `... > Microsoft Defender Antivirus > Microsoft Defender Exploit Guard > Attack Surface Reduction > Configure Attack Surface Reduction rules` — isi *Value name = GUID*, *Value = 1/2/6*. Untuk exclusion: *"Exclude files and paths from Attack surface reduction rules"* (global) dan *"Apply a list of exclusions to specific attack surface reduction (ASR) rules"* (per-rule, butuh ADMX 24H2+).
**Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\<GUID> = 1`.

---

## 9. Controlled Folder Access (Anti-Ransomware)

**APA.** Controlled Folder Access (CFA) mencegah aplikasi yang tidak tepercaya memodifikasi file di folder terproteksi (Documents, Pictures, dll.) — pertahanan anti-ransomware.

**KENAPA.** Ransomware (T1486) mengenkripsi file pengguna. CFA hanya mengizinkan aplikasi tepercaya menulis ke folder terlindungi, memblokir enkripsi massal oleh proses asing.

**CARA.**

```powershell
Set-MpPreference -EnableControlledFolderAccess Enabled   # Enabled / Disabled / AuditMode

# Tambah aplikasi yang diizinkan menulis
Add-MpPreference -ControlledFolderAccessAllowedApplications "C:\Apps\backup-agent.exe"

# Tambah folder yang dilindungi (selain folder default sistem)
Add-MpPreference -ControlledFolderAccessProtectedFolders "D:\DataPenting"

# Lihat konfigurasi
Get-MpPreference | Select-Object EnableControlledFolderAccess, `
  ControlledFolderAccessAllowedApplications, ControlledFolderAccessProtectedFolders
```

> Mulai di `AuditMode` lalu naikkan ke `Enabled` setelah memetakan aplikasi sah yang memang perlu menulis (mis. agen backup, editor).

**GPO:** `... > Microsoft Defender Exploit Guard > Controlled folder access > Configure Controlled folder access = Enabled (Block)`.
**Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access\EnableControlledFolderAccess = 1`.

---

## 10. Network Protection

**APA.** Network Protection memperluas SmartScreen ke seluruh jaringan: memblokir koneksi outbound ke domain/IP berbahaya (phishing, C2, situs reputasi buruk) dari proses apa pun, bukan hanya browser.

**KENAPA.** Menutup jalur C2 (command-and-control, T1071) dan phishing tingkat jaringan. Melengkapi firewall (**-> Modul 04**) yang fokus pada port/protokol, bukan reputasi domain.

**CARA.**

```powershell
Set-MpPreference -EnableNetworkProtection Enabled   # Enabled / Disabled / AuditMode
Get-MpPreference | Select-Object EnableNetworkProtection
```

**GPO:** `... > Microsoft Defender Exploit Guard > Network Protection > Prevent users and apps from accessing dangerous websites = Enabled (Block)`.
**Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection\EnableNetworkProtection = 1`.

---

## 11. Tamper Protection

**APA.** Tamper Protection mengunci pengaturan keamanan inti Defender (RTP, cloud protection, signature update, ASR) agar **tidak dapat dimatikan** oleh malware, script, atau bahkan admin lokal lewat registry/`Set-MpPreference`.

**KENAPA.** Langkah lazim attacker setelah dapat hak admin lokal adalah `Set-MpPreference -DisableRealtimeMonitoring $true` atau menghapus registry Defender (T1562.001 *Impair Defenses*). Tamper Protection menggagalkan ini — perubahan ditolak dan dicatat.

**CARA (PENTING — tidak via GPO domain biasa).**

- **Per-device:** `Windows Security` app > *Virus & threat protection* > *Manage settings* > **Tamper Protection = On**.
- **Skala enterprise:** **Microsoft Intune** (Endpoint security > Antivirus, atau Defender for Endpoint), bukan Group Policy domain. Tamper Protection sengaja **tidak** dapat dimatikan/diatur lewat GPO `gpedit` lokal atau domain agar tidak bisa di-disable lewat jalur yang sama dengan yang dipakai attacker.
- **Verifikasi:**

```powershell
Get-MpComputerStatus | Select-Object IsTamperProtected, TamperProtectionSource
# IsTamperProtected = True ; TamperProtectionSource = Intune / Microsoft Defender for Endpoint / ...
```

> **Dampak ke `Set-MpPreference`:** ketika Tamper Protection aktif, perintah yang **melemahkan** proteksi inti (mis. mematikan RTP, cloud, atau menghapus ASR) akan diabaikan, sementara perubahan yang **memperketat** tetap berlaku. Saat lab, jika Anda perlu mengubah-ubah RTP untuk pengujian, nonaktifkan Tamper Protection sementara — lalu **aktifkan kembali**.

Registry status (read-only, jangan diandalkan untuk mengubah): `HKLM\SOFTWARE\Microsoft\Windows Defender\Features\TamperProtection`.

---

## 12. Manajemen Exclusions

**APA.** Exclusion memberitahu Defender untuk **tidak memindai** path, ekstensi, proses, atau IP tertentu.

**KENAPA (RISIKO).** Exclusion adalah **celah keamanan yang sah-secara-konfigurasi**. Attacker yang tahu/menebak folder ter-exclude akan menaruh payload di sana agar lolos scan (**T1562.001 Impair Defenses: Disable or Modify Tools**). Folder seperti `C:\Temp`, share aplikasi, atau path agen backup yang di-exclude secara malas adalah target empuk. **Prinsip: exclusion seminimal mungkin, spesifik, dan diaudit.**

**CARA (lihat & kelola).**

```powershell
# Lihat semua exclusion (path / extension / process / IP)
Get-MpPreference | Select-Object Exclusion*

# Tambah (gunakan SANGAT hemat & sespesifik mungkin)
Add-MpPreference -ExclusionPath "C:\AppX\db\data.mdf"
Add-MpPreference -ExclusionExtension "ldf"
Add-MpPreference -ExclusionProcess "C:\AppX\service.exe"

# Hapus exclusion yang tidak perlu
Remove-MpPreference -ExclusionPath "C:\Temp"
```

**Prinsip hardening exclusion:**

- Jangan exclude folder yang bisa ditulis user (`%TEMP%`, `Downloads`, share publik).
- Exclude **file/proses spesifik**, bukan folder luas atau wildcard `*`.
- **Audit berkala** daftar exclusion — bandingkan dengan baseline yang disetujui.
- Pada Server, exclusion sah biasanya untuk DB engine/role; ikuti rekomendasi resmi Microsoft per-role (mis. exclusion otomatis untuk role AD DS, DNS, DHCP sudah diterapkan Defender by default di Server 2022).

> **Untuk auditor/blue team:** exclusion yang tidak terdaftar di baseline = temuan. Atur exclusion via GPO/Intune agar tidak bisa ditambah diam-diam secara lokal, dan log perubahan via Event ID Defender (**-> Modul 06**).

---

## 13. Exploit Protection (Pengganti EMET)

**APA.** Exploit Protection adalah penerus **EMET**: mitigasi tingkat sistem & per-aplikasi (DEP, ASLR/ForceRelocateImages, CFG, SEHOP, blok Win32k system calls, validasi heap, dll.) untuk mempersulit eksploitasi memori.

**KENAPA.** Banyak eksploit (T1203) bergantung pada layout memori yang dapat diprediksi. ASLR/DEP/CFG memutus rantai eksploit bahkan saat patch belum ada.

**CARA.**

```powershell
# Lihat mitigasi efektif (sistem & per-proses)
Get-ProcessMitigation -System
Get-ProcessMitigation -Name notepad.exe

# Set mitigasi per aplikasi
Set-ProcessMitigation -Name target.exe -Enable DEP,ForceRelocateImages,CFG

# Ekspor konfigurasi ke XML (untuk distribusi via GPO)
Get-ProcessMitigation -RegistryConfigFilePath C:\exploit-protection.xml

# Impor konfigurasi XML
Set-ProcessMitigation -PolicyFilePath C:\exploit-protection.xml

# Migrasi dari EMET: konversi XML EMET lama ke format baru
ConvertTo-ProcessMitigationPolicy -EMETFilePath emet.xml -OutputFilePath ep.xml
```

- **GUI:** `Windows Security` > *App & browser control* > *Exploit protection settings*.
- **GPO:** `Computer Configuration > Administrative Templates > Windows Components > Windows Defender Exploit Guard > Exploit Protection > Use a common set of exploit protection settings` (tunjuk ke file XML hasil ekspor). Cara link GPO **-> Modul 03**.

---

## 14. SmartScreen (App & Browser Control)

**APA.** Microsoft Defender SmartScreen mengecek reputasi aplikasi/URL yang diunduh atau dijalankan dan memblokir/memperingatkan konten berbahaya atau jarang terlihat.

**KENAPA.** Memutus tahap *Initial Access*/*User Execution* (T1204) untuk download berbahaya dan phishing, sebelum file sempat dieksekusi.

**CARA.**

- **GUI:** `Windows Security` > *App & browser control* > *Reputation-based protection settings* (Check apps and files, SmartScreen for Edge, Phishing protection).
- **GPO:** `Computer Configuration > Administrative Templates > Windows Components > Windows Defender SmartScreen > Explorer > Configure Windows Defender SmartScreen = Enabled (Warn and prevent bypass)`.
- **Registry:**

```reg
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System]
"EnableSmartScreen"=dword:00000001
"ShellSmartScreenLevel"="Block"
```

Pada **Windows 11**, SmartScreen juga mencakup *Enhanced Phishing Protection* (memperingatkan saat password Windows diketik di situs/aplikasi tidak aman) — fitur ini lebih lengkap dibanding Windows 10.

---

## 15. AMSI (Antimalware Scan Interface)

**APA.** AMSI adalah antarmuka standar yang memungkinkan aplikasi (PowerShell, Windows Script Host/VBScript/JScript, Office VBA macro, .NET, WMI) mengirim konten **yang sudah ter-deobfuscate di memori** ke AV (Defender bertindak sebagai AMSI provider) untuk dipindai — termasuk script fileless yang tidak pernah menyentuh disk.

**KENAPA (sudut pandang attacker).** Karena AMSI melihat script setelah di-decode, payload PowerShell/Cobalt Strike yang di-obfuscate tetap terdeteksi. Maka attacker rutin mencoba **AMSI bypass**: mem-patch `amsi.dll!AmsiScanBuffer` di memori, manipulasi `amsiContext`/`amsiInitFailed` via reflection, atau memecah string. Inilah alasan kombinasi pertahanan berikut penting:

- ASR **Block execution of potentially obfuscated scripts** (`5BEB7EFE-FD9A-4556-801D-275E5FFC04CC`) menyulitkan obfuscation.
- **PowerShell Constrained Language Mode** + application control (WDAC/AppLocker) membatasi reflection/loading assembly (**-> Modul 03**).
- **PowerShell Script Block Logging** menangkap script yang ter-deobfuscate untuk forensik (**-> Modul 06**).
- Cloud protection + behavior monitoring menangkap pola bypass yang dikenal.

**CARA (verifikasi AMSI berfungsi).** Ketik string uji AMSI standar di PowerShell; bila Defender aktif, baris diblokir:

```powershell
# String uji resmi AMSI (analog "EICAR" untuk AMSI) — akan diblokir bila AMSI aktif
'AMSI Test Sample: 7e72c3ce-861b-4339-8740-0ac1484c1386'
```

Bila AMSI/Defender aktif, perintah di atas memunculkan error *"This script contains malicious content and has been blocked by your antivirus software"*.

---

## 16. WDAC vs AppLocker (Ringkas)

**APA.** Application control membatasi **apa yang boleh dieksekusi**, bukan mendeteksi yang jahat. Dua mekanisme Windows:

| | **WDAC** (Windows Defender Application Control) | **AppLocker** |
|---|---|---|
| Cakupan | Kernel-level, kebijakan per-device, sangat kuat | User/Group, lebih mudah dikelola |
| Bypass | Sulit (berlaku sebelum eksekusi, termasuk driver) | Lebih mudah dilewati |
| Cocok untuk | Server/Tier 0, kiosk, lockdown ketat | Lingkungan campuran, transisi |

**KENAPA.** Application control adalah pertahanan paling efektif melawan eksekusi tooling/payload tak dikenal (T1204, T1059) dan mendukung PowerShell Constrained Language Mode (memperkuat anti-AMSI-bypass).

**CARA.** Detail pembuatan kebijakan WDAC/AppLocker, signing, dan deployment via GPO **-> lihat Modul 03** (pemilik mekanisme application control). Di modul AV cukup pahami bahwa WDAC/AppLocker melengkapi Defender: AV mendeteksi yang jahat, application control memblokir yang tidak diizinkan.

---

## 17. Microsoft Defender for Endpoint (EDR)

**APA.** Microsoft Defender for Endpoint (MDE) adalah platform **EDR** (Endpoint Detection and Response) berbasis cloud: telemetri perilaku, deteksi pasca-kompromi, threat & vulnerability management, automated investigation & remediation, dan portal (Microsoft Defender / Security.microsoft.com).

**KENAPA.** AV fokus *prevention*; EDR menambah *detection & response* terhadap serangan yang sudah lolos — memberi visibility lateral movement, persistence, dan C2 yang tidak tertangkap signature.

**CARA (gambaran).**

- **Onboarding:** jalankan/deploy *onboarding package* (script `.cmd`/GPO/Intune/SCCM) yang mendaftarkan host ke tenant MDE. Verifikasi: `Get-MpComputerStatus` menampilkan `AMRunningMode` dan service `Sense` (`Get-Service Sense`) berjalan.
- **EDR in block mode:** memungkinkan EDR **melakukan remediasi** atas deteksi pasca-kompromi **meski Defender AV berstatus passive** (mis. saat AV pihak ketiga jadi primary). Tanpa ini, di mode passive Defender hanya mendeteksi tanpa memblokir.
- **Hubungan dengan AV:** ASR, Network Protection, dan cloud protection memberi sinyal yang diperkaya MDE. AV = baris depan; EDR = jaring pengaman + investigasi.

> Untuk LKS biasanya MDE penuh (berlisensi cloud) tidak tersedia; pahami konsep onboarding & EDR block mode, dan fokus hardening pada Defender AV + ASR + Tamper Protection yang dapat diuji offline.

---

## Serangan Umum & Mitigasi

| Teknik penyerang | MITRE ATT&CK | Mitigasi di modul ini |
|------------------|--------------|------------------------|
| Matikan/ubah AV (`Set-MpPreference -DisableRealtimeMonitoring $true`, hapus registry, stop service) | T1562.001 | **Tamper Protection** + kelola via GPO/Intune; audit Event ID 5001/5004/5007/5010/5012 (**-> Modul 06**) |
| Dump kredensial dari LSASS (Mimikatz, comsvcs) | T1003.001 | ASR `9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2`; Credential Guard (**-> Modul 01**) |
| Exclusion abuse — taruh payload di folder ter-exclude | T1562.001 | Exclusion minim & spesifik, audit daftar (bagian 12) |
| AMSI bypass untuk jalankan PowerShell jahat | T1562.001 / T1059.001 | AMSI + ASR obfuscated scripts + Constrained Language Mode (**-> Modul 03**) + Script Block Logging (**-> Modul 06**) |
| Fileless / injeksi proses | T1055 | Behavior monitoring + ASR Office-injection `75668C1F-...` |
| Phishing attachment → Office macro spawn proses | T1566.001 / T1204.002 | ASR `D4F940AB-...`, `BE9BA2D9-...`, `92E97FA1-...` |
| Lateral movement via PsExec/WMI | T1569.002 / T1047 | ASR `D1E49AAC-...` (uji Audit dulu di Server) |
| Ransomware enkripsi massal | T1486 | Controlled Folder Access + ASR ransomware `C1DB55AB-...` |
| C2 / unduhan dari domain jahat | T1071 / T1204 | Network Protection + SmartScreen |
| BYOVD (driver rentan untuk matikan EDR) | T1068 / T1562 | ASR `56A863A9-...` (block vulnerable signed drivers) |
| Webshell di server web/Exchange | T1505.003 | ASR `A8F5898E-...` (Block Webshell creation for Servers) |

---

## Hardening Checklist (Modul Ini)

- [ ] `Get-MpComputerStatus` → `AMRunningMode = Normal`, semua engine `*Enabled = True`
- [ ] Real-time, behavior, IOAV, script scanning aktif (`Disable* = $false`)
- [ ] Cloud protection: `MAPSReporting = Advanced`, `CloudBlockLevel = High`, `CloudExtendedTimeout = 50`
- [ ] Block at First Sight aktif (`DisableBlockAtFirstSeen = $false`)
- [ ] `SubmitSamplesConsent` mengizinkan kirim sample (SendSafeSamples/SendAllSamples)
- [ ] PUA Protection = `Enabled`
- [ ] Signature ter-update (`AntivirusSignatureLastUpdated` ≤ 24 jam)
- [ ] ASR rules inti aktif (LSASS, Office child process, email exec, obfuscated scripts, Win32 API macro, PsExec/WMI) — minimal Audit, target Block
- [ ] Controlled Folder Access = `Enabled` dengan allowed apps tepat
- [ ] Network Protection = `Enabled`
- [ ] **Tamper Protection = On** (via Windows Security app / Intune)
- [ ] Exclusion minim, spesifik, terdaftar di baseline, tidak ada folder writable-user
- [ ] Exploit Protection (DEP/ASLR/CFG) terkonfigurasi & didistribusi via GPO
- [ ] SmartScreen = `Enabled (Warn and prevent bypass)`
- [ ] Kebijakan AV dikelola GPO/Intune, bukan hanya lokal (**-> Modul 03**)
- [ ] (Jika ada) host ter-onboard MDE & EDR in block mode aktif

---

## Lab Praktik

**Prasyarat:** Windows 10/11 client atau Windows Server 2022. Jalankan PowerShell **as Administrator**. Untuk lab pengujian RTP, **nonaktifkan Tamper Protection sementara** lalu aktifkan kembali di akhir.

**Langkah 1 — Baseline status.**
Lakukan: `Get-MpComputerStatus | Select AMRunningMode,RealTimeProtectionEnabled,IsTamperProtected,AntivirusSignatureLastUpdated`
Konfirmasi dengan: `AMRunningMode = Normal` dan `RealTimeProtectionEnabled = True`.

**Langkah 2 — Update & quick scan.**
Lakukan: `Update-MpSignature; Start-MpScan -ScanType QuickScan`
Konfirmasi dengan: `Get-MpComputerStatus | Select QuickScanStartTime,QuickScanEndTime` menampilkan waktu scan terbaru.

**Langkah 3 — Uji deteksi dengan EICAR.**
Lakukan (buat file uji standar AV — Defender akan langsung mengarantina):
```powershell
$eicar = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
Set-Content -Path "$env:TEMP\eicar.com" -Value $eicar
```
Konfirmasi dengan: `Get-MpThreatDetection | Select -First 1 InitialDetectionTime,ThreatID,Resources` menampilkan deteksi EICAR (Win32/EICAR), dan file otomatis hilang/karantina.

**Langkah 4 — Aktifkan ASR mode Audit, lalu Block.**
Lakukan (Audit dulu untuk lihat dampak):
```powershell
$ids = @('D4F940AB-401B-4EFC-AADC-AD5F3C50688A','9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2','5BEB7EFE-FD9A-4556-801D-275E5FFC04CC')
$ids | ForEach-Object { Add-MpPreference -AttackSurfaceReductionRules_Ids $_ -AttackSurfaceReductionRules_Actions AuditMode }
```
Konfirmasi dengan: `(Get-MpPreference).AttackSurfaceReductionRules_Ids` dan `...Actions` menampilkan 3 GUID = `2` (Audit). Setelah memverifikasi tidak ada aplikasi sah yang terdampak (cek Event ID 1122 di log, **-> Modul 06**), naikkan ke Block:
```powershell
$ids | ForEach-Object { Add-MpPreference -AttackSurfaceReductionRules_Ids $_ -AttackSurfaceReductionRules_Actions Enabled }
```
Konfirmasi: nilai Actions berubah menjadi `1` (Block).

**Langkah 5 — Controlled Folder Access & Network Protection.**
Lakukan:
```powershell
Set-MpPreference -EnableControlledFolderAccess Enabled
Set-MpPreference -EnableNetworkProtection Enabled
```
Konfirmasi dengan: `Get-MpPreference | Select EnableControlledFolderAccess,EnableNetworkProtection` → keduanya `1` (Enabled). Uji CFA: coba tulis file dari aplikasi tak tepercaya ke `Documents` → diblokir (Event ID 1123).

**Langkah 6 — Aktifkan kembali Tamper Protection** (Windows Security app) dan verifikasi `IsTamperProtected = True`.

---

## Perintah Audit/Verifikasi

```powershell
# 1) Status engine lengkap — semua harus True; AMRunningMode = Normal
Get-MpComputerStatus | Format-List AMRunningMode, AntivirusEnabled, `
  RealTimeProtectionEnabled, BehaviorMonitorEnabled, IoavProtectionEnabled, `
  OnAccessProtectionEnabled, NISEnabled, IsTamperProtected, TamperProtectionSource, `
  AntivirusSignatureVersion, AntivirusSignatureLastUpdated
# Harapan: semua *Enabled = True, IsTamperProtected = True

# 2) Cloud protection & BAFS
Get-MpPreference | Select-Object MAPSReporting, SubmitSamplesConsent, `
  CloudBlockLevel, CloudExtendedTimeout, DisableBlockAtFirstSeen, PUAProtection
# Harapan: MAPSReporting=2(Advanced), CloudBlockLevel=High, CloudExtendedTimeout=50,
#          DisableBlockAtFirstSeen=False, PUAProtection=1

# 3) ASR rules aktif (pasangan Ids <-> Actions sejajar)
$p = Get-MpPreference
for ($i=0; $i -lt $p.AttackSurfaceReductionRules_Ids.Count; $i++) {
  '{0}  =>  {1}' -f $p.AttackSurfaceReductionRules_Ids[$i], $p.AttackSurfaceReductionRules_Actions[$i]
}
# Harapan: GUID inti bernilai 1 (Block)

# 4) CFA & Network Protection
Get-MpPreference | Select-Object EnableControlledFolderAccess, EnableNetworkProtection
# Harapan: keduanya = 1

# 5) Exclusions (audit over-exclusion) — AV exclusions + ASR exclusions
Get-MpPreference | Select-Object ExclusionPath, ExclusionExtension, ExclusionProcess, ExclusionIpAddress, `
  AttackSurfaceReductionOnlyExclusions, AttackSurfaceReductionRules_RuleSpecificExclusions
# Harapan: minim, spesifik, tidak ada folder writable-user; ASR global exclusion sebisa mungkin kosong (pakai per-rule)

# 6) Exploit Protection sistem
Get-ProcessMitigation -System | Out-String

# 7) Service EDR (jika MDE onboarded)
Get-Service Sense, WinDefend | Select-Object Name, Status, StartType
# Harapan: WinDefend Running; Sense Running bila onboarded

# 8) Riwayat ancaman
Get-MpThreat ; Get-MpThreatDetection | Select-Object -First 5 InitialDetectionTime, ThreatID
```

```cmd
:: Versi & status via MpCmdRun (alternatif tanpa PowerShell)
"%ProgramFiles%\Windows Defender\MpCmdRun.exe" -SignatureUpdate
"%ProgramFiles%\Windows Defender\MpCmdRun.exe" -Scan -ScanType 1
```

> Event ID verifikasi (Defender block/audit, perubahan konfigurasi, Tamper) ada di channel `Microsoft-Windows-Windows Defender/Operational` — daftar Event ID lengkap & cara WEF/Sysmon **-> lihat Modul 06**. Referensi cepat: ASR block `1121` / audit `1122`, CFA block `1123` / audit `1124`, Network Protection audit `1125` / block `1126`, malware terdeteksi `1116`, action diambil `1117`, konfigurasi diubah `5007`, RTP dimatikan `5001`, Tamper Protection memblokir perubahan `5013`.

---

## Panduan GUI (Langkah Klik)

> Bagian ini adalah **referensi pendamping point-and-click** untuk perintah PowerShell/GPO di atas — berguna saat tidak ada akses PowerShell, untuk verifikasi cepat per-device, atau saat menjelaskan ke operator non-CLI. **Bukan pengganti** jalur PowerShell/GPO/Intune yang sudah dibahas; di lingkungan domain, konfigurasi tetap sebaiknya didorong terpusat (GPO/Intune) agar tidak bisa diubah lokal. Setiap langkah dikaitkan ke setting yang **setara** di bagian command modul ini.

**Snap-in & app penting.**

| Snap-in / App | Cara buka | Fungsi |
|---------------|-----------|--------|
| **Windows Security** (app) | Start > ketik "Windows Security"; atau Run (Win+R) > `windowsdefender:` | Toggle per-device: Real-time/Cloud/Tamper Protection, Controlled Folder Access, Exclusions, Exploit Protection, SmartScreen, scan & update |
| **Group Policy Management** — `gpmc.msc` | Run > `gpmc.msc` (butuh RSAT/ada di DC) | Edit & link GPO **domain** untuk kebijakan Defender terpusat (ASR, Network Protection, CFA, MAPS). Cara buat & link GPO **-> Modul 03** |
| **Local Group Policy Editor** — `gpedit.msc` | Run > `gpedit.msc` | Kebijakan Defender pada **satu host lokal** (non-domain / lab) |
| **Services** — `services.msc` | Run > `services.msc` | Verifikasi status service `WinDefend` & `Sense` (read-only) |
| **Event Viewer** — `eventvwr.msc` | Run > `eventvwr.msc` | Lihat Event ID Defender (channel *Windows Defender/Operational*) — detail **-> Modul 06** |

> **Catatan path GPO — `gpmc.msc` vs `gpedit.msc`:** node **`Policies`** hanya ada di `gpmc.msc` (Group Policy Management Editor domain), jadi pathnya `Computer Configuration > Policies > Administrative Templates > ...`. Pada `gpedit.msc` lokal node `Policies` **tidak ada**, sehingga pathnya `Computer Configuration > Administrative Templates > ...` (langkah berikutnya identik). Inilah sebab modul menulis path GPO dalam dua bentuk tersebut.

---

### A. Real-time, Cloud-delivered, & Tamper Protection — Windows Security

App: **Windows Security**. Buka: Start > "Windows Security" atau Run > `windowsdefender:`.

**Toggle proteksi inti.** Path: `Virus & threat protection > Virus & threat protection settings > Manage settings`.

1. Buka Windows Security, klik **Virus & threat protection** (panel kiri).
2. Di bawah *Virus & threat protection settings*, klik **Manage settings**.
3. **Real-time protection = On** — setara `Set-MpPreference -DisableRealtimeMonitoring $false` (bagian 4).
4. **Cloud-delivered protection = On** — setara `-MAPSReporting Advanced` (bagian 5).
5. **Automatic sample submission = On** — setara `-SubmitSamplesConsent SendSafeSamples` (bagian 6).
6. **Tamper Protection = On** — setara bagian 11.

> **JUJUR (Tamper Protection):** toggle ini **hanya** ada di sini (atau via **Intune** untuk skala enterprise) — **tidak ada di GPO** `gpmc.msc`/`gpedit.msc`. Ini sengaja: agar tidak bisa dimatikan lewat jalur yang sama dengan yang dipakai attacker (lihat bagian 11).
> **JUJUR (toggle terpisah):** **Behavior monitoring** dan **IOAV protection** **tidak** punya toggle tersendiri di Windows Security — keduanya terikat pada *Real-time protection*. Untuk mengaturnya terpisah gunakan PowerShell (`-DisableBehaviorMonitoring` / `-DisableIOAVProtection`, bagian 4) atau GPO.
> **JUJUR (level cloud):** Windows Security hanya menyediakan on/off cloud. **`CloudBlockLevel`, `CloudExtendedTimeout`, dan Block at First Sight** (bagian 5) **tidak** punya kontrol di app ini — hanya via GPO (`... > Microsoft Defender Antivirus > MAPS` / `MpEngine`), PowerShell, atau Intune.

### B. Controlled Folder Access (anti-ransomware) — Windows Security

App: **Windows Security**. Path: `Virus & threat protection > Ransomware protection > Manage ransomware protection`.

1. Buka Windows Security > **Virus & threat protection**.
2. Scroll ke bagian **Ransomware protection** > klik **Manage ransomware protection**.
3. **Controlled folder access = On** — setara `Set-MpPreference -EnableControlledFolderAccess Enabled` (bagian 9).
4. Klik **Protected folders** > **Add a protected folder** untuk menambah folder (setara `-ControlledFolderAccessProtectedFolders`).
5. Klik **Allow an app through Controlled folder access** > **Add an allowed app** untuk allowlist aplikasi sah seperti agen backup (setara `-ControlledFolderAccessAllowedApplications`).

> Mulai dari pengamatan (AuditMode hanya tersedia via PowerShell/GPO; app langsung On/Off), petakan aplikasi sah dulu sebelum mengaktifkan agar tidak mematahkan tool yang menulis ke folder terproteksi.

### C. Exclusions — Windows Security

App: **Windows Security**. Path: `Virus & threat protection > Virus & threat protection settings > Manage settings > Exclusions > Add or remove exclusions`.

1. Windows Security > **Virus & threat protection** > **Manage settings**.
2. Scroll ke **Exclusions** > klik **Add or remove exclusions**.
3. Klik **Add an exclusion** > pilih **File / Folder / File type / Process** — setara `Add-MpPreference -ExclusionPath / -ExclusionExtension / -ExclusionProcess` (bagian 12).

> **Ingat prinsip bagian 12:** exclusion **seminimal mungkin, spesifik, dan diaudit**. Jangan exclude folder writable-user (`%TEMP%`, `Downloads`, share publik). Idealnya exclusion didorong via GPO/Intune agar tidak bisa ditambah diam-diam secara lokal.

### D. Exploit Protection (pengganti EMET) — Windows Security

App: **Windows Security**. Path: `App & browser control > Exploit protection settings`.

1. Windows Security > **App & browser control**.
2. Scroll ke bawah > klik **Exploit protection settings**.
3. Tab **System settings** untuk mitigasi global (DEP, Force randomization for images/ASLR, CFG, SEHOP, Validate heap integrity, dll.) atau tab **Program settings** untuk mitigasi per-aplikasi — setara `Set-ProcessMitigation` (bagian 13).
4. Untuk distribusi terpusat, gunakan **Export settings** (kanan-bawah) menghasilkan XML, lalu point GPO ke file tersebut: `... > Windows Defender Exploit Guard > Exploit Protection > Use a common set of exploit protection settings` (bagian 13).

> **JUJUR:** app ini hanya mengatur mitigasi pada host lokal + ekspor XML; deployment massal tetap lewat GPO yang menunjuk ke XML.

### E. SmartScreen (App & browser control) — Windows Security

App: **Windows Security**. Path: `App & browser control > Reputation-based protection > Reputation-based protection settings`.

1. Windows Security > **App & browser control**.
2. Klik **Reputation-based protection settings**.
3. Aktifkan **Check apps and files**, **SmartScreen for Microsoft Edge**, **Phishing protection**, dan **Potentially unwanted app blocking** — yang terakhir setara `-PUAProtection Enabled` (bagian 6); keseluruhan setara bagian 14.

### F. Update signature & Scan (on-demand) — Windows Security

App: **Windows Security** > **Virus & threat protection**.

1. **Update definisi:** di bawah *Virus & threat protection updates* klik **Protection updates** > **Check for updates** — setara `Update-MpSignature` (bagian 7).
2. **Scan:** klik **Quick scan**, atau **Scan options** > pilih *Full scan* / *Custom scan* / **Microsoft Defender Antivirus (offline) scan** — setara `Start-MpScan` / `Start-MpWDOScan` (bagian 7).
3. **Quarantine & riwayat:** klik **Protection history** untuk melihat ancaman, dan restore/remove item karantina — setara `Get-MpThreat` / `MpCmdRun.exe -Restore` (bagian 7).

### G. ASR rules, Network Protection, & CFA terpusat — `gpmc.msc` / `gpedit.msc`

Snap-in: **`gpmc.msc`** (domain) atau **`gpedit.msc`** (lokal). Buka: Run (Win+R) > `gpmc.msc`. Cara buat & link GPO **-> Modul 03**.

Path induk (Exploit Guard): `Computer Configuration > Policies > Administrative Templates > Windows Components > Microsoft Defender Antivirus > Microsoft Defender Exploit Guard` (hilangkan node `Policies` bila pakai `gpedit.msc` lokal).

**Attack Surface Reduction (ASR) rules.**

1. Buka `gpmc.msc` > edit GPO target.
2. Navigasi ke path induk di atas > **Attack Surface Reduction**.
3. Buka **Configure Attack Surface Reduction rules** > pilih **Enabled** > klik **Show...**.
4. Isi tiap baris: **Value name = GUID aturan**, **Value = `1` (Block) / `2` (Audit) / `6` (Warn)** — setara `Set-MpPreference -AttackSurfaceReductionRules_Ids/_Actions` (bagian 8; GUID lihat tabel bagian 8).

> **JUJUR:** GUI GPO hanya menerima **daftar ID + state mentah** tanpa nama aturan. Pemilihan ASR **per-GUID berdasarkan nama** jauh lebih praktis lewat **PowerShell** atau **Intune** (yang menampilkan nama aturan + dropdown state). Untuk lomba/lab, PowerShell di bagian 8 lebih cepat & minim salah-ketik GUID.

**Network Protection.** Path: `... > Microsoft Defender Exploit Guard > Network Protection > Prevent users and apps from accessing dangerous websites = Enabled (Block)` — setara `Set-MpPreference -EnableNetworkProtection Enabled` (bagian 10).

> **JUJUR:** Network Protection **tidak** punya toggle di Windows Security app per-device — pengaturannya **hanya** via GPO (di atas), PowerShell, atau Intune.

**Controlled Folder Access (alternatif terpusat).** Path: `... > Microsoft Defender Exploit Guard > Controlled folder access > Configure Controlled folder access = Enabled (Block)` — versi GPO dari toggle di bagian B / setara bagian 9.

### H. Verifikasi via GUI — Services & Event Viewer

- **`services.msc`:** cari **`WinDefend`** (*Microsoft Defender Antivirus Service*) dan **`Sense`** (*Windows Defender Advanced Threat Protection Service*, hanya bila ter-onboard MDE) — pastikan **Running**. Setara `Get-Service WinDefend, Sense` (bagian Audit/Verifikasi).
- **`eventvwr.msc`:** `Applications and Services Logs > Microsoft > Windows > Windows Defender > Operational` — lihat Event ID (mis. malware `1116`, ASR block `1121`, CFA block `1123`, RTP dimatikan `5001`, Tamper memblokir perubahan `5013`). Daftar Event ID lengkap & WEF/Sysmon **-> Modul 06**.

> **Tidak punya GUI (jujur).** **AMSI** (bagian 15) tidak punya toggle GUI mana pun — ia aktif otomatis selama Real-time protection/Defender aktif, dan hanya dapat diverifikasi via string uji di PowerShell. Begitu pula nilai cloud granular (`CloudBlockLevel`, `CloudExtendedTimeout`, Block at First Sight) dan exclusion **per-rule ASR** yang tidak punya kontrol di Windows Security app — gunakan GPO/PowerShell/Intune.

---

## Referensi

- **Microsoft Security Baseline** — Windows 11, Windows 10, dan Windows Server 2022 (Security Compliance Toolkit). Anchor untuk nilai cloud protection, BAFS, dan rekomendasi ASR.
- **CIS Microsoft Windows Server 2022 Benchmark** & **CIS Microsoft Windows 11 Enterprise Benchmark** — anchor nilai numerik (cloud block level, interval update, PUA). Lihat juga **CIS Microsoft Intune for Windows** untuk ASR/CFA.
- **Microsoft Learn — Microsoft Defender Antivirus:** *Reference table of ASR rules (GUID lengkap & terbaru)*, *Enable cloud-delivered protection*, *Block at first sight*, *Controlled folder access*, *Network protection*, *Tamper protection*, *Exploit protection reference*.
- **Microsoft Learn — Set-MpPreference / Get-MpComputerStatus** (Defender PowerShell module) untuk parameter cmdlet otoritatif.
- **MITRE ATT&CK** — T1003, T1055, T1059, T1071, T1204, T1486, T1505.003, T1562.001, T1566 untuk pemetaan teknik.
- Modul terkait: **Modul 01** (Credential Guard/PAM), **Modul 03** (GPO, WDAC/AppLocker), **Modul 04** (Firewall/Network), **Modul 06** (Logging, Event ID, Sysmon).
