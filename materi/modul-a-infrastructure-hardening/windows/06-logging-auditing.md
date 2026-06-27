# Modul 06 — Logging & Auditing

> Logging & auditing adalah "mata dan telinga" dari sistem yang sudah di-harden: tanpa jejak audit yang benar, Anda bisa memblokir serangan tetapi tidak akan pernah tahu bahwa serangan terjadi, siapa pelakunya, dan apa yang disentuh. Dari sudut pandang penyerang, log adalah bukti yang harus dihancurkan atau dimatikan — itulah sebabnya teknik seperti `Clear-EventLog`, "Indicator Removal" (T1070), dan unload Sysmon menjadi langkah baku setelah kompromi. Modul ini mengajarkan cara mengaktifkan audit yang granular, men-sentralisasi log agar tidak bisa dihapus attacker di host, dan membaca Event ID kunci untuk membuktikan apa yang sebenarnya terjadi.

## Daftar Isi

1. [Konsep & Tujuan](#1-konsep--tujuan)
2. [Arsitektur Windows Event Log](#2-arsitektur-windows-event-log)
3. [Advanced Audit Policy vs Legacy Audit Policy](#3-advanced-audit-policy-vs-legacy-audit-policy)
4. [Subkategori Audit yang Wajib Diaktifkan](#4-subkategori-audit-yang-wajib-diaktifkan)
5. [Command-line Process Auditing (Event 4688)](#5-command-line-process-auditing-event-4688)
6. [Tabel Event ID Kunci](#6-tabel-event-id-kunci)
7. [PowerShell Logging](#7-powershell-logging)
8. [Sysmon (Sysinternals)](#8-sysmon-sysinternals)
9. [Windows Event Forwarding (WEF/WEC)](#9-windows-event-forwarding-wefwec)
10. [Ukuran, Retensi & Integritas Log](#10-ukuran-retensi--integritas-log)
11. [Sinkronisasi Waktu untuk Korelasi](#11-sinkronisasi-waktu-untuk-korelasi)
12. [Serangan Umum & Mitigasi](#serangan-umum--mitigasi)
13. [Hardening Checklist (Modul Ini)](#hardening-checklist-modul-ini)
14. [Lab Praktik](#lab-praktik)
15. [Perintah Audit/Verifikasi](#perintah-auditverifikasi)
16. [Referensi](#referensi)

---

## 1. Konsep & Tujuan

Tujuan logging & auditing dalam konteks hardening Windows ada tiga lapis:

1. **Deteksi (detection)** — menghasilkan event saat aktivitas mencurigakan terjadi (logon gagal beruntun, pembuatan akun, eksekusi PowerShell ter-obfuscate, akses LSASS).
2. **Forensik (forensics)** — menyimpan jejak yang cukup detail untuk merekonstruksi rangkaian serangan setelah insiden (siapa, kapan, dari mana, command line apa yang dijalankan).
3. **Akuntabilitas (accountability)** — mengaitkan setiap aksi sensitif ke identitas yang bisa dipertanggungjawabkan, sehingga abuse oleh insider maupun akun yang dicuri bisa ditelusuri.

Tiga prinsip operasional yang membedakan logging "ada" dengan logging "berguna":

- **Granularitas** — gunakan Advanced Audit Policy (subkategori), bukan basic audit policy (kategori). Ini menghindari banjir event yang tidak bisa dibaca.
- **Integritas & sentralisasi** — log yang hanya tinggal di host adalah log yang bisa dihapus penyerang. Forward ke collector/SIEM (WEF/WEC) sehingga ada salinan di luar jangkauan host yang sudah dikompromikan.
- **Korelasi** — waktu yang sinkron (-> lihat Modul 02 untuk peran PDC emulator) dan Event ID yang dipahami artinya membuat ratusan ribu baris log menjadi narasi yang bisa dibaca.

> **Catatan pembagian materi:** Modul ini adalah pemilik **Advanced Audit Policy + daftar Event ID + PowerShell logging + Sysmon + WEF**. Mekanisme membuat & me-link GPO (LSDOU, security filtering, `gpupdate`, `gpresult`) dimiliki **Modul 03** — di sini kita hanya menyebut path GPO dan berkata "terapkan via GPO -> lihat Modul 03". Audit Kerberos/NTLM hardening dimiliki **Modul 02**; Firewall/SMB/RDP/WinRM dimiliki **Modul 04**; Defender/ASR dimiliki **Modul 05**. Setiap modul lain yang menyinggung event/audit menunjuk ke sini.

---

## 2. Arsitektur Windows Event Log

**APA.** Windows Event Log adalah layanan (`EventLog`, `wevtsvc`) yang menulis event terstruktur (XML) ke file `.evtx`. Sejak Windows Vista/Server 2008 arsitekturnya berbasis *channel*, bukan sekadar tiga log klasik.

**KENAPA.** Memahami channel mana yang menampung event apa adalah dasar dari semua deteksi. Salah channel = event "hilang" padahal sebenarnya tercatat di tempat lain.

**Channel utama (Windows Logs):**

| Channel | Isi | Contoh Event |
|---------|-----|--------------|
| `Security` | Hasil audit (logon, privilege, object access, policy change). Hanya ditulis oleh LSASS. | 4624, 4625, 4688, 1102 |
| `System` | Kernel & driver, Service Control Manager, time service. | 7045 (service installed), 7036, 104 (log cleared) |
| `Application` | Aplikasi & komponen user-mode. | Error/Warning aplikasi |
| `Setup` | Instalasi OS, update, role/feature. | Servicing |
| `ForwardedEvents` | Tujuan default event yang di-forward dari host lain (WEF). | Apa pun yang dikirim collector |

**Applications and Services Logs** — channel modular per-komponen, lokasi sumber event modern paling kaya:

| Channel | Isi |
|---------|-----|
| `Microsoft-Windows-PowerShell/Operational` | Script Block Logging (4104), pipeline (4103) |
| `Microsoft-Windows-Sysmon/Operational` | Semua event Sysmon (1, 3, 10, 22, ...) |
| `Microsoft-Windows-TaskScheduler/Operational` | Operasi scheduled task |
| `Microsoft-Windows-WinRM/Operational` | Aktivitas WinRM/remoting (-> lihat Modul 04) |
| `Microsoft-Windows-TerminalServices-*` | Sesi RDP |
| `Windows PowerShell` (classic) | 400/600 engine lifecycle (PSv2-era) |

**Lokasi `.evtx` di disk:**

```
%SystemRoot%\System32\Winevt\Logs\*.evtx
contoh: C:\Windows\System32\Winevt\Logs\Security.evtx
        C:\Windows\System32\Winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx
```

> Catatan: tanda `/` pada nama channel ditulis sebagai `%4` di nama file (`Microsoft-Windows-PowerShell%4Operational.evtx`).

**Dua alat utama:**

```powershell
# Enumerasi semua channel & status
wevtutil el                                  # enumerate logs (cmd/PS)
Get-WinEvent -ListLog * | Where-Object IsEnabled

# Lihat konfigurasi sebuah channel (ukuran, retensi)
wevtutil gl Security                         # get-log config
Get-WinEvent -ListLog Security | Format-List *

# Baca event terbaru
Get-WinEvent -LogName Security -MaxEvents 20
wevtutil qe Security /c:5 /rd:true /f:text   # query, 5 terbaru, format text
```

`Get-WinEvent` adalah cmdlet modern (mendukung semua channel + `-FilterHashtable` yang cepat). `Get-EventLog` adalah cmdlet lama yang **hanya** membaca classic logs (Security/System/Application) dan tidak mendukung Applications and Services Logs — hindari untuk deteksi modern.

---

## 3. Advanced Audit Policy vs Legacy Audit Policy

**APA.** Windows punya dua "lapisan" konfigurasi audit:

- **Legacy/basic audit policy** — 9 kategori kasar (Local Policies > Audit Policy), mis. "Audit account logon events".
- **Advanced Audit Policy Configuration** — 10 kategori dipecah menjadi ~60 *subkategori* granular, mis. memisahkan "Credential Validation" dari "Kerberos Authentication Service".

**KENAPA.** Subkategori memungkinkan Anda mengaktifkan persis event yang berguna tanpa membanjiri Security log dengan noise. Jika basic dan advanced diset bersamaan, hasilnya konflik tak terduga. Solusinya: **paksa sistem hanya menghormati subkategori** lewat opsi `SCENoApplyLegacyAuditPolicy`.

**CARA.**

Aktifkan paksaan subkategori (wajib lebih dulu):

- **GPO path:** `Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options > "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings"` → **Enabled**
- **Registry:**

```reg
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa]
"SCENoApplyLegacyAuditPolicy"=dword:00000001
```

Konfigurasikan subkategori (terapkan via GPO -> lihat Modul 03):

- **GPO path:** `Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Audit Policies > [kategori]`

Inspeksi & set runtime dengan `auditpol` (berguna untuk verifikasi cepat, tetapi setting via GPO yang persisten — `auditpol` lokal akan ditimpa GPO saat refresh):

```cmd
:: Lihat seluruh kebijakan audit efektif
auditpol /get /category:*

:: Lihat satu subkategori
auditpol /get /subcategory:"Process Creation"

:: Set satu subkategori (lokal, untuk testing)
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable

:: Backup & restore kebijakan audit ke CSV (berguna untuk baseline)
auditpol /backup /file:C:\auditpol-baseline.csv
auditpol /restore /file:C:\auditpol-baseline.csv
```

> **Penting:** GPO menyimpan kebijakan advanced audit di file `audit.csv` yang didorong ke `%SystemRoot%\System32\GroupPolicy\Machine\Microsoft\Windows NT\Audit\audit.csv`. Jangan mengedit di GUI `Local Security Policy` bila Anda memakai Advanced Audit Policy lewat GPO domain — gunakan GPO agar konsisten dan auditable.

---

## 4. Subkategori Audit yang Wajib Diaktifkan

**APA & KENAPA.** Tabel berikut adalah rekomendasi minimum yang diselaraskan dengan **Microsoft Security Baseline (Windows Server 2022 / Windows 11)** dan **CIS Microsoft Windows Benchmark** sebagai rujukan tunggal angka/setting. Kolom S/F = Success/Failure yang harus diaktifkan. Beberapa baris hanya relevan di **Domain Controller** (ditandai *DC*).

> Sumber nilai: Microsoft Security Compliance Toolkit (security baseline) + CIS Benchmark seksi *Advanced Audit Policy Configuration*. Bila ada selisih kecil antar versi baseline, gunakan baseline yang sedang dipakai juri/lomba sebagai acuan dan dokumentasikan.

| Kategori | Subkategori | Rekomendasi | Mengapa penting |
|----------|-------------|-------------|-----------------|
| **Account Logon** | Credential Validation | Success + Failure | NTLM validation (4776) — deteksi password spraying |
| Account Logon | Kerberos Authentication Service *DC* | Success + Failure | TGT request (4768/4771) — AS-REP roasting, brute force |
| Account Logon | Kerberos Service Ticket Operations *DC* | Success + Failure | TGS request (4769) — Kerberoasting |
| **Account Management** | User Account Management | Success + Failure | 4720/4722/4723/4724/4725/4726/4738 |
| Account Management | Security Group Management | Success + Failure | 4728/4732/4756 — privilege escalation via grup |
| Account Management | Computer Account Management | Success (+ Failure di DC) | 4741 — pembuatan komputer (mis. abuse MachineAccountQuota) |
| Account Management | Other Account Management Events | Success + Failure | perubahan kebijakan akun |
| **Detailed Tracking** | Process Creation | Success | 4688 + command line — inti deteksi eksekusi |
| Detailed Tracking | Process Termination | Success (opsional) | korelasi durasi proses |
| Detailed Tracking | PNP Activity | Success | 6416 — perangkat USB/PnP terhubung |
| **Logon/Logoff** | Logon | Success + Failure | 4624/4625 — inti deteksi akses |
| Logon/Logoff | Logoff | Success | 4634/4647 |
| Logon/Logoff | Special Logon | Success | 4672/4964 — logon dengan privilege tinggi/grup khusus |
| Logon/Logoff | Account Lockout | Success (+ Failure) | 4740 — lockout akibat brute force |
| Logon/Logoff | Other Logon/Logoff Events | Success + Failure | RDP reconnect, dll. |
| Logon/Logoff | Group Membership | Success | 4627 — grup yang dibawa token saat logon |
| **Policy Change** | Audit Policy Change | Success + Failure | 4719 — attacker mematikan audit |
| Policy Change | Authentication Policy Change | Success | perubahan trust/Kerberos policy |
| Policy Change | MPSSVC Rule-Level Policy Change | Success + Failure | perubahan rule firewall (-> lihat Modul 04) |
| **Privilege Use** | Sensitive Privilege Use | Success + Failure | 4673/4674 — pemakaian privilege sensitif spt SeDebugPrivilege (4672 ada di Special Logon) |
| **DS Access** *DC* | Directory Service Access | Success + Failure | 4662 — operasi objek AD (indikator DCSync) |
| DS Access *DC* | Directory Service Changes | Success + Failure | 5136/5137/5141 — perubahan objek AD |
| **Object Access** | File Share | Success + Failure | 5140 — akses share jaringan |
| Object Access | Detailed File Share | Failure (Success opsional) | 5145 — akses file granular dalam share |
| Object Access | Removable Storage | Success + Failure | 4663 ke media removable — exfil USB |
| Object Access | Other Object Access Events | Success + Failure | 4698/4699 — scheduled task |
| **System** | Security State Change | Success | 4608/4616 — boot, perubahan waktu |
| System | Security System Extension | Success + Failure | 4697 — driver/service security |
| System | System Integrity | Success + Failure | tamper pada subsistem audit |

> **Object Access via SACL.** Subkategori Object Access **tidak** otomatis mengaudit file/registry tertentu. Anda harus memasang **SACL (System Access Control List)** pada objek yang ingin dipantau (klik kanan file/folder/registry key > `Properties > Security > Advanced > Auditing > Add`). Tanpa SACL, subkategori "File System"/"Registry" aktif tetapi tidak menghasilkan event (4663). Contoh berguna: pasang SACL "Read" pada atribut LAPS password untuk mendeteksi siapa membaca kredensial — -> lihat Modul 01 untuk LAPS.

---

## 5. Command-line Process Auditing (Event 4688)

**APA.** Secara default, Event 4688 (process creation) hanya mencatat nama executable. Mengaktifkan "Include command line in process creation events" menambahkan **argumen command line lengkap** ke event.

**KENAPA.** Tanpa command line, `powershell.exe` hanya terlihat sebagai "powershell.exe". Dengan command line, Anda melihat `powershell.exe -nop -w hidden -enc <base64>` — perbedaan antara buta dan melihat serangan. Ini salah satu setting deteksi dengan rasio nilai/usaha tertinggi.

**CARA.**

Aktifkan dua hal sekaligus:

1. **Audit Process Creation = Success** (lihat tabel §4).
2. **Include command line:**
   - **GPO path:** `Computer Configuration > Policies > Administrative Templates > System > Audit Process Creation > "Include command line in process creation events"` → **Enabled**
   - **Registry:**

```reg
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit]
"ProcessCreationIncludeCmdLine_Enabled"=dword:00000001
```

```powershell
# Verifikasi command line muncul di 4688
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -MaxEvents 5 |
  ForEach-Object { ($_ | Select-Object -ExpandProperty Message) }
```

> **Pertimbangan keamanan:** command line bisa berisi password yang diketik di CLI (mis. `net use ... /user:admin Passw0rd`). Itu menjadikan command line sensitif. Karena 4688 ada di Security log yang biasanya hanya bisa dibaca admin, risiko ini umumnya dapat diterima dan dianjurkan baseline — tetapi pastikan akses ke Security log/SIEM dikontrol ketat. Sysmon Event 1 juga merekam command line (lihat §8).

---

## 6. Tabel Event ID Kunci

**APA & KENAPA.** Hafal artinya, bukan hanya nomornya. Tabel ini adalah "kamus" yang dipakai saat lomba untuk membuktikan apa yang terjadi. Channel ditandai bila bukan `Security`.

| Event ID | Channel | Arti |
|----------|---------|------|
| **4624** | Security | An account was **successfully logged on** (cek Logon Type) |
| **4625** | Security | An account **failed to log on** (cek Status/Sub Status untuk alasan) |
| **4634** | Security | An account was **logged off** |
| **4647** | Security | **User initiated logoff** (interactive logoff) |
| **4648** | Security | Logon attempted using **explicit credentials** (runas/lateral movement) |
| **4672** | Security | **Special privileges** assigned to new logon (admin-equivalent) |
| **4964** | Security | **Special groups** have been assigned to a new logon |
| **4720** | Security | A user account was **created** |
| **4722** | Security | A user account was **enabled** |
| **4725** | Security | A user account was **disabled** |
| **4723** | Security | Attempt to **change** an account's password (oleh user sendiri) |
| **4724** | Security | Attempt to **reset** an account's password (oleh admin/other) |
| **4726** | Security | A user account was **deleted** |
| **4738** | Security | A user account was **changed** |
| **4740** | Security | A user account was **locked out** |
| **4767** | Security | A user account was **unlocked** |
| **4728** | Security | Member added to **security-enabled global group** |
| **4732** | Security | Member added to **security-enabled local group** |
| **4756** | Security | Member added to **security-enabled universal group** |
| **4768** | Security | A Kerberos **TGT (authentication ticket)** was requested (AS-REP roasting bila pre-auth tidak diperlukan, enc RC4 0x17) |
| **4769** | Security | A Kerberos **service ticket** was requested (Kerberoasting bila RC4) |
| **4771** | Security | Kerberos **pre-authentication failed** (brute force / password spraying) |
| **4776** | Security | DC attempted to **validate credentials** (NTLM) |
| **4688** | Security | A new **process** has been created (+ command line bila diaktifkan) |
| **4697** | Security | A **service was installed** in the system (sumber: Security log) |
| **7045** | System | A **service was installed** (sumber: Service Control Manager) |
| **4698** | Security | A **scheduled task was created** |
| **4699** | Security | A **scheduled task was deleted** |
| **4719** | Security | **System audit policy was changed** (attacker mematikan audit) |
| **1102** | Security | The **audit log was cleared** |
| **104** | System | The **System/Application log was cleared** |
| **4662** | Security | An **operation was performed on an AD object** (indikator DCSync — lihat catatan) |
| **5140** | Security | A **network share** object was accessed |
| **5145** | Security | A network share object was **checked for access** (detailed file share) |

**Catatan korelasi penting:**

- **4624/4625 Logon Type (field `LogonType`)** — wajib dihafal; ia membedakan "logon" mana yang Anda lihat. Tabel lengkap:

  | Type | Nama | Arti / kapan muncul | Sinyal keamanan |
  |------|------|---------------------|-----------------|
  | **2** | Interactive | Logon di konsol/keyboard fisik atau lewat KVM | Logon admin interaktif di server = mencurigakan |
  | **3** | Network | Akses sumber daya jaringan (SMB share, `net use`, akses RPC) | Inti lateral movement; Pass-the-Hash muncul sebagai Type 3 |
  | **4** | Batch | Scheduled task berjalan dengan kredensial tersimpan | Task persistence (T1053) |
  | **5** | Service | Service dimulai oleh SCM dengan akun service | Service baru mencurigakan ↔ korelasi 7045 |
  | **7** | Unlock | Workstation di-unlock dari screen lock | — |
  | **8** | NetworkCleartext | Kredensial dikirim **cleartext** lewat jaringan (IIS Basic auth, beberapa PsExec) | Kredensial polos di kabel — selidiki |
  | **9** | NewCredentials | `runas /netonly` — proses memakai kredensial alternatif untuk koneksi jaringan saja | Indikator **overpass-the-hash / token manipulation** |
  | **10** | RemoteInteractive | **RDP** / Terminal Services / Remote Assistance | Akses RDP — korelasi dengan §2 channel TerminalServices |
  | **11** | CachedInteractive | Logon interaktif memakai **cached domain credentials** (DC tak terjangkau) | Laptop offline; juga muncul saat DC sengaja diisolasi |

  > Type **9 (NewCredentials)** dan Type **3** dari akun bernilai tinggi adalah dua sinyal Pass-the-Hash/overpass yang paling sering dipakai saat hunting.

- **4625 Sub Status (alasan gagal):** `0xC000006A` = password salah, `0xC0000064` = user tidak ada, `0xC0000234` = akun terkunci, `0xC0000072` = akun disabled, `0xC0000071` = password expired, `0xC0000133` = clock skew (waktu tidak sinkron). Banjir 4625 dengan **banyak username berbeda** dari satu sumber = **password spraying**; banyak kegagalan pada **satu** akun = brute force klasik.
- **4662 DCSync:** event 4662 dengan `Properties` mengandung GUID replikasi berikut adalah indikator **DCSync (T1003.006)** bila berasal dari prinsipal yang bukan DC:
  - `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` — DS-Replication-Get-Changes
  - `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` — DS-Replication-Get-Changes-All
  - `89e95b76-444d-4c62-991a-0facbeda640c` — DS-Replication-Get-Changes-In-Filtered-Set
- **4769 Kerberoasting:** service ticket request dengan `Ticket Encryption Type = 0x17` (RC4) untuk banyak SPN = indikasi Kerberoasting. Hardening RC4/Kerberos -> lihat Modul 02.
- **4768/4769 keduanya hanya muncul di DC** karena KDC ada di DC.

> **Verifikasi ID privilege & device:** 4673 = *A privileged service was called*, 4674 = *An operation was attempted on a privileged object* (subkategori Sensitive Privilege Use). 4741 = *A computer account was created* (Computer Account Management). 6416 = *A new external device was recognized by the System* (PNP Activity). Keempatnya sudah dikonfirmasi sesuai dokumentasi Microsoft.

---

## 7. PowerShell Logging

**APA.** PowerShell adalah alat favorit attacker (living-off-the-land). Tiga mekanisme logging melengkapi satu sama lain:

| Mekanisme | Event ID | Channel | Isi |
|-----------|----------|---------|-----|
| **Module Logging** | 4103 | `Microsoft-Windows-PowerShell/Operational` | Detail eksekusi pipeline per-modul (parameter binding) |
| **Script Block Logging** | 4104 | `Microsoft-Windows-PowerShell/Operational` | Teks script block yang dikompilasi — termasuk yang ter-deobfuscate |
| **Transcription** | — (file) | folder transcript | Transkrip input/output sesi seperti `Start-Transcript` |

**KENAPA.** **Script Block Logging (4104)** sangat kuat karena PowerShell mencatat script **setelah** de-obfuscation: command yang dikirim sebagai Base64/`-EncodedCommand` atau di-`Invoke-Expression` tetap muncul dalam bentuk plaintext di 4104. Inilah cara mendeteksi payload yang sengaja dikaburkan. Module Logging (4103) menambah konteks parameter; Transcription memberi rekaman lengkap untuk forensik.

**CARA (terapkan via GPO -> lihat Modul 03):**

- **GPO path:** `Computer Configuration > Policies > Administrative Templates > Windows Components > Windows PowerShell`
  - "Turn on Module Logging" → Enabled, Module Names = `*`
  - "Turn on PowerShell Script Block Logging" → Enabled (opsional: centang "Log script block invocation start/stop" = 4105/4106, lebih berisik)
  - "Turn on PowerShell Transcription" → Enabled, set "Transcript output directory" ke share write-only yang aman, centang "Include invocation headers"

- **Registry ekuivalen:**

```reg
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging]
"EnableScriptBlockLogging"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging]
"EnableModuleLogging"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription]
"EnableTranscripting"=dword:00000001
"EnableInvocationHeader"=dword:00000001
"OutputDirectory"="\\\\logserver\\PSTranscripts$"
```

Untuk Module Logging, nama modul `*` disimpan di subkey `ModuleLogging\ModuleNames` dengan value `*`=`*`.

```powershell
# Lihat Script Block Logging yang sudah tercatat
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} -MaxEvents 10 |
  Select-Object TimeCreated, @{n='Script';e={$_.Properties[2].Value}}
```

> **Bypass yang harus ditutup:** Script Block Logging hanya berlaku untuk **PowerShell v3+**. Attacker sering menjalankan `powershell.exe -version 2` untuk turun ke **PSv2** yang tidak punya 4104/AMSI. Hilangkan engine PSv2 (disable fitur "Windows PowerShell 2.0 Engine") -> lihat Modul 04. Tanpa itu, semua logging PowerShell Anda bisa di-bypass dengan satu flag.

---

## 8. Sysmon (Sysinternals)

**APA.** System Monitor (Sysmon) adalah driver + service dari Sysinternals yang mencatat aktivitas sistem dengan detail jauh melampaui audit bawaan Windows, ke channel `Microsoft-Windows-Sysmon/Operational`.

**KENAPA melampaui audit default.** Audit bawaan tidak memberi: **hash** proses, **parent process** yang konsisten, koneksi jaringan per-proses, **image/DLL load**, **CreateRemoteThread**, dan terutama **ProcessAccess ke LSASS** (indikator credential dumping). Sysmon mengisi celah ini dan output-nya mudah diteruskan ke WEF/SIEM.

**Event ID Sysmon penting:**

| Event ID | Arti | Nilai deteksi |
|----------|------|---------------|
| **1** | Process create | command line + hash + parent + user — inti deteksi eksekusi |
| **3** | Network connection | koneksi per-proses (C2, exfil) |
| **6** | Driver loaded | driver kernel dimuat + hash + status tanda tangan — deteksi **BYOVD** (Bring Your Own Vulnerable Driver, T1068/T1562) & rootkit driver |
| **7** | Image loaded (DLL) | deteksi DLL injection / unsigned module |
| **8** | CreateRemoteThread | injeksi ke proses lain |
| **10** | Process access | akses ke `lsass.exe` = indikator **credential dumping (T1003.001)** |
| **11** | File create | dropper menulis payload |
| **12/13/14** | Registry create-delete / value set / rename | persistence via Run keys, dll. |
| **22** | DNS query | resolusi domain mencurigakan (DGA, C2) |
| **23** | File delete (archived) | indicator removal / penghapusan bukti |

**CARA — instal & maintain config:**

Gunakan config komunitas yang sudah matang, jangan default kosong. Dua yang umum dipakai:
- **SwiftOnSecurity `sysmon-config`** — baseline well-commented, cocok untuk belajar.
- **Olaf Hartong `sysmon-modular`** — modular, dipetakan ke teknik MITRE ATT&CK.

```cmd
:: Instal pertama kali (accept EULA + apply config)
sysmon64.exe -accepteula -i sysmonconfig.xml

:: Update/ganti config tanpa reinstall
sysmon64.exe -c sysmonconfig.xml

:: Lihat skema/konfigurasi efektif saat ini
sysmon64.exe -c

:: Uninstall (driver + service)
sysmon64.exe -u force
```

```powershell
# Konfirmasi service & channel aktif
Get-Service Sysmon64                                   # Status = Running
Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational" | Select RecordCount, IsEnabled

# Cari akses LSASS (credential dumping)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=10} |
  Where-Object { $_.Message -match 'lsass\.exe' } | Select-Object -First 5 TimeCreated, Message

# Cari driver dimuat yang TIDAK ditandatangani (kandidat BYOVD) — Event 6
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=6} |
  Where-Object { $_.Message -match 'Signed:\s*false' } | Select-Object -First 5 TimeCreated, Message
```

> Nama service & binary bergantung arsitektur: `sysmon.exe` membuat service `Sysmon` (x86), sedangkan `sysmon64.exe` membuat service `Sysmon64` (x64); drivernya bernama `SysmonDrv`. Di Windows Server 2022 (x64) gunakan `sysmon64.exe` dan service `Sysmon64`. Jadikan instalasi + config Sysmon bagian dari image/baseline, dan lindungi dengan ACL agar service tidak mudah di-stop oleh non-admin.

---

## 9. Windows Event Forwarding (WEF/WEC)

**APA.** WEF mengirim event dari banyak host (sources) ke satu **Windows Event Collector (WEC)**. Event tiba di channel `ForwardedEvents` collector (atau custom channel). Transport memakai WinRM (HTTP 5985 / HTTPS 5986).

**KENAPA — ini kontrol integritas, bukan sekadar kenyamanan.** Jika attacker meng-compromise sebuah host, ia bisa `Clear-EventLog`/`wevtutil cl` untuk menghapus jejak (Event 1102). Tetapi salinan yang sudah ter-forward ke collector berada **di luar jangkauannya**. Forwarding + alert pada 1102/4719 adalah mitigasi inti terhadap anti-forensik. Sentralisasi juga menyederhanakan korelasi dan menjadi feed alami ke SIEM.

**Dua mode subscription:**

| Mode | Inisiator | Kapan dipakai |
|------|-----------|---------------|
| **Source-initiated** (push) | Source mendaftar ke collector | Skala besar, domain — sources didorong via GPO, mudah ditambah |
| **Collector-initiated** (pull) | Collector menghubungi sources | Jumlah host kecil & tetap, kontrol terpusat |

**CARA — sisi Collector:**

```cmd
:: 1. Aktifkan & quick-config Windows Event Collector service (Wecsvc)
wecutil qc /q

:: 2. Buat subscription dari file XML
wecutil cs subscription.xml

:: 3. Status runtime subscription (lihat host yang aktif lapor)
wecutil gr <SubscriptionId>

:: 4. List/hapus subscription
wecutil es
wecutil ds <SubscriptionId>
```

**Contoh `subscription.xml` minimal (source-initiated) yang siap dipakai `wecutil cs`:**

```xml
<Subscription xmlns="http://schemas.microsoft.com/2006/03/windows/events/subscription">
    <SubscriptionId>SecurityLogs</SubscriptionId>
    <SubscriptionType>SourceInitiated</SubscriptionType>
    <Description>Forward Security log dari semua member domain</Description>
    <Enabled>true</Enabled>
    <Uri>http://schemas.microsoft.com/wbem/wsman/1/windows/EventLog</Uri>
    <ConfigurationMode>Normal</ConfigurationMode>
    <Query>
        <![CDATA[
            <QueryList>
                <Query Id="0" Path="Security">
                    <Select Path="Security">*[System[(EventID=4624 or EventID=4625 or EventID=4688 or EventID=4720 or EventID=4732 or EventID=1102 or EventID=4719)]]</Select>
                </Query>
            </QueryList>
        ]]>
    </Query>
    <ReadExistingEvents>true</ReadExistingEvents>
    <TransportName>HTTP</TransportName>
    <ContentFormat>RenderedText</ContentFormat>
    <Locale Language="en-US"/>
    <LogFile>ForwardedEvents</LogFile>
    <AllowedSourceNonDomainComputers></AllowedSourceNonDomainComputers>
    <AllowedSourceDomainComputers>O:NSG:NSD:(A;;GA;;;DC)(A;;GA;;;NS)</AllowedSourceDomainComputers>
</Subscription>
```

Penjelasan field kunci:

- `SubscriptionType = SourceInitiated` → mode **push**; daftar source datang dari GPO "Configure target Subscription Manager", bukan ditulis di sini.
- `Query` → ambil hanya event bernilai tinggi dari channel `Security` (filter XPath: logon, proses, pembuatan akun, penambahan grup, **1102** log-cleared, **4719** audit-policy-changed). Untuk seluruh channel cukup `<Select Path="Security">*</Select>`.
- `AllowedSourceDomainComputers` → **SDDL** yang menentukan siapa boleh mengirim. `O:NSG:NSD:(A;;GA;;;DC)(A;;GA;;;NS)` memberi `GenericAll` ke alias **`DC` = Domain Computers** dan **`NS` = NETWORK SERVICE** — pola standar agar semua mesin domain bisa lapor. Persempit dengan SID grup khusus bila hanya OU tertentu yang boleh.
- `ContentFormat = RenderedText` → event tiba sudah ter-render (mudah dibaca); pakai `Events` (raw) bila diteruskan ke SIEM yang mem-parse XML sendiri.
- `Locale Language` → bahasa string yang dirender; samakan dengan locale collector.

> Buat dengan `wecutil cs subscription.xml`, lalu cek host yang sudah lapor: `wecutil gr SecurityLogs`. Bila tak ada source muncul, periksa GPO Subscription Manager di source dan keanggotaan `NT AUTHORITY\NETWORK SERVICE` di `Event Log Readers` (untuk membaca Security log).

**CARA — sisi Source (push/source-initiated), terapkan via GPO -> lihat Modul 03:**

- Aktifkan WinRM di source (-> lihat Modul 04 untuk hardening WinRM):

```cmd
winrm quickconfig
```

- **GPO path:** `Computer Configuration > Policies > Administrative Templates > Windows Components > Event Forwarding > "Configure target Subscription Manager"` → Enabled, value:

```
Server=http://WEC01.lab.local:5985/wsman/SubscriptionManager/WEC,Refresh=60
```

- Tambahkan akun mesin source (atau `Network Service`) ke grup yang punya akses baca log; untuk source-initiated, source membaca log sebagai `NETWORK SERVICE`, jadi tambahkan `NT AUTHORITY\NETWORK SERVICE` ke `Event Log Readers` bila perlu membaca Security log.

> Untuk lomba dengan 1 DC + beberapa klien, source-initiated via GPO adalah pola paling realistis: link satu GPO "WEF-Sources" ke OU klien, dan event mulai mengalir ke `ForwardedEvents` di collector. Pertimbangkan mengarahkan collector ke SIEM/Sentinel sebagai langkah lanjut.

---

## 10. Ukuran, Retensi & Integritas Log

**APA.** Setiap channel punya **maximum log size** dan **retention method**. Default kecil (mis. Security ~20 MB) sehingga di lingkungan sibuk event lama tertimpa dalam hitungan jam — bukti hilang sebelum sempat dibaca.

**KENAPA.** Security log yang terlalu kecil = anti-forensik gratis untuk attacker (cukup hasilkan banyak noise agar event jahat tergulir keluar). Naikkan ukuran, dan **utamakan forwarding** ke collector/SIEM sebagai sumber kebenaran jangka panjang.

**Rekomendasi ukuran (anchor: CIS Microsoft Windows Benchmark, seksi *Event Log Service*):**

| Channel | Max size (CIS minimum) |
|---------|------------------------|
| Application | ≥ 32,768 KB (32 MB) |
| Security | ≥ 196,608 KB (192 MB) |
| System | ≥ 32,768 KB (32 MB) |
| Setup | ≥ 32,768 KB (32 MB) |

> Sumber: CIS Benchmark "Specify the maximum log file size (KB)". Microsoft Security Baseline juga menaikkan Security log secara signifikan. Di production, ukuran Security sering dinaikkan jauh lebih besar (mis. 1–4 GB) bila tidak ada WEF; bila ada WEF/SIEM, ukuran lokal cukup sebagai buffer. Jangan mengarang angka — gunakan minimum CIS sebagai lantai dan dokumentasikan bila menaikkannya.

**Retention method.** CIS L1 menyarankan "Control Event Log behavior when the log file reaches its maximum size" = **Disabled**, artinya **overwrite events as needed (oldest first)** sambil mengandalkan WEF/SIEM untuk retensi. Jangan set ke "Do not overwrite (clear manually)" pada Security tanpa monitoring kapasitas — log penuh bisa menghentikan sistem bila `CrashOnAuditFail` aktif.

**CARA.**

- **GPO path:** `Computer Configuration > Policies > Administrative Templates > Windows Components > Event Log Service > Security > "Specify the maximum log file size (KB)"`
- **Registry:**

```reg
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security]
"MaxSize"=dword:0c000000
```

> `0x0C000000` = 201,326,592 byte = 196,608 KB.

```cmd
:: Set ukuran & retensi via wevtutil (lokal)
wevtutil sl Security /ms:201326592 /rt:false /ab:false
```
`/rt:false` = overwrite as needed; `/rt:true` = retain (do not overwrite); `/ab` = auto-backup saat penuh.

```powershell
# Verifikasi ukuran efektif
Get-WinEvent -ListLog Security | Select-Object LogName, MaximumSizeInBytes, LogMode, RecordCount
```

**Integritas.** Batasi siapa yang bisa membaca/menghapus log (Security log hanya admin + `Event Log Readers`), forward off-host, dan alert pada penghapusan log (1102) & perubahan audit (4719) — lihat §12.

---

## 11. Sinkronisasi Waktu untuk Korelasi

**APA & KENAPA.** Korelasi lintas host hanya berfungsi bila jam mereka sinkron. Selisih beberapa detik saja membuat rangkaian serangan lintas mesin mustahil disusun, dan Kerberos sendiri menolak tiket bila skew > 5 menit (default). Dalam domain, **PDC emulator** adalah sumber waktu otoritatif yang harus disinkronkan ke sumber eksternal (NTP) — detail peran PDC -> lihat Modul 02.

**CARA — verifikasi cepat:**

```cmd
:: Konfigurasi & sumber waktu host
w32tm /query /configuration
w32tm /query /source
w32tm /query /status

:: Cek offset terhadap PDC/sumber
w32tm /stripchart /computer:DC01.lab.local /samples:3 /dataonly
```

Pastikan semua member mengambil waktu dari hierarki domain (`Type = NT5DS`) dan PDC dari NTP eksternal yang tepercaya.

---

## Serangan Umum & Mitigasi

| Teknik penyerang | MITRE ATT&CK | Jejak/Event | Mitigasi (modul ini) |
|------------------|--------------|-------------|----------------------|
| Clear Windows Event Logs | **T1070.001** | Security **1102**, System **104** | Forward off-host (WEF, §9); alert real-time pada 1102; batasi hak hapus log |
| Mematikan/mengubah audit policy | **T1562.001** (Impair Defenses) | **4719** (audit policy changed) | Alert pada 4719; kunci kebijakan via GPO (di-reapply tiap refresh -> Modul 03) |
| Disable/unload Sysmon | **T1562.001** | Sysmon **4** (state changed), service stop | ACL pada service, alert pada Sysmon Event 4 & hilangnya heartbeat di collector |
| PowerShell ter-obfuscate / encoded | **T1059.001** | PS **4104** (deobfuscated), 4103 | Script Block Logging (§7) + hapus PSv2 (-> Modul 04) |
| Downgrade ke PSv2 untuk bypass logging/AMSI | **T1059.001 / T1562.001** | absennya 4104 saat `-version 2` | Disable Windows PowerShell 2.0 Engine -> Modul 04 |
| Credential dumping dari LSASS | **T1003.001** | Sysmon **10** (access ke lsass.exe), 4688 tool dumping | Sysmon Event 10; Credential Guard -> Modul 01; Defender -> Modul 05 |
| DCSync (replikasi kredensial) | **T1003.006** | **4662** dengan GUID DS-Replication-Get-Changes(-All) | Audit DS Access (§4); alert pola 4662 dari non-DC |
| Kerberoasting | **T1558.003** | **4769** RC4 (0x17) untuk banyak SPN | Audit Kerberos Service Ticket Ops; hardening RC4 -> Modul 02 |
| AS-REP roasting / Kerberos brute force | **T1558.004 / T1110** | **4768 / 4771** gagal beruntun | Audit Kerberos Auth Service; lockout -> Modul 02 |
| Password spraying (NTLM) | **T1110.003** | **4625 / 4776** banyak user dari satu sumber | Audit Credential Validation; korelasi 4625 di SIEM |
| Persistence via service/scheduled task | **T1543.003 / T1053.005** | **7045 / 4697**, **4698/4699** | Audit Security System Extension + Object Access |
| Exfil via removable media | **T1052.001** | **4663** ke removable, PnP **6416** | Audit Removable Storage + PNP Activity (§4) |

---

## Hardening Checklist (Modul Ini)

- [ ] `SCENoApplyLegacyAuditPolicy` = Enabled (force subcategory) via GPO.
- [ ] Advanced Audit Policy subkategori wajib (tabel §4) diterapkan via GPO ke server, DC, dan klien.
- [ ] Audit Process Creation = Success **dan** "Include command line in process creation events" = Enabled (4688 + cmdline).
- [ ] DS Access (Directory Service Access & Changes) = Success+Failure di **Domain Controller**.
- [ ] PowerShell Script Block Logging (4104) + Module Logging (4103) + Transcription = Enabled via GPO.
- [ ] Windows PowerShell 2.0 Engine di-disable (tutup bypass PSv2) -> Modul 04.
- [ ] Sysmon terinstal dengan config matang (SwiftOnSecurity/Olaf Hartong); channel `Microsoft-Windows-Sysmon/Operational` aktif.
- [ ] Max log size dinaikkan minimal ke nilai CIS (Security ≥ 196,608 KB; App/System/Setup ≥ 32,768 KB).
- [ ] Retention = overwrite as needed + **forwarding** ke collector/SIEM dikonfigurasi.
- [ ] WEF/WEC aktif: subscription source-initiated via GPO, event masuk ke `ForwardedEvents`.
- [ ] Alert real-time pada Event **1102** (log cleared) dan **4719** (audit policy changed).
- [ ] Akses baca/hapus Security log dibatasi (admin + `Event Log Readers` saja).
- [ ] Waktu tersinkron ke hierarki domain (PDC -> NTP eksternal); skew terverifikasi `w32tm`.

---

## Lab Praktik

**Topologi:** `DC01` (Windows Server 2022, Domain Controller) + `CLIENT01` (Windows 10/11, member domain). Jalankan langkah di DC kecuali disebut lain.

### Langkah 1 — Aktifkan Advanced Audit Policy + 4688 command line via GPO

1. Buat GPO `Audit-Baseline`, link ke OU yang berisi server & klien (mekanisme -> Modul 03).
2. Set `Security Options > Audit: Force audit policy subcategory settings...` = **Enabled**.
3. Di `Advanced Audit Policy Configuration`, set minimal: Logon = S+F, Process Creation = S, Audit Policy Change = S+F, Security Group Management = S+F (lihat tabel §4).
4. Set `Administrative Templates > System > Audit Process Creation > Include command line...` = **Enabled**.
5. **Lakukan:** `gpupdate /force` di DC dan CLIENT01.
6. **Konfirmasi dengan:**

```cmd
auditpol /get /subcategory:"Process Creation","Logon"
```
Output harus menampilkan `Success` (dan `Success and Failure` untuk Logon).

### Langkah 2 — Aktifkan PowerShell Script Block Logging

1. Di GPO yang sama: `Administrative Templates > Windows Components > Windows PowerShell > Turn on PowerShell Script Block Logging` = **Enabled**.
2. **Lakukan:** `gpupdate /force` di CLIENT01.
3. **Konfirmasi dengan:**

```powershell
(Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging').EnableScriptBlockLogging
```
Harus mengembalikan `1`.

### Langkah 3 — Instal Sysmon dengan config

1. Unduh Sysmon (Sysinternals) + `sysmonconfig.xml` (mis. SwiftOnSecurity) ke CLIENT01.
2. **Lakukan:**

```cmd
sysmon64.exe -accepteula -i sysmonconfig.xml
```
3. **Konfirmasi dengan:** `Get-Service Sysmon64` → Status `Running`, dan channel `Microsoft-Windows-Sysmon/Operational` punya `RecordCount` > 0.

### Langkah 4 — Picu logon gagal & jalankan PowerShell

1. **Lakukan (logon gagal):** dari CLIENT01, coba `runas` / login dengan password salah 3x, atau:

```cmd
net use \\DC01\C$ /user:lab\administrator PasswordSalah123
```
(akan gagal → menghasilkan 4625/4776).

2. **Lakukan (PowerShell mencurigakan untuk memicu 4104):**

```powershell
powershell -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACIAaABhAGwAbABvACAATABLAFMAIgA=
```
(Base64 dari `Write-Host "hallo LKS"` — script block-nya akan muncul plaintext di 4104.)

### Langkah 5 — Temukan event dengan Get-WinEvent

```powershell
# 4625 logon gagal (lihat akun & alasan)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 5 |
  Select-Object TimeCreated, @{n='Target';e={$_.Properties[5].Value}}, Message

# 4104 script block (lihat teks ter-deobfuscate)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} -MaxEvents 5 |
  Select-Object TimeCreated, @{n='Script';e={$_.Properties[2].Value}}
```
**Konfirmasi:** 4625 menampilkan akun `administrator` & status password salah; 4104 menampilkan teks `Write-Host "hallo LKS"` walau dijalankan sebagai Base64 — membuktikan logging menembus obfuscation.

### Langkah 6 (lanjutan) — Uji integritas: clear log harus terdeteksi

```powershell
# Hanya untuk demonstrasi deteksi di lab — JANGAN di production tanpa izin
wevtutil cl Security
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102} -MaxEvents 1
```
**Konfirmasi:** menghapus **Security log** menghasilkan Event **1102** di Security (menghapus channel lain seperti Application/System menghasilkan Event **104** di System, bukan 1102) — inilah yang harus memicu alert dan sudah aman tersimpan bila WEF aktif (§9). Karena 1102 ditulis sebagai event pertama di log yang baru dikosongkan, ia tetap muncul; sebaliknya bukti 4625/4688 yang sudah di-forward selamat di collector — inilah alasan forwarding off-host.

---

## Perintah Audit/Verifikasi

Perintah berikut dijamin bisa dijalankan untuk membuktikan setting aktif; output yang diharapkan disebutkan.

```cmd
:: 1. Force subcategory aktif → harus 0x1
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v SCENoApplyLegacyAuditPolicy

:: 2. Seluruh kebijakan audit efektif → kolom Inclusion Setting terisi Success/Failure
auditpol /get /category:*

:: 3. Process Creation command line aktif → ProcessCreationIncludeCmdLine_Enabled = 0x1
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled
```

```powershell
# 4. Script Block Logging aktif → 1
(Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -EA SilentlyContinue).EnableScriptBlockLogging

# 5. Ukuran & mode Security log → MaximumSizeInBytes >= 201326592, LogMode = Circular
Get-WinEvent -ListLog Security | Select-Object LogName, MaximumSizeInBytes, LogMode, RecordCount, IsEnabled

# 6. Sysmon hidup → Status Running + RecordCount > 0
Get-Service Sysmon64 | Select-Object Name, Status
Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' | Select-Object RecordCount, IsEnabled

# 7. Channel PowerShell Operational aktif & terisi
Get-WinEvent -ListLog 'Microsoft-Windows-PowerShell/Operational' | Select-Object RecordCount, IsEnabled

# 8. Bukti 4688 berisi command line (cari proses dengan argumen)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -MaxEvents 3 |
  Select-Object TimeCreated, @{n='CmdLine';e={$_.Properties[8].Value}}

# 9. Verifikasi WEF subscription (di collector) → ada subscription Active
wecutil es
```

```cmd
:: 10. Verifikasi sinkronisasi waktu → Source mengarah ke DC/NTP, offset kecil
w32tm /query /source
w32tm /query /status
```

> Catatan indeks `Properties[n]`: posisi field dalam objek event dapat berbeda antar OS build. Bila `Properties[8]` (CmdLine pada 4688) atau `Properties[2]` (script pada 4104) tidak sesuai, periksa `($evt | Format-List *)` lalu sesuaikan indeks. Untuk produksi gunakan `Get-WinEvent ... | ForEach-Object { $_.ToXml() }` agar field bernama eksplisit.

---

## Referensi

- **Microsoft Security Baseline** (Windows Server 2022 & Windows 11) — bagian dari *Microsoft Security Compliance Toolkit* (SCT). Rujukan tunggal untuk rekomendasi subkategori audit & ukuran log. Terapkan/bandingkan dengan **Policy Analyzer** + **LGPO.exe** -> lihat Modul 03.
- **CIS Microsoft Windows Server 2022 / Windows 11 Benchmark** — seksi *Advanced Audit Policy Configuration* dan *Administrative Templates > Windows Components > Event Log Service*. Anchor angka maximum log size.
- **Microsoft Learn:**
  - *Advanced security audit policy settings* (Windows security audit reference).
  - *Audit Process Creation* + *Command line process auditing*.
  - *Windows PowerShell logging / Script Block Logging* (`about_Logging_Windows`).
  - *Use Windows Event Forwarding to help with intrusion detection* (WEF/WEC subscriptions).
  - *Events to monitor* (daftar Event ID rekomendasi untuk dimonitor — "Appendix L").
- **Sysinternals Sysmon** — dokumentasi resmi (Event ID & skema konfigurasi).
- **Konfigurasi Sysmon komunitas:** SwiftOnSecurity `sysmon-config`; Olaf Hartong `sysmon-modular` (dipetakan ke MITRE ATT&CK).
- **MITRE ATT&CK** — referensi teknik: T1070.001, T1562.001, T1059.001, T1003.001, T1003.006, T1558.003/.004, T1110.003.
