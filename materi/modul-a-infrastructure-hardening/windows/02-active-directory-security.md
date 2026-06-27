# Modul 02 — Konfigurasi Keamanan Dasar Active Directory

> Active Directory (AD) adalah pusat identitas seluruh domain: satu Domain Controller (DC) yang jebol berarti seluruh organisasi jebol. Dari sudut pandang penyerang, AD adalah "crown jewel" — setelah memegang akun istimewa atau hash KRBTGT, mereka bisa membuat tiket Kerberos palsu (Golden Ticket), mereplikasi seluruh hash password (DCSync), dan bertahan tanpa terdeteksi. Modul ini mengeraskan fondasi AD: password & lockout policy, Kerberos, NTLM, LDAP signing, delegasi, dan kebersihan grup istimewa, sehingga jalur serangan klasik tertutup sejak awal.

## Daftar Isi

1. [Konsep & Tujuan](#1-konsep--tujuan)
2. [Mengamankan Domain Controller](#2-mengamankan-domain-controller)
3. [Password Policy (Default Domain Policy)](#3-password-policy-default-domain-policy)
4. [Account Lockout Policy](#4-account-lockout-policy)
5. [Fine-Grained Password Policy (PSO)](#5-fine-grained-password-policy-pso)
6. [Kebijakan Kerberos](#6-kebijakan-kerberos)
7. [Memaksa AES & Menonaktifkan RC4](#7-memaksa-aes--menonaktifkan-rc4)
8. [Rotasi Password KRBTGT](#8-rotasi-password-krbtgt)
9. [NTLM Hardening](#9-ntlm-hardening)
10. [LDAP Signing & Channel Binding](#10-ldap-signing--channel-binding)
11. [Hygiene Grup Privileged](#11-hygiene-grup-privileged)
12. [AdminSDHolder & SDProp](#12-adminsdholder--sdprop)
13. [Delegation (Unconstrained / Constrained / RBCD)](#13-delegation)
14. [AD Recycle Bin](#14-ad-recycle-bin)
15. [SYSVOL & GPP (cpassword / MS14-025)](#15-sysvol--gpp)
16. [Built-in Accounts & Sinkronisasi Waktu](#16-built-in-accounts--sinkronisasi-waktu)
17. [AD-integrated DNS](#17-ad-integrated-dns)
18. [Serangan Umum & Mitigasi](#serangan-umum--mitigasi)
19. [Hardening Checklist (Modul Ini)](#hardening-checklist-modul-ini)
20. [Lab Praktik](#lab-praktik)
21. [Perintah Audit/Verifikasi](#perintah-auditverifikasi)
22. [Referensi](#referensi)

---

## 1. Konsep & Tujuan

Active Directory menyimpan identitas (user, computer, service), kredensial (hash password di `ntds.dit`), dan kebijakan keamanan untuk seluruh domain. Tiga properti yang kita lindungi:

- **Confidentiality** — hash password dan secret tidak boleh bocor (mitigasi DCSync, Kerberoasting).
- **Integrity** — tiket Kerberos dan binding LDAP tidak boleh dipalsukan atau di-relay (mitigasi Golden Ticket, LDAP relay).
- **Availability** — objek yang terhapus bisa dipulihkan (AD Recycle Bin), DC tetap dapat melayani autentikasi.

Prinsip kunci modul ini:

- **Least privilege** — minimalkan keanggotaan grup istimewa (model tiering Tier 0/1/2 → lihat Modul 01).
- **Defense in depth** — banyak lapisan: kebijakan password kuat + lockout + Kerberos armoring + NTLM/LDAP hardening.
- **Anchor numerik tunggal** — semua angka (panjang password, threshold lockout, lifetime tiket) diankor ke **Microsoft Security Baseline** dan **CIS Benchmark**. Jangan mengarang angka; bila dua sumber berbeda, tampilkan keduanya dengan sumbernya.

**Penting soal mekanisme GPO:** Password Policy, Account Lockout Policy, dan Kerberos Policy adalah kebijakan **tingkat domain** — hanya GPO yang di-*link* ke root domain (default: *Default Domain Policy*) yang berlaku untuk akun domain. Override per-user/grup untuk password & lockout **hanya** bisa lewat PSO (Bagian 5), bukan GPO pada OU. Cara membuat, men-*link*, dan mengedit GPO (LSDOU, inheritance, security filtering) adalah milik **Modul 03** — di modul ini kita fokus pada *nilai apa* yang diset dan *kenapa*, bukan mekanik GPO-nya.

---

## 2. Mengamankan Domain Controller

**APA:** DC adalah server paling sensitif; ia menyimpan salinan database AD (`ntds.dit`) berisi semua hash. Hardening DC = mengurangi attack surface fisik dan logikal.

**KENAPA:** Kompromi satu DC = kompromi seluruh domain. Penyerang yang bisa logon lokal atau menjalankan kode di DC bisa langsung mengekstrak hash (`T1003.003` — NTDS).

**CARA:**

| Tindakan | Detail |
|---|---|
| **Peran minimal** | DC hanya menjalankan AD DS + DNS. Jangan pasang IIS, file share umum, browser, Office, atau aplikasi pihak ketiga di DC. |
| **Kurangi software** | Hapus role/feature yang tidak perlu; gunakan **Server Core** (tanpa GUI) untuk attack surface lebih kecil. |
| **Batasi logon** | Hanya Tier 0 admin boleh logon interaktif ke DC. Diset lewat **User Rights Assignment** (Allow/Deny log on locally, Deny log on through Remote Desktop) → mekanisme URA milik **Modul 03**; model tiering & PAW milik **Modul 01**. |
| **Patch** | DC harus selalu ter-patch (mis. mitigasi Zerologon CVE-2020-1472, sAMAccountName spoofing CVE-2021-42278/42287). |
| **Akses fisik** | DC di ruang terkunci; BitLocker pada volume yang memuat `ntds.dit`. |

**RODC untuk lokasi tak aman:** Read-Only Domain Controller (RODC) menyimpan salinan AD yang *read-only* dan secara default **tidak** meng-cache password apa pun. Gunakan di cabang/lokasi dengan keamanan fisik lemah. Yang di-cache dikontrol oleh **Password Replication Policy (PRP)** — daftar akun yang boleh di-cache. Akun Tier 0 (Domain Admins, dll.) **tidak boleh** masuk PRP RODC. Bila RODC dicuri, hanya password yang sudah di-cache yang berisiko, dan bisa di-reset terarah.

**Backup & DSRM:**

- Lakukan **System State backup** rutin (berisi AD database, SYSVOL, registry).
- **DSRM (Directory Services Restore Mode)** password diset saat promosi DC. Ini password lokal untuk boot ke mode pemulihan. Reset berkala dan simpan aman (breakglass → lihat Modul 01).

```cmd
ntdsutil "set dsrm password" "reset password on server null" q q
```

```powershell
# Cek/atur sinkronisasi DSRM agar bisa dipakai untuk operasi tertentu (opsional)
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v DsrmAdminLogonBehavior
```

---

## 3. Password Policy (Default Domain Policy)

**APA:** Aturan kompleksitas dan umur password untuk semua akun domain. Diset di **Default Domain Policy** (atau GPO lain yang di-link ke root domain).

**Path GPO:** `Computer Configuration > Policies > Windows Settings > Security Settings > Account Policies > Password Policy`

**KENAPA:** Password lemah/pendek mudah ditebak (password spraying `T1110.003`) atau dipecah offline setelah hash dicuri (Kerberoasting `T1558.003`).

**CARA — tabel nilai (anchor ke sumber):**

| Setting | Microsoft Security Baseline | CIS Benchmark (L1) | Catatan |
|---|---|---|---|
| **Enforce password history** | 24 | 24 | Cegah daur ulang password. |
| **Maximum password age** | *Tidak direkomendasikan* (expiration dihapus) | 365 hari (≤365, **bukan 0**) | Lihat divergensi di bawah. |
| **Minimum password age** | 1 hari | 1 hari | Cegah user memutar history dalam sehari. |
| **Minimum password length** | 14 karakter | 14 karakter | GUI klasik membatasi tampilan ≤14. |
| **Password must meet complexity requirements** | Enabled | Enabled | 3 dari 4 kategori karakter. |
| **Store passwords using reversible encryption** | Disabled | Disabled | Setara plaintext; **harus off**. |

**Divergensi "panjang vs ekspirasi" (poin penting):** Sejak baseline era Windows 10 1903, **Microsoft menghapus rekomendasi password expiration** (Maximum password age) — mengikuti **NIST SP 800-63B** yang menyatakan ekspirasi periodik mendorong password lemah/berpola dan sebaiknya hanya di-reset bila ada indikasi kompromi. **CIS** masih mensyaratkan ≤365 hari (tidak boleh 0). Untuk LKS: tampilkan kedua nilai, dan pahami argumennya — utamakan **panjang & keunikan** (passphrase panjang) di atas rotasi paksa. Bila juri memakai CIS, set 365; bila memakai filosofi modern Microsoft, panjang ditingkatkan dan ekspirasi dilonggarkan, dengan deteksi kompromi sebagai gantinya.

**Delta Windows Server 2022 — minimum length > 14:** Server 2022 menambah dua setting di Account Policies: **"Minimum password length audit"** (mencatat akun yang tidak memenuhi target panjang tanpa benar-benar mengunci, untuk uji dampak) dan **"Relax minimum password length limits"** (`RelaxMinimumPasswordLengthLimits`) yang mengizinkan **Minimum password length** dinaikkan melebihi batas lama 14 karakter, hingga **maksimum 128 karakter**. Setting ini tersedia mulai OS Windows 10 versi 2004 / Server 2022 ke atas dan harus diaktifkan pada semua DC; **tidak** ada syarat Domain/Forest Functional Level khusus — yang diperlukan adalah DC yang menjalankan build tersebut. Berguna untuk transisi ke passphrase panjang tanpa langsung mengunci user.

```powershell
# Lihat policy password domain saat ini
Get-ADDefaultDomainPasswordPolicy

# Set via PowerShell (alternatif GUI; perubahan domain-wide)
Set-ADDefaultDomainPasswordPolicy -Identity "contoso.local" `
  -MinPasswordLength 14 `
  -PasswordHistoryCount 24 `
  -ComplexityEnabled $true `
  -MinPasswordAge "1.00:00:00" `
  -MaxPasswordAge "365.00:00:00" `
  -ReversibleEncryptionEnabled $false
```

---

## 4. Account Lockout Policy

**APA:** Mengunci akun setelah sejumlah percobaan login gagal.

**Path GPO:** `... > Account Policies > Account Lockout Policy`

**KENAPA:** Menghambat brute-force dan password spraying (`T1110`). Tanpa lockout, penyerang bebas mencoba ribuan password.

**CARA — tabel nilai:**

| Setting | Microsoft Security Baseline | CIS Benchmark (L1) | Catatan |
|---|---|---|---|
| **Account lockout threshold** | 10 percobaan | ≤5 (bukan 0) | 0 = tidak pernah lockout (**jangan**). |
| **Account lockout duration** | 15 menit | ≥15 menit | Lama akun terkunci. |
| **Reset account lockout counter after** | 15 menit | ≥15 menit | **Harus ≤** lockout duration. |
| **Allow Administrator account lockout** | Enabled | Enabled | Baru di Win11/Server 2022 — RID 500 ikut bisa terkunci. |

**Trade-off DoS:** Threshold terlalu rendah memudahkan **lockout-based DoS** — penyerang sengaja gagal login untuk mengunci akun korban dan mengganggu operasi. Threshold terlalu tinggi memperlemah perlindungan brute-force. Nilai baseline (5–10) adalah kompromi. **Threshold 0 menonaktifkan lockout sepenuhnya — jangan pernah dipakai.** Reset counter harus ≤ lockout duration agar percobaan terakumulasi dengan benar.

**Delta Win11/Server 2022:** Sejak Windows 11 22H2 / Server 2022 (build Oktober 2022), **instalasi baru** OS sudah memiliki **default lockout** bawaan: threshold 10, duration 10 menit, reset counter 10 menit (10/10/10), dan "Allow Administrator account lockout" aktif. Default ini diterapkan otomatis pada fresh install (bukan upgrade dari versi lama), bahkan sebelum admin mengonfigurasi domain policy.

```powershell
Set-ADDefaultDomainPasswordPolicy -Identity "contoso.local" `
  -LockoutThreshold 10 `
  -LockoutDuration "0.00:15:00" `
  -LockoutObservationWindow "0.00:15:00"
```

---

## 5. Fine-Grained Password Policy (PSO)

**APA:** **Password Settings Object (PSO)** memungkinkan kebijakan password/lockout berbeda untuk grup/user tertentu dalam satu domain — mengatasi keterbatasan "satu domain, satu password policy".

**KENAPA:** Akun admin/Tier 0 perlu kebijakan **lebih ketat** (mis. minimum 20+ karakter, ekspirasi pendek) daripada user biasa. PSO adalah satu-satunya cara override password+lockout per-grup tanpa membuat domain baru.

**CARA (PowerShell — RSAT AD module):**

```powershell
# Buat PSO ketat untuk admin
New-ADFineGrainedPasswordPolicy -Name "PSO-Admins" `
  -Precedence 10 `
  -MinPasswordLength 20 `
  -PasswordHistoryCount 24 `
  -ComplexityEnabled $true `
  -MinPasswordAge "1.00:00:00" `
  -MaxPasswordAge "60.00:00:00" `
  -LockoutThreshold 5 `
  -LockoutDuration "0.00:30:00" `
  -LockoutObservationWindow "0.00:30:00" `
  -ReversibleEncryptionEnabled $false

# Terapkan ke grup (lebih baik ke grup daripada user langsung)
Add-ADFineGrainedPasswordPolicySubject "PSO-Admins" -Subjects "Domain Admins","Enterprise Admins"

# Verifikasi target dan policy efektif untuk satu user
Get-ADFineGrainedPasswordPolicy -Identity "PSO-Admins"
Get-ADUserResultantPasswordPolicy -Identity "adm-andi"
```

**Precedence (penting):** Bila satu user kena banyak PSO, **angka precedence terKECIL menang**. PSO yang langsung di-assign ke user mengalahkan PSO yang di-assign via grup. Pastikan precedence unik agar resolusi deterministik. PSO membutuhkan **Domain Functional Level 2008+** dan disimpan di container `Password Settings Container` (System).

---

## 6. Kebijakan Kerberos

**APA:** Mengatur masa berlaku tiket Kerberos (TGT/TGS), renewal, dan toleransi jam.

**Path GPO:** `... > Account Policies > Kerberos Policy` (hanya berlaku di tingkat domain).

**KENAPA:** Tiket berumur panjang memperluas jendela penyalahgunaan tiket curian (Pass-the-Ticket `T1550.003`). Toleransi jam yang longgar mempermudah replay. Validitas Kerberos bergantung pada **sinkronisasi waktu** (Bagian 16) — jika selisih jam > toleransi, autentikasi gagal.

**CARA — tabel nilai (default = anchor baseline):**

| Setting | Nilai (Microsoft default / CIS) | Catatan |
|---|---|---|
| **Maximum lifetime for user ticket (TGT)** | 10 jam | ≤10 jam. |
| **Maximum lifetime for service ticket (TGS)** | 600 menit (10 jam) | ≤600 menit, >10 menit. |
| **Maximum lifetime for user ticket renewal** | 7 hari | ≤7 hari. |
| **Maximum tolerance for computer clock synchronization** | 5 menit | ≤5 menit — krusial untuk cegah replay. |
| **Enforce user logon restrictions** | Enabled | Validasi tiap permintaan TGS terhadap hak logon user. |

Nilai-nilai ini juga merupakan default Windows; CIS dan Microsoft Security Baseline mempertahankannya. **Catatan Golden Ticket:** lifetime ini hanya membatasi tiket yang dikeluarkan KDC sah — Golden Ticket palsu bisa diberi lifetime sembarang (sering 10 tahun), sehingga mitigasi sebenarnya adalah melindungi hash KRBTGT (Bagian 8), bukan policy ini.

**Kerberos Armoring (FAST):** **Flexible Authentication Secure Tunneling (FAST)** membungkus **AS exchange (pre-authentication)** Kerberos dalam channel terenkripsi (di-armor oleh TGT komputer), sehingga melindungi dari sniffing pre-auth dan dari spoofing error KDC. Diaktifkan via GPO:

- **DC side:** `Computer Configuration > Administrative Templates > System > KDC > Support Dynamic Access Control and Kerberos armoring` → *Supported* atau *Always provide claims/Fail unarmored requests*.
- **Client side:** `... > System > Kerberos > Kerberos client support for claims, compound authentication and Kerberos armoring` → *Enabled*.

Armoring membutuhkan klien & DC yang mendukung dan **DFL 2012+**. Terapkan via GPO → mekanisme link/scoping lihat **Modul 03**.

> **Nuansa terhadap roasting (jangan overstate).** FAST meng-armor **AS exchange**, jadi ia menyumbang ke pertahanan **AS-REP Roasting** (melindungi blob pre-auth) — namun **tidak menyelesaikan Kerberoasting**. Kerberoasting memakai **TGS exchange**: tiket layanan (TGS) tetap dienkripsi dengan **kunci akun service** dan dikembalikan ke peminta, sehingga **tetap bisa di-crack offline** terlepas dari FAST. Mitigasi Kerberoasting yang sebenarnya tetap: **password panjang/PSO**, **gMSA** (Modul 01), dan **memaksa AES (Bagian 7)** sehingga tiket tidak lagi memakai RC4 yang murah di-crack. FAST adalah pelengkap, bukan pengganti, untuk Kerberoasting.

---

## 7. Memaksa AES & Menonaktifkan RC4

**APA:** Mengatur tipe enkripsi yang boleh dipakai Kerberos melalui atribut `msDS-SupportedEncryptionTypes` dan Security Option.

**KENAPA:** **RC4-HMAC** memakai kunci turunan NT hash yang lemah dan mempermudah Kerberoasting offline (`T1558.003`). **DES** sudah usang. **AES128/AES256** jauh lebih kuat. Menonaktifkan RC4 mempersulit cracking tiket layanan.

**Nilai bit `msDS-SupportedEncryptionTypes`:**

| Bit (dec / hex) | Algoritma |
|---|---|
| 1 / 0x1 | DES-CBC-CRC |
| 2 / 0x2 | DES-CBC-MD5 |
| 4 / 0x4 | RC4-HMAC |
| 8 / 0x8 | AES128-CTS-HMAC-SHA1-96 |
| 16 / 0x10 | AES256-CTS-HMAC-SHA1-96 |

AES-only = `8 + 16 = 24` (**0x18**).

**CARA:**

- **GPO (Security Option):** `... > Local Policies > Security Options > Network security: Configure encryption types allowed for Kerberos` → centang **AES128_HMAC_SHA1**, **AES256_HMAC_SHA1**, dan **Future encryption types**; **jangan** centang RC4/DES.

```powershell
# Set per-akun (mis. service account) ke AES-only (0x18 = 24)
Set-ADUser -Identity "svc-sql" -Replace @{ 'msDS-SupportedEncryptionTypes' = 24 }

# Audit: temukan akun yang masih mengizinkan RC4 (bit 0x4) atau belum diset
Get-ADObject -Filter * -Properties msDS-SupportedEncryptionTypes |
  Where-Object { $_.'msDS-SupportedEncryptionTypes' -band 0x4 } |
  Select-Object Name, msDS-SupportedEncryptionTypes
```

**Caveat operasional (depth tingkat pemenang — wajib paham sebelum prod):**

- **Kunci AES dibuat saat password DIUBAH.** Akun yang password-nya dibuat sebelum dukungan AES (atau di-migrasi) mungkin **belum punya kunci AES**. Bila RC4 dimatikan sebelum password di-reset, autentikasi akun itu **rusak**. Solusi: ubah/reset password agar kunci AES tergenerasi, lalu baru matikan RC4.
- **Menonaktifkan RC4 forest-wide** bisa merusak **trust** lama, appliance, dan sistem legacy yang hanya bicara RC4.
- **Selalu audit `msDS-SupportedEncryptionTypes` lebih dulu di produksi** (perintah di atas) sebelum penegakan. Di lab ini kita akan mematikan RC4, jadi pahami konsekuensinya.

### 7.1 Enumerasi akun rentan roasting (AS-REP & Kerberoasting)

Sebelum menutup, temukan dulu **akun yang bisa di-roast** — ini perintah enumerasi yang sama dipakai penyerang (sisi blue-team: cari & perbaiki lebih dulu). Roasting bernilai tinggi justru pada akun yang masih mengizinkan **RC4** (hash turunan NT, jauh lebih cepat di-crack daripada AES).

```powershell
# (1) AS-REP Roasting (T1558.004): akun dengan preauth Kerberos DIMATIKAN
#     → AS-REP-nya bisa diminta tanpa kredensial & di-crack offline ($krb5asrep$, hashcat -m 18200)
Get-ADUser -Filter { DoesNotRequirePreAuth -eq $true } -Properties DoesNotRequirePreAuth |
  Where-Object { $_.Enabled } | Select-Object SamAccountName, DoesNotRequirePreAuth
#   Harapan setelah hardening: KOSONG. Perbaiki: hidupkan preauth di tab Account ADUC
#   atau: Set-ADAccountControl -Identity <user> -DoesNotRequirePreAuth $false

# (2) Kerberoasting (T1558.003): akun USER dengan SPN (service account)
#     → TGS-nya bisa diminta lalu di-crack offline ($krb5tgs$, hashcat -m 13100 RC4 / -m 19700 AES)
Get-ADUser -Filter { ServicePrincipalName -like '*' } `
  -Properties ServicePrincipalName, msDS-SupportedEncryptionTypes |
  Select-Object SamAccountName,
    @{n='SPN';e={$_.ServicePrincipalName -join ', '}},
    @{n='EncTypes';e={$_.'msDS-SupportedEncryptionTypes'}}
#   (akun komputer & krbtgt punya SPN secara wajar — fokus ke akun USER ber-SPN)

# (3) Silang keduanya dengan RC4: akun ber-SPN yang RC4-nya masih aktif = prioritas perbaikan
Get-ADUser -Filter { ServicePrincipalName -like '*' } -Properties msDS-SupportedEncryptionTypes |
  Where-Object {
    $e = $_.'msDS-SupportedEncryptionTypes'
    ($e -eq $null) -or ($e -eq 0) -or ($e -band 0x4)   # null/0 ⇒ RC4 default, atau bit RC4 menyala
  } | Select-Object SamAccountName, msDS-SupportedEncryptionTypes
#   Harapan: kosong setelah AES dipaksa. Perbaikan: panjangkan password/PSO (Bagian 5),
#   ganti ke gMSA (Modul 01), set msDS-SupportedEncryptionTypes = 24 (AES-only), reset password.
```

> **Catatan `msDS-SupportedEncryptionTypes` null/0:** akun yang atribut ini **kosong/0** diperlakukan KDC sebagai **RC4 diizinkan** (perilaku default) — jadi jangan anggap "tidak diset" = aman. Set eksplisit ke `24` (0x18) untuk AES-only.

---

## 8. Rotasi Password KRBTGT

**APA:** `KRBTGT` adalah akun yang kuncinya menandatangani semua TGT. Rotasi = mengganti password akun ini.

**KENAPA:** Jika penyerang mencuri hash KRBTGT (mis. via DCSync), mereka bisa membuat **Golden Ticket** (`T1558.001`) — TGT palsu untuk siapa saja, dengan lifetime sembarang, valid sampai KRBTGT diganti. Rotasi membatalkan semua Golden Ticket yang ada.

**KENAPA harus 2x (double-reset):** Akun KRBTGT menyimpan **dua kunci**: password *current* dan *previous*. Sekali reset, kunci lama masih valid (di slot previous) sehingga tiket aktif tidak langsung putus. **Reset kedua** menggeser kunci yang sudah bocor keluar dari slot previous, sehingga benar-benar tidak valid lagi.

**CARA & urutan (alasan jeda — propagasi replikasi DULU):**

1. Reset KRBTGT pertama.
2. **Tunggu replikasi selesai ke SEMUA DC.** Inilah alasan utama jeda: jika reset kedua dilakukan sebelum DC lain menerima reset pertama, slot kunci bisa kacau dan tiket sah pun putus. Sekunder, beri waktu agar tiket yang masih beredar (≤ max TGT lifetime, 10 jam) bisa di-renew memakai kunci baru.
3. Reset KRBTGT kedua setelah replikasi penuh + jeda lifetime.

```powershell
# Cek waktu password KRBTGT terakhir diubah (audit)
Get-ADUser krbtgt -Properties PasswordLastSet | Select-Object Name, PasswordLastSet

# Paksa replikasi seluruh forest setelah reset
repadmin /syncall /AdeP
```

Gunakan skrip resmi Microsoft **`New-KrbtgtKeys.ps1`** (kini diarsipkan di `microsoftarchive/New-KrbtgtKeys.ps1`; fork komunitas yang masih dipelihara: `Reset-KrbTgt-Password-For-RWDCs-And-RODCs.ps1`) yang menangani reset aman + verifikasi replikasi, alih-alih mereset manual lewat ADUC. **Catatan interval:** Microsoft **tidak** menetapkan interval rotasi periodik yang baku — dokumentasi "AD Forest Recovery: Reset the krbtgt password" menyerahkan kadensi ke kebijakan organisasi (selaraskan dengan jadwal backup, prosedur operasional, dan kebutuhan keamanan). Praktik umum di lapangan adalah rotasi **minimal dua kali setahun** (≈180 hari) sebagai higienitas, bukan hanya saat insiden.

---

## 9. NTLM Hardening

**APA:** Membatasi/menonaktifkan protokol autentikasi lawas LM dan NTLMv1, memaksa NTLMv2, dan membatasi penggunaan NTLM.

**KENAPA:** LM/NTLMv1 lemah secara kriptografis dan rentan terhadap relay & cracking; NTLM secara umum rentan **NTLM relay** (`T1557.001`) dan **Pass-the-Hash** (`T1550.002`). Kerberos harus diutamakan; NTLM dibatasi.

**CARA:**

| Setting | Path GPO (Security Options) | Nilai | Registry |
|---|---|---|---|
| **LAN Manager authentication level** | `Network security: LAN Manager authentication level` | *Send NTLMv2 response only. Refuse LM & NTLM* (level 5) | `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LmCompatibilityLevel = 5` |
| **No LM hash** | `Network security: Do not store LAN Manager hash value on next password change` | Enabled (default sejak Vista/2008) | `...\Lsa\NoLMHash = 1` |
| **Restrict NTLM: Audit incoming traffic** | `Network security: Restrict NTLM: Audit Incoming NTLM Traffic` | *Enable auditing for all accounts* | — |
| **Restrict NTLM: Outgoing to remote servers** | `Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers` | *Audit all* lalu *Deny all* setelah inventarisasi | — |

```reg
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa]
"LmCompatibilityLevel"=dword:00000005
"NoLMHash"=dword:00000001
```

**Strategi:** Mulai dengan **audit** ("Restrict NTLM: Audit Incoming/Outgoing") untuk menemukan aplikasi yang masih bergantung pada NTLM (cek **Event ID** terkait di Operational log; daftar lengkap Event ID & audit policy → **Modul 06**), baru tingkatkan ke **Deny** agar tidak memutus layanan sah. Penegakan via GPO → **Modul 03**.

---

## 10. LDAP Signing & Channel Binding

**APA:** Memaksa DC menolak LDAP bind yang tidak ditandatangani (signing) dan mem-binding koneksi LDAPS ke channel TLS-nya (channel binding token / CBT).

**KENAPA:** Tanpa signing/CBT, penyerang bisa melakukan **LDAP relay** (varian `T1557`) — meneruskan kredensial korban ke DC untuk membuat akun/komputer atau mengubah ACL (sering dipakai bersama RBCD untuk eskalasi). Signing memastikan integritas; channel binding mengikat autentikasi ke sesi TLS spesifik sehingga tidak bisa di-relay.

**CARA:**

| Kontrol | Path GPO (Security Options) | Registry | Nilai target |
|---|---|---|---|
| **LDAP server signing** | `Domain controller: LDAP server signing requirements` | `HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity` | **2 = Require signing** |
| **LDAP channel binding** | `Domain controller: LDAP server channel binding token requirements` | `HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\LdapEnforceChannelBinding` | **2 = Always** (1 = When supported, 0 = Never) |
| **LDAP client signing** | `Network security: LDAP client signing requirements` | `HKLM\SYSTEM\CurrentControlSet\Services\LDAP\LDAPClientIntegrity` | **2 = Require signing** |

```reg
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\Parameters]
"LDAPServerIntegrity"=dword:00000002
"LdapEnforceChannelBinding"=dword:00000002
```

**Catatan rollout:** Mulai dengan **`LdapEnforceChannelBinding = 1` (When supported)** dan audit klien yang gagal (Event ID **2889** = bind LDAP unsigned, dicatat di Directory Service log — detail interpretasi event → **Modul 06**) sebelum naik ke **2 (Always)**, agar aplikasi lama tidak putus. Microsoft sejak update Maret 2020 sangat menganjurkan signing+CBT diaktifkan.

---

## 11. Hygiene Grup Privileged

**APA:** Meminimalkan dan mengaudit keanggotaan grup berhak tinggi.

**KENAPA:** Setiap anggota grup ini adalah target bernilai tinggi. Anggota berlebih = attack surface lebih luas untuk privilege escalation dan lateral movement. Model tiering, JIT/JEA, dan time-based membership ada di **Modul 01** — di sini kita pastikan grupnya ramping dan teraudit.

**Grup yang harus dijaga ketat (idealnya nyaris kosong / hanya akun Tier 0):**

| Grup | Risiko bila berlebih |
|---|---|
| **Domain Admins** | Kontrol penuh atas domain. |
| **Enterprise Admins** | Kontrol penuh atas seluruh forest (default kosong selain Administrator). |
| **Schema Admins** | Ubah skema AD (harus kosong kecuali saat perubahan skema). |
| **Administrators (built-in domain)** | Setara DA pada DC. |
| **Account Operators** | Bisa kelola akun non-admin & logon ke DC — sering disalahgunakan; kosongkan. |
| **Backup Operators** | Bisa baca/tulis file apa pun & backup `ntds.dit` → ekstraksi hash; kosongkan/ketati. |
| **Print Operators / Server Operators** | Hak logon & driver di DC; kosongkan. |

```powershell
# Audit keanggotaan Domain Admins (rekursif)
Get-ADGroupMember -Identity "Domain Admins" -Recursive |
  Select-Object Name, SamAccountName, objectClass

# Audit grup sensitif lain sekaligus
"Enterprise Admins","Schema Admins","Administrators","Account Operators","Backup Operators" |
  ForEach-Object {
    "=== $_ ==="
    Get-ADGroupMember -Identity $_ -Recursive | Select-Object -ExpandProperty SamAccountName
  }
```

Aturan praktis: **Schema Admins & Enterprise Admins kosong** kecuali saat operasi spesifik; **Domain Admins seramping mungkin**; gunakan akun terpisah per tier (jangan akun harian masuk DA).

### 11.1 Audit hak DCSync (replication rights pada domain head)

**APA & KENAPA:** Serangan **DCSync** (`T1003.006`) memakai protokol replikasi DRSUAPI untuk menarik hash semua akun (termasuk KRBTGT) **tanpa logon ke DC**. Yang dibutuhkan penyerang adalah dua *extended right* pada objek **domain head** (root domain):

| Extended right | rightsGuid |
|---|---|
| **DS-Replication-Get-Changes** | `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` |
| **DS-Replication-Get-Changes-All** | `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` |
| DS-Replication-Get-Changes-In-Filtered-Set | `89e95b76-444d-4c62-991a-0facbeda640c` |

DCSync menuntut **kedua** GUID pertama (`Get-Changes` + `Get-Changes-All`); secara default hanya **Domain Controllers, Domain Admins, Enterprise Admins, dan Administrators** yang memilikinya. Setiap principal lain yang memegangnya = pintu belakang DCSync.

**CARA — enumerasi principal yang punya hak replikasi pada domain head:**

```powershell
$domDN = (Get-ADDomain).DistinguishedName
# Cast ke [guid[]] supaya perbandingan Guid-ke-Guid (hindari false-negative dari mismatch tipe)
[guid[]]$repl = @('1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',   # Get-Changes
                  '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2')   # Get-Changes-All
(Get-Acl "AD:$domDN").Access |
  Where-Object { $_.ObjectType -in $repl -and $_.AccessControlType -eq 'Allow' } |
  Select-Object IdentityReference,
    @{n='Right';e={ if ($_.ObjectType -eq $repl[1]) {'Get-Changes-All'} else {'Get-Changes'} }}
#   Harapan: HANYA Domain Controllers / Domain Admins / Enterprise Admins / Administrators.
#   Principal lain (user/grup biasa) = hapus segera (delegasi DCSync tak sah).
```

Untuk **deteksi runtime** (bukan hanya audit ACL), aktifkan **Audit Directory Service Access** dan pantau **Event ID 4662** yang `Properties`-nya memuat GUID di atas sementara `Subject` **bukan** akun komputer DC (daftar Event ID & audit policy → **Modul 06**).

---

## 12. AdminSDHolder & SDProp

**APA:** `AdminSDHolder` adalah objek template di `CN=AdminSDHolder,CN=System,<domain>` yang menyimpan ACL "emas". Proses **SDProp (Security Descriptor Propagator)** menyalin ACL ini ke semua **protected accounts/groups** secara berkala.

**KENAPA:** Mencegah ACL akun istimewa diam-diam diubah penyerang (mis. memberi diri sendiri hak reset password pada DA). SDProp mengembalikan ACL ke template, dan menyetel atribut `adminCount = 1` pada objek terproteksi.

**CARA KERJA:**

- SDProp berjalan otomatis **tiap 60 menit** di PDC emulator (default). Diatur oleh registry `HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\AdminSDProtectFrequency` (detik, default 3600). Microsoft menyarankan **tidak** mengubah interval ini tanpa alasan kuat.
- Objek yang anggota (langsung/tidak langsung) dari protected groups (Domain Admins, Enterprise Admins, Administrators, Schema Admins, Account Operators, Backup Operators, Server Operators, Print Operators, KRBTGT, dll.) mendapat `adminCount=1` dan **inheritance dimatikan** + ACL dari AdminSDHolder.

**Dampak ke delegasi:** Jika user pernah jadi anggota protected group lalu dikeluarkan, `adminCount=1` **tetap menempel** dan inheritance tetap mati — sehingga delegasi yang mengandalkan inheritance ACL (mis. helpdesk reset password di OU) **tidak berlaku** untuk akun itu. Ini disebut "orphaned adminCount".

```powershell
# Temukan akun ber-adminCount=1 (kandidat orphaned bila bukan lagi anggota protected group)
Get-ADUser -LDAPFilter "(adminCount=1)" -Properties adminCount, memberOf |
  Select-Object Name, SamAccountName

# Paksa SDProp jalan sekarang (via ldp/PowerShell) — RunProtectAdminGroupsTask
$rootdse = Get-ADRootDSE
Set-ADObject -Identity $rootdse -Replace @{ runProtectAdminGroupsTask = 1 }
```

**Audit ACL AdminSDHolder** secara berkala untuk entri tak sah:

```powershell
(Get-Acl "AD:CN=AdminSDHolder,CN=System,DC=contoso,DC=local").Access |
  Select-Object IdentityReference, ActiveDirectoryRights, AccessControlType
```

---

## 13. Delegation

**APA:** Kerberos delegation memungkinkan satu layanan bertindak atas nama (impersonate) user ke layanan lain. Ada tiga jenis dengan tingkat risiko berbeda.

**KENAPA:** Delegasi yang salah konfigurasi adalah jalur eskalasi favorit. Terutama **unconstrained delegation** sangat berbahaya.

| Jenis | Atribut | Risiko |
|---|---|---|
| **Unconstrained** | `userAccountControl` flag `TRUSTED_FOR_DELEGATION` (0x80000) | **Tertinggi.** Host menyimpan **TGT** user yang terhubung di memori → bisa diekstrak & dipakai ulang. DC punya ini secara default; jangan pernah berikan ke server biasa. Penyerang dapat memaksa DC mengautentikasi (mis. PrinterBug) ke host unconstrained lalu mencuri TGT DC. |
| **Constrained** | `msDS-AllowedToDelegateTo` (+ `TRUSTED_TO_AUTH_FOR_DELEGATION` 0x1000000 untuk protocol transition) | Lebih aman: hanya boleh delegasi ke SPN spesifik. Protocol transition (S4U2Self) tetap berisiko bila SPN target sensitif. |
| **Resource-Based Constrained (RBCD)** | `msDS-AllowedToActOnBehalfOfOtherIdentity` (diset di objek **target**) | Delegasi dikontrol di sisi resource. Aman bila ACL pembuat/penulis atribut ini dijaga — sering disalahgunakan setelah LDAP relay/write akses ke objek komputer. |

**Hardening:**

- **Audit unconstrained delegation** (selain DC, harus nyaris tidak ada):

```powershell
# Computer/akun dengan unconstrained delegation (TrustedForDelegation = $true)
Get-ADComputer -Filter { TrustedForDelegation -eq $true } -Properties TrustedForDelegation |
  Select-Object Name
Get-ADUser -Filter { TrustedForDelegation -eq $true } -Properties TrustedForDelegation |
  Select-Object Name
```

- **Audit constrained delegation** (atribut `msDS-AllowedToDelegateTo` — daftar SPN target yang boleh di-impersonate); perhatikan juga flag protocol transition `TRUSTED_TO_AUTH_FOR_DELEGATION` (S4U2Self, `TrustedToAuthForDelegation = $true`) yang lebih berisiko:

```powershell
# Akun dengan constrained delegation + target SPN-nya
Get-ADObject -LDAPFilter '(msDS-AllowedToDelegateTo=*)' `
  -Properties msDS-AllowedToDelegateTo, userAccountControl |
  Select-Object Name, @{n='DelegateTo';e={$_.'msDS-AllowedToDelegateTo'}}
# Subset protocol transition (paling berisiko)
Get-ADUser -Filter { TrustedToAuthForDelegation -eq $true } |
  Select-Object Name, SamAccountName
```

- **Audit Resource-Based Constrained Delegation (RBCD)** — atribut `msDS-AllowedToActOnBehalfOfOtherIdentity` diset di objek **target**; sering ditanam penyerang setelah LDAP relay / write-access ke objek komputer:

```powershell
# Objek (umumnya komputer) yang punya RBCD diset — tiap entri = principal yang boleh impersonate
Get-ADObject -LDAPFilter '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' `
  -Properties msDS-AllowedToActOnBehalfOfOtherIdentity |
  ForEach-Object {
    $acl = New-Object System.Security.AccessControl.RawSecurityDescriptor(
      $_.'msDS-AllowedToActOnBehalfOfOtherIdentity', 0)
    [PSCustomObject]@{ Target = $_.Name; AceCount = $acl.DiscretionaryAcl.Count }
  }
```

  Bersihkan RBCD tak sah dengan `Set-ADComputer <target> -Clear 'msDS-AllowedToActOnBehalfOfOtherIdentity'`.

- **Lindungi akun Tier 0** dengan atribut **"Account is sensitive and cannot be delegated"** (`userAccountControl` flag `NOT_DELEGATED` 0x100000) — mencegah akun itu pernah didelegasikan oleh layanan mana pun:

```powershell
Set-ADUser -Identity "adm-andi" -AccountNotDelegated $true
# Verifikasi
Get-ADUser "adm-andi" -Properties AccountNotDelegated | Select-Object Name, AccountNotDelegated
```

- Tambahkan akun Tier 0 ke grup **Protected Users** (efek + caveat → **Modul 01**), yang antara lain melarang delegasi dan NTLM untuk anggotanya.

### 13.1 `ms-DS-MachineAccountQuota` = 0 (tutup jalur RBCD & noPac)

**APA:** Atribut domain `ms-DS-MachineAccountQuota` (MAQ) menentukan berapa banyak akun komputer yang boleh **dibuat oleh user biasa (non-admin)**. **Defaultnya 10** — artinya setiap authenticated user dapat menambahkan hingga 10 akun komputer ke domain.

**KENAPA ini berbahaya:** kemampuan membuat akun komputer adalah prasyarat dua jalur eskalasi yang justru dibahas modul ini:

- **RBCD abuse** (Bagian 13): penyerang membuat akun komputer baru (memakai kuota MAQ), lalu — bila ia punya write-access ke `msDS-AllowedToActOnBehalfOfOtherIdentity` objek target (mis. hasil LDAP relay, Bagian 10) — menetapkan komputer barunya sebagai principal RBCD dan meng-impersonate user mana pun ke target (S4U2Proxy) → eksekusi sebagai admin.
- **noPac / sAMAccountName spoofing (CVE-2021-42278 + CVE-2021-42287)**: penyerang membuat akun komputer (MAQ>0), mengganti `sAMAccountName`-nya agar menyamai nama DC (tanpa `$`), meminta TGT, lalu setelah komputer "hilang" KDC mencocokkan ke DC asli dan menerbitkan TGS sebagai DC → privilege escalation ke Domain Admin.

Menyetel **MAQ = 0** memutus kedua rantai pada akarnya: hanya akun dengan hak eksplisit (`SeMachineAccountPrivilege`/didelegasikan) yang boleh menambah komputer.

**CARA:**

```powershell
# Audit nilai saat ini (waspada bila 10/default)
Get-ADObject -Identity (Get-ADDomain).DistinguishedName `
  -Properties ms-DS-MachineAccountQuota | Select-Object ms-DS-MachineAccountQuota

# Set MAQ = 0 (user biasa tidak bisa lagi menambah akun komputer)
Set-ADDomain -Identity "contoso.local" -Replace @{ 'ms-DS-MachineAccountQuota' = 0 }
```

> Setelah MAQ=0, join domain mesin baru dilakukan oleh akun yang **didelegasikan** hak Create Computer Object pada OU komputer (mis. lewat *Delegation of Control*), bukan oleh sembarang user. Patch DC untuk CVE-2021-42278/42287 (Bagian 2) tetap wajib — MAQ=0 adalah lapisan kedua, bukan pengganti patch.

---

## 14. AD Recycle Bin

**APA:** Fitur opsional yang memungkinkan pemulihan objek AD yang terhapus **dengan atributnya utuh** (tanpa restore otoritatif dari backup).

**KENAPA:** Penghapusan objek (tidak sengaja atau sabotase) bisa melumpuhkan operasi. Recycle Bin = recovery cepat (availability).

**CARA:**

```powershell
# Aktifkan (IRREVERSIBLE — sekali aktif tidak bisa dimatikan). Butuh FFL 2008 R2+.
Enable-ADOptionalFeature 'Recycle Bin Feature' `
  -Scope ForestOrConfigurationSet `
  -Target 'contoso.local'

# Pulihkan objek terhapus
Get-ADObject -SearchBase "CN=Deleted Objects,DC=contoso,DC=local" `
  -IncludeDeletedObjects -Filter { Name -like "*Andi*" } |
  Restore-ADObject
```

**Catatan:** Aktivasi **permanen** dan memerlukan **Forest Functional Level minimal 2008 R2**. Setelah aktif, objek yang dihapus masuk fase "deleted" (atribut dipertahankan) sebelum benar-benar tombstoned.

---

## 15. SYSVOL & GPP

**APA:** Membersihkan password yang tertanam di **Group Policy Preferences (GPP)** dan memastikan permission SYSVOL benar.

**KENAPA:** GPP dulu bisa menyimpan password (mis. set local admin password) di atribut `cpassword` dalam file XML di SYSVOL. **Kunci AES untuk dekripsi `cpassword` dipublikasikan Microsoft di MSDN** — siapa pun yang bisa baca SYSVOL (semua authenticated user) bisa mendekripsinya. Diperbaiki oleh **MS14-025**, tetapi file lama bisa tertinggal.

**CARA — temukan & hapus cpassword:**

```powershell
# Cari semua file GPP yang masih memuat cpassword
Get-ChildItem "\\contoso.local\SYSVOL\contoso.local\Policies" -Recurse -Include *.xml -ErrorAction SilentlyContinue |
  Select-String -Pattern "cpassword" |
  Select-Object Path
```

File yang biasanya terdampak: `Groups.xml`, `Services.xml`, `ScheduledTasks.xml`, `DataSources.xml`, `Printers.xml`, `Drives.xml`. Hapus/ubah GPP yang mengandung `cpassword`, dan untuk manajemen password local admin gunakan **Windows LAPS** (→ **Modul 01**).

**Permission SYSVOL:** SYSVOL direplikasi via DFSR dan dibaca semua authenticated users (perlu untuk apply GPO). Pastikan **tidak ada izin tulis** untuk non-admin pada folder Policies, dan tinjau ACL secara berkala.

---

## 16. Built-in Accounts & Sinkronisasi Waktu

**Built-in accounts:**

| Akun | Tindakan | Path |
|---|---|---|
| **Guest** | **Disabled** | `Security Options > Accounts: Guest account status` = Disabled |
| **Administrator (RID 500)** | **Rename** (defense-in-depth saja) | `Security Options > Accounts: Rename administrator account` |
| **KRBTGT** | Jangan hapus; rotasi password (Bagian 8) | — |

**Catatan kejujuran soal rename Administrator:** Rename hanya **defense-in-depth ringan**. Akun built-in administrator selalu punya **RID 500** yang tidak berubah, sehingga tool penyerang tetap bisa mengidentifikasinya lewat SID (`...-500`). Jadi rename **bukan** kontrol utama — kontrol utamanya adalah membatasi penggunaan & logon akun ini. Buat juga akun admin bernama lain dan nonaktifkan/awasi RID 500.

```powershell
# Disable Guest, verifikasi status akun built-in
Get-ADUser -Filter * -Properties Enabled |
  Where-Object { $_.SID -like "*-501" -or $_.SID -like "*-500" } |
  Select-Object Name, Enabled, SID
```

**Sinkronisasi waktu (krusial untuk Kerberos):** Kerberos menolak tiket bila selisih jam > 5 menit (Bagian 6). **PDC emulator** dari domain root adalah sumber waktu otoritatif; ia harus sinkron ke sumber eksternal andal (NTP), dan semua DC/klien lain sinkron ke hierarki domain.

```powershell
# Identifikasi PDC emulator
Get-ADDomain | Select-Object PDCEmulator

# Konfigurasi PDC emulator ke NTP eksternal
w32tm /config /manualpeerlist:"id.pool.ntp.org time.windows.com" /syncfromflags:manual /reliable:yes /update
Restart-Service w32time
w32tm /resync /rediscover

# Verifikasi status & sumber waktu
w32tm /query /status
w32tm /query /configuration
```

---

## 17. AD-integrated DNS

**APA:** Zona DNS terintegrasi AD sebaiknya hanya menerima **secure dynamic updates**.

**KENAPA:** "Nonsecure and secure" memungkinkan host mana pun menimpa record (DNS spoofing/poisoning, mendukung serangan relay/MITM). "Secure only" mensyaratkan klien terautentikasi dan ber-ACL.

**CARA:**

```powershell
# Set zona ke secure-only dynamic updates
Set-DnsServerPrimaryZone -Name "contoso.local" -DynamicUpdate "Secure"

# Verifikasi
Get-DnsServerZone -Name "contoso.local" | Select-Object ZoneName, DynamicUpdate
```

GUI: **DNS Manager > zona > Properties > General > Dynamic updates** = *Secure only*. Hardening service DNS lebih lanjut (DNS socket pool, cache locking, RRL, query resolution policy) → **Modul 04**.

---

## Serangan Umum & Mitigasi

| Serangan | MITRE ATT&CK | Cara kerja singkat | Mitigasi di modul ini |
|---|---|---|---|
| **DCSync** | T1003.006 | Akun dengan hak replikasi (Replicating Directory Changes All) memakai protokol DRSUAPI untuk menarik hash semua akun, termasuk KRBTGT. | Batasi hak replikasi ke DC saja; hygiene grup privileged (Bagian 11); audit ACL domain head; deteksi via logging (Modul 06). |
| **Kerberoasting** | T1558.003 | Minta TGS untuk akun dengan SPN, crack offline untuk dapat password service account. | Service account password panjang/PSO (Bagian 5), **gMSA** (Modul 01), matikan RC4 paksa AES (Bagian 7); enumerasi akun ber-SPN (Bagian 7.1). *FAST tidak menutup Kerberoasting (TGS exchange) — lihat catatan Bagian 6.* |
| **AS-REP Roasting** | T1558.004 | Akun dengan "Do not require Kerberos preauthentication" mengeluarkan AS-REP yang bisa di-crack offline. | Pastikan **tidak ada** akun dengan preauth dimatikan (enumerasi `DoesNotRequirePreAuth`, Bagian 7.1); password kuat; AES; FAST meng-armor AS exchange (Bagian 6). |
| **Golden Ticket** | T1558.001 | TGT palsu ditandatangani hash KRBTGT → akses penuh, lifetime sembarang. | Lindungi hash KRBTGT; **rotasi KRBTGT 2x** (Bagian 8); batasi Tier 0 (Modul 01). |
| **Silver Ticket** | T1558.002 | TGS palsu ditandatangani hash akun service/komputer → akses ke satu layanan tanpa menyentuh DC. | Password service kuat + AES; rotasi password komputer; gMSA (Modul 01). |
| **Password spraying** | T1110.003 | Coba satu password umum ke banyak akun untuk hindari lockout. | Password length/complexity (Bagian 3), lockout policy (Bagian 4), monitoring (Modul 06). |
| **LDAP / NTLM relay** | T1557 / T1557.001 | Relay autentikasi korban ke DC untuk modifikasi objek (mis. tambah RBCD, buat akun). | LDAP signing + channel binding (Bagian 10), NTLMv2 + Restrict NTLM (Bagian 9), SMB signing (Modul 04). |
| **Pass-the-Hash / Pass-the-Ticket** | T1550.002 / T1550.003 | Pakai hash/tiket curian tanpa tahu password. | NTLM hardening (Bagian 9), Protected Users & Credential Guard (Modul 01), Kerberos lifetime (Bagian 6). |
| **Unconstrained delegation abuse** | (terkait T1558/T1187) | Paksa DC autentikasi ke host unconstrained, curi TGT DC. | Audit & hapus unconstrained (Bagian 13); "Account is sensitive"; Protected Users (Modul 01). |

---

## Hardening Checklist (Modul Ini)

- [ ] DC peran minimal (AD DS + DNS), Server Core bila memungkinkan, tanpa software pihak ketiga.
- [ ] Logon ke DC dibatasi ke Tier 0 (via URA → Modul 03).
- [ ] System State backup rutin + DSRM password diset & disimpan aman.
- [ ] RODC dipakai di lokasi tak aman; akun Tier 0 tidak masuk PRP RODC.
- [ ] Password Policy: min length 14, history 24, complexity on, reversible encryption **off**.
- [ ] Max password age diputuskan sesuai sumber juri (CIS 365 / filosofi Microsoft no-expiry) dan didokumentasikan.
- [ ] Account Lockout: threshold 5–10, duration ≥15 mnt, reset counter ≤ duration, threshold **bukan 0**.
- [ ] Minimal 1 PSO ketat untuk Domain Admins (precedence unik).
- [ ] Kerberos: TGT ≤10 jam, TGS ≤600 mnt, renew ≤7 hari, clock skew ≤5 mnt.
- [ ] Kerberos Armoring (FAST) diaktifkan (DC + klien, DFL 2012+).
- [ ] AES dipaksa, RC4/DES dinonaktifkan (`msDS-SupportedEncryptionTypes`); akun diaudit lebih dulu.
- [ ] KRBTGT dirotasi 2x dengan jeda replikasi penuh; rotasi periodik dijadwalkan.
- [ ] NTLM: `LmCompatibilityLevel = 5` (NTLMv2 only), `NoLMHash = 1`, Restrict NTLM (audit → deny).
- [ ] LDAP server signing = Require, `LdapEnforceChannelBinding = 2`, LDAP client signing = Require.
- [ ] Grup privileged ramping; Schema/Enterprise Admins kosong; Account/Backup Operators kosong.
- [ ] Hak replikasi DCSync (`1131f6aa`/`1131f6ad`) pada domain head hanya milik DC/Domain Admins/Enterprise Admins; principal lain dihapus.
- [ ] AdminSDHolder ACL diaudit; orphaned `adminCount=1` ditinjau.
- [ ] Tidak ada unconstrained delegation di luar DC; constrained (`msDS-AllowedToDelegateTo`) & RBCD (`msDS-AllowedToActOnBehalfOfOtherIdentity`) diaudit; akun Tier 0 ber-`AccountNotDelegated`.
- [ ] `ms-DS-MachineAccountQuota = 0` (tutup jalur RBCD/noPac); join domain via akun terdelegasi; DC ter-patch CVE-2021-42278/42287.
- [ ] Tidak ada akun ber-`DoesNotRequirePreAuth` (AS-REP); akun USER ber-SPN diaudit & dipaksa AES (Kerberoast).
- [ ] AD Recycle Bin aktif (FFL 2008 R2+).
- [ ] SYSVOL bersih dari `cpassword`; permission SYSVOL ditinjau.
- [ ] Guest disabled; Administrator (RID 500) di-rename + dibatasi penggunaannya.
- [ ] PDC emulator sinkron ke NTP eksternal andal.
- [ ] Zona AD-integrated DNS = Secure dynamic updates only.

---

## Lab Praktik

**Prasyarat:** DC Windows Server 2022 (`contoso.local`), RSAT/AD PowerShell module, sesi sebagai Domain Admin (di host admin Tier 0). Ganti `contoso.local` dengan domain lab Anda.

**Langkah 1 — Set Password & Lockout domain policy**

1. Lakukan: jalankan perintah set policy.

```powershell
Set-ADDefaultDomainPasswordPolicy -Identity "contoso.local" `
  -MinPasswordLength 14 -PasswordHistoryCount 24 -ComplexityEnabled $true `
  -MinPasswordAge "1.00:00:00" -MaxPasswordAge "365.00:00:00" `
  -ReversibleEncryptionEnabled $false `
  -LockoutThreshold 10 -LockoutDuration "0.00:15:00" -LockoutObservationWindow "0.00:15:00"
```

2. Konfirmasi dengan:

```powershell
Get-ADDefaultDomainPasswordPolicy
```

→ Output harus menunjukkan `MinPasswordLength : 14`, `ComplexityEnabled : True`, `LockoutThreshold : 10`, `ReversibleEncryptionEnabled : False`.

**Langkah 2 — Buat 1 PSO untuk admin**

1. Lakukan: buat PSO dan assign ke Domain Admins.

```powershell
New-ADFineGrainedPasswordPolicy -Name "PSO-Admins" -Precedence 10 `
  -MinPasswordLength 20 -PasswordHistoryCount 24 -ComplexityEnabled $true `
  -MaxPasswordAge "60.00:00:00" -MinPasswordAge "1.00:00:00" `
  -LockoutThreshold 5 -LockoutDuration "0.00:30:00" -LockoutObservationWindow "0.00:30:00"
Add-ADFineGrainedPasswordPolicySubject "PSO-Admins" -Subjects "Domain Admins"
```

2. Konfirmasi dengan:

```powershell
# Pilih anggota bertipe user (hindari error bila ada grup tersarang)
$adm = Get-ADGroupMember "Domain Admins" -Recursive |
  Where-Object { $_.objectClass -eq 'user' } | Select-Object -First 1
Get-ADUserResultantPasswordPolicy -Identity $adm.SamAccountName
```

→ Output menampilkan PSO `PSO-Admins` dengan `MinPasswordLength : 20`.

**Langkah 3 — Aktifkan AD Recycle Bin**

1. Lakukan:

```powershell
Enable-ADOptionalFeature 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target 'contoso.local' -Confirm:$false
```

2. Konfirmasi dengan:

```powershell
(Get-ADOptionalFeature -Filter "Name -eq 'Recycle Bin Feature'").EnabledScopes
```

→ Output **tidak kosong** (memuat DN partition Configuration) = fitur aktif.

**Langkah 4 — Nonaktifkan RC4 (audit dulu, lalu paksa AES)**

1. Lakukan (audit): cari akun yang masih izinkan RC4.

```powershell
Get-ADObject -Filter * -Properties msDS-SupportedEncryptionTypes |
  Where-Object { $_.'msDS-SupportedEncryptionTypes' -band 0x4 } | Select-Object Name
```

2. Lakukan (paksa AES pada service account uji):

```powershell
Set-ADUser -Identity "svc-test" -Replace @{ 'msDS-SupportedEncryptionTypes' = 24 }
```

3. Konfirmasi dengan:

```powershell
Get-ADUser "svc-test" -Properties msDS-SupportedEncryptionTypes |
  Select-Object Name, msDS-SupportedEncryptionTypes
```

→ Nilai `24` (0x18 = AES128+AES256, tanpa RC4). Untuk paksa domain-wide, set Security Option via GPO (Bagian 7) → Modul 03. **Ingat:** reset password akun sebelum mematikan RC4 agar kunci AES tergenerasi.

**Langkah 5 — Audit keanggotaan Domain Admins**

1. Lakukan:

```powershell
Get-ADGroupMember -Identity "Domain Admins" -Recursive |
  Select-Object Name, SamAccountName, objectClass
```

2. Konfirmasi: bandingkan dengan daftar Tier 0 yang sah. Keluarkan akun tak sah:

```powershell
Remove-ADGroupMember -Identity "Domain Admins" -Members "user-tidak-sah" -Confirm:$false
```

→ Jalankan ulang `Get-ADGroupMember` dan pastikan hanya akun Tier 0 yang sah tersisa.

**Langkah 6 — Verifikasi NTLM, LDAP signing & FAST (hands-on, read-back)**

> Langkah ini **memverifikasi** setting yang diterapkan via GPO (Bagian 6/9/10) tanpa memutus konektivitas lab. Penegakan penuh dilakukan di GPO (→ Modul 03); di sini kita buktikan nilainya benar-benar mendarat.

1. Lakukan (jalankan di DC):

```powershell
# NTLM: hanya NTLMv2 (level 5) & tanpa LM hash
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v NoLMHash
# LDAP signing + channel binding di DC
reg query "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /v LDAPServerIntegrity
reg query "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /v LdapEnforceChannelBinding
# FAST/armoring (KDC side): EnableCbacAndArmor=1 (aktif) + CbacAndArmorLevel = tingkat
#   CbacAndArmorLevel: 0=Supported, 1=Always provide claims, 2=Fail unarmored auth requests
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters" /v EnableCbacAndArmor
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters" /v CbacAndArmorLevel
```

2. Konfirmasi: `LmCompatibilityLevel=0x5`, `NoLMHash=0x1`, `LDAPServerIntegrity=0x2`, `LdapEnforceChannelBinding` ≥ `0x1` (audit) menuju `0x2`, dan `EnableCbacAndArmor=0x1` (KDC mendukung armoring; `CbacAndArmorLevel` = 1 *Always provide claims* untuk DFL 2012 R2). Untuk rollout aman, mulai `LdapEnforceChannelBinding=1` (When supported), pantau Event 2889, baru naik ke 2 (Bagian 10).

**Langkah 7 — Audit jalur AD (roasting, MAQ, DCSync, delegasi)**

1. Lakukan (jalankan di DC/host admin):

```powershell
# Roasting (Bagian 7.1)
Get-ADUser -Filter { DoesNotRequirePreAuth -eq $true } | Select SamAccountName     # AS-REP → harus kosong
Get-ADUser -Filter { ServicePrincipalName -like '*' } -Properties ServicePrincipalName |
  Select SamAccountName, ServicePrincipalName                                       # Kerberoast → tinjau
# MachineAccountQuota (Bagian 13.1)
Get-ADObject (Get-ADDomain).DistinguishedName -Properties ms-DS-MachineAccountQuota |
  Select ms-DS-MachineAccountQuota                                                  # target: 0
# DCSync replication rights (Bagian 11.1)
$domDN=(Get-ADDomain).DistinguishedName
[guid[]]$repl='1131f6aa-9c07-11d1-f79f-00c04fc2dcd2','1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
(Get-Acl "AD:$domDN").Access |
  Where-Object { $_.ObjectType -in $repl -and $_.AccessControlType -eq 'Allow' } |
  Select IdentityReference                                                          # hanya DC/DA/EA
# Delegasi (Bagian 13)
Get-ADObject -LDAPFilter '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' | Select Name   # RBCD tak sah?
```

2. Konfirmasi: AS-REP kosong; MAQ=0; daftar DCSync hanya principal default; tidak ada RBCD tak sah. Bila ada temuan, perbaiki sesuai Bagian 7.1/11.1/13/13.1.

---

## Perintah Audit/Verifikasi

Semua perintah berikut dijamin dapat dijalankan untuk membuktikan setting aktif (output yang diharapkan disebutkan). Untuk korelasi **Event ID** (mis. 4740 lockout, 2889 LDAP unsigned bind, 4768/4769 Kerberos), lihat **Modul 06** sebagai pemilik daftar Event ID.

```powershell
# 1. Password & lockout policy domain
Get-ADDefaultDomainPasswordPolicy
# Harapkan: MinPasswordLength=14, ComplexityEnabled=True, ReversibleEncryptionEnabled=False, LockoutThreshold=10

# 2. Daftar PSO & precedence
Get-ADFineGrainedPasswordPolicy -Filter * | Select-Object Name, Precedence, MinPasswordLength
# Harapkan: PSO-Admins, Precedence 10, MinPasswordLength 20

# 3. AD Recycle Bin aktif
(Get-ADOptionalFeature -Filter "Name -eq 'Recycle Bin Feature'").EnabledScopes
# Harapkan: tidak kosong (DN Configuration partition)

# 4. Akun yang masih izinkan RC4 (idealnya minimal/none)
Get-ADObject -Filter * -Properties msDS-SupportedEncryptionTypes |
  Where-Object { $_.'msDS-SupportedEncryptionTypes' -band 0x4 } | Select-Object Name
# Harapkan: kosong setelah penegakan AES

# 5. NTLM & LDAP registry (jalankan di DC)
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel
# Harapkan: 0x5
reg query "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /v LDAPServerIntegrity
# Harapkan: 0x2
reg query "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /v LdapEnforceChannelBinding
# Harapkan: 0x2

# 6. KRBTGT terakhir di-rotasi
Get-ADUser krbtgt -Properties PasswordLastSet | Select-Object Name, PasswordLastSet
# Harapkan: tanggal baru (sesudah rotasi 2x)

# 7. Unconstrained delegation di luar DC (harus kosong)
Get-ADComputer -Filter { TrustedForDelegation -eq $true } -Properties TrustedForDelegation |
  Where-Object { $_.Name -notin (Get-ADDomainController -Filter *).Name } | Select-Object Name
# Harapkan: kosong

# 8. Guest disabled & built-in admin status
Get-ADUser -Filter * -Properties Enabled |
  Where-Object { $_.SID -like "*-501" -or $_.SID -like "*-500" } |
  Select-Object Name, Enabled, SID
# Harapkan: RID 501 (Guest) Enabled=False

# 9. DNS secure dynamic updates
Get-DnsServerZone -Name "contoso.local" | Select-Object ZoneName, DynamicUpdate
# Harapkan: DynamicUpdate=Secure

# 10. Sinkronisasi waktu PDC
w32tm /query /status
# Harapkan: Source = NTP eksternal, Stratum rendah, tanpa error skew besar
```

---

## Referensi

- **Microsoft Security Baselines** — Security Compliance Toolkit (SCT), baseline Windows Server 2022 & Windows 11 (nilai password, lockout, Kerberos, NTLM, LDAP). Penerapan baseline via LGPO.exe/Policy Analyzer → **Modul 03**.
- **CIS Microsoft Windows Server 2022 Benchmark** & **CIS Windows 11 Enterprise Benchmark** (Level 1/2) — anchor numerik password/lockout/Kerberos.
- **Microsoft Learn:**
  - "Password policy recommendations" & "Minimum password length audit".
  - "Maximum password age" / NIST SP 800-63B (rasional penghapusan ekspirasi).
  - "AD Forest Recovery — Resetting the krbtgt password".
  - "Domain controller: LDAP server signing requirements" & "LDAP channel binding and LDAP signing (ADV190023)".
  - "Network security: LAN Manager authentication level" & "Restricting NTLM".
  - "Configure encryption types allowed for Kerberos" (`msDS-SupportedEncryptionTypes`).
  - "AdminSDHolder, Protected Groups and SDPROP".
  - "How the Active Directory Recycle Bin works" (`Enable-ADOptionalFeature`).
- **MS14-025** — Vulnerability in Group Policy Preferences (cpassword).
- **NIST SP 800-63B** — Digital Identity Guidelines (kebijakan password modern).
- **MITRE ATT&CK** — T1003.006 (DCSync), T1558.001–.004 (Kerberos abuse), T1110.003 (password spraying), T1557.001 (relay), T1550.002/.003 (PtH/PtT).

> Lihat juga: **Modul 01** (PAM, Tier 0, Windows LAPS, Protected Users, gMSA, Credential Guard), **Modul 03** (GPO: link/scoping, URA, Security Options, SCT/LGPO), **Modul 04** (network, SMB/LDAP transport, DNS service hardening), **Modul 06** (Advanced Audit Policy, Event ID, logging).
