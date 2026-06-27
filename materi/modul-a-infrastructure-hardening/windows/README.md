# Paket Materi Windows Hardening — LKS Cyber Security

> Indeks dan peta navigasi untuk enam modul hardening Windows yang dipakai pada persiapan lomba **LKS (Lomba Kompetensi Siswa) bidang Cyber Security**. Tujuan paket ini: membangun kemampuan **mengeraskan (harden)** infrastruktur Windows berbasis Active Directory dari sudut pandang **blue team** — menutup jalur serangan klasik (Pass-the-Hash, LLMNR poisoning, Kerberoasting, ransomware, log clearing, dan sejenisnya) lewat konfigurasi yang dapat diuji dan diverifikasi.
>
> **Referensi latihan (WSA 2025):** skenario hardening **Windows / Active Directory** nyata + **VM**, arsip & slide *Network Hardening* dari **WorldSkills ASEAN 2025**, dipetakan ke modul-modul di bawah. Lihat [Latihan WSA 2025](../../latihan-wsa-2025/README.md).

## Tujuan & Konteks

Setiap modul disusun dengan pola **APA → KENAPA → CARA**, dilengkapi tabel **Serangan Umum & Mitigasi** (dipetakan ke MITRE ATT&CK), **Hardening Checklist**, **Lab Praktik**, dan **Perintah Audit/Verifikasi**. Filosofi yang dipegang di seluruh paket:

- **Assume breach** — anggap satu host sudah dikuasai; desain agar kompromi tidak menyebar.
- **Least privilege & defense-in-depth** — hak seminimal mungkin, berlapis.
- **Anchor numerik tunggal** — semua angka (panjang password, ukuran log, dll.) diankor ke **Microsoft Security Baseline** dan **CIS Benchmark**, bukan dikarang. Bila dua sumber berbeda, tampilkan keduanya beserta sumbernya.
- **Audit dulu, baru enforce** — kontrol berisiko lockout (ASR, NTLM/LDAP, AppLocker, Auth Silo) selalu diuji di mode audit sebelum diberlakukan.

Materi ini ditulis untuk **lingkungan lab / sistem dengan izin eksplisit**. Lihat [Cara Pakai & Etika](#cara-pakai-saat-latihan--lomba) sebelum menjalankan perintah apa pun.

---

## Asumsi Build

| Komponen | Asumsi default materi |
|---|---|
| **Domain Controller** | Windows Server 2022 (AD DS + DNS), nama domain lab contoh `lks.local` / `contoso.local` / `corp.local` |
| **Client / endpoint** | Windows 10 / Windows 11 (member domain) |
| **Attacker (lab)** | Kali/Linux untuk Responder, nmap, dan tooling uji (hanya pada Lab Praktik Modul 04/06) |
| **Tooling admin** | RSAT / modul PowerShell `ActiveDirectory`, `GroupPolicy`, `LAPS`, Defender cmdlets, Sysinternals |
| **Functional level** | Sebagian fitur menuntut DFL/FFL tertentu (PSO 2008+, AD Recycle Bin 2008 R2+, Kerberos armoring 2012+, LAPS encryption 2016+, PAM/JIT forest 2016) |

### Unduh OS untuk Lab (Gratis & Legal)

Semua OS untuk lab tersedia gratis sebagai **Evaluation** (fitur penuh, hanya dibatasi waktu) di **[Microsoft Evaluation Center](https://www.microsoft.com/en-us/evalcenter)**:

| OS | Unduh | Masa eval | Catatan |
|---|---|---|---|
| **Windows Server 2025** (Eval) | <https://www.microsoft.com/en-us/evalcenter/download-windows-server-2025> | ±180 hari | Rilis terbaru; **SMB signing & sebagian kontrol sudah default-on** (lihat *Catatan Delta Versi*). |
| **Windows Server 2022** (Eval) | Cari "Windows Server 2022" di [Evaluation Center](https://www.microsoft.com/en-us/evalcenter) | ±180 hari | **Default materi ini** — paling cocok bila panitia LKS memakai Server 2022. |
| **Windows 11 / 10 Enterprise** (Eval) | Cari "Windows 11 Enterprise" di [Evaluation Center](https://www.microsoft.com/en-us/evalcenter) | ±90 hari | Client untuk *join domain* & uji GPO / Windows LAPS / Defender. |

> - Pilih **Desktop Experience** (bukan *Server Core*) agar bisa latihan GUI: GPMC, `gpedit.msc`, Event Viewer, Windows Security.
> - Promosikan jadi DC: `Install-ADDSForest -DomainName lks.local`. **Snapshot VM** dulu sebelum hardening (banyak setting berisiko lockout).
> - Perpanjang masa eval bila habis: `slmgr /rearm` lalu reboot (cek sisa hari dengan `slmgr /dlv`).
> - Tooling gratis pendukung: **RSAT** (modul PowerShell `ActiveDirectory`/`GroupPolicy`), **Microsoft Security Compliance Toolkit** (LGPO.exe + Policy Analyzer — Modul 03), **Sysmon** (Modul 06), file uji **EICAR** (Modul 05). Mesin penyerang: **Kali Linux** (gratis).

### Catatan Delta Versi

Banyak setting kini **default-on** di build modern; tetap **verifikasi** karena fresh-install vs upgrade dan edisi (Pro/Enterprise) berbeda. Ringkasan delta yang tersebar di seluruh modul:

| Area | Delta versi | Modul |
|---|---|---|
| **Password length > 14** | `RelaxMinimumPasswordLengthLimits` (naik s/d 128 char) + "Minimum password length audit" tersedia sejak Win10 2004 / Server 2022 | 02 |
| **Account lockout default** | Fresh install Win11 22H2 / Server 2022 sudah punya lockout bawaan **10/10/10** + "Allow Administrator account lockout" aktif | 02, 04 |
| **Windows LAPS** | Built-in OS sejak **April 2023** (Win10/11, Server 2019/2022) — tidak perlu MSI legacy `AdmPwd` | 01 |
| **Credential Guard** | Default-on hanya di **Win11 22H2+ edisi Enterprise** pada hardware yang memenuhi syarat; bukan default di Server | 01 |
| **SMBv1** | Tidak terinstal default sejak Win10 1709 / Server 2019 | 04 |
| **SMB signing** | Wajib default sejak **Win11 24H2 / Server 2025**; di Server 2022 harus dipaksa eksplisit | 04 |
| **Insecure guest logon** | Diblokir default sejak Win10 1709 (Enterprise/Education) & Win11 | 04 |
| **TLS 1.0/1.1** | Disabled by default di Win11 & update Server 2022 terbaru | 04 |
| **Defender** | Engine aktif default sejak Server 2016, tapi **GUI** hanya default di Server 2022 (Server 2016 perlu `Windows-Defender-Gui`); Win11 menambah Enhanced Phishing Protection | 05 |

---

## Daftar Modul & Peta Kepemilikan (Ownership Map)

Modul-modul ini ditulis dengan **kepemilikan materi yang tegas**: satu topik dimiliki satu modul, modul lain hanya menunjuk ("→ lihat Modul X"). Gunakan kolom **Dimiliki modul ini** untuk tahu ke mana mencari sumber kebenaran sebuah topik.

| # | Modul | Ringkas | Dimiliki modul ini (ownership) |
|---|---|---|---|
| 01 | [Privileged Access Management (PAM)](01-privileged-access-management.md) | Lindungi identitas berhak istimewa agar kompromi satu host tidak jadi kompromi domain. | Tiering / Enterprise Access Model, PAW, Protected Users, Authentication Policy Silos, **Windows LAPS**, JIT/TTL membership, JEA, gMSA, breakglass, **Credential Guard** & Remote Credential Guard / Restricted Admin |
| 02 | [Konfigurasi Keamanan Dasar Active Directory](02-active-directory-security.md) | Eraskan fondasi AD: password, Kerberos, NTLM, LDAP, delegasi, dan grup istimewa. | **Nilai** Password/Lockout/Kerberos policy, PSO, AES/RC4, rotasi **KRBTGT**, NTLM hardening, **LDAP signing & channel binding**, hygiene grup privileged, AdminSDHolder, delegation, AD Recycle Bin, SYSVOL/GPP `cpassword`, built-in accounts & sinkronisasi waktu, AD-integrated DNS |
| 03 | [GPO — Local & Active Directory Policy](03-gpo-policy.md) | Mesin pengiriman semua kebijakan: buat, scope, proses, verifikasi GPO. | **Mekanisme GPO** (LSDOU, link/filter, loopback, `gpupdate`/`gpresult`/RSoP), Central Store ADMX, **URA**, **Security Options** & UAC, **SCT** (LGPO.exe, Policy Analyzer), mekanisme **AppLocker & WDAC** |
| 04 | [Network Service Security](04-network-service-security.md) | Kurangi attack surface jaringan: firewall, SMB, RDP, resolusi nama, protokol legacy. | Windows Defender Firewall, **SMB hardening**, RDP transport (NLA/TLS), **LLMNR/NBT-NS/mDNS/WPAD**, WinRM, disable service tak terpakai, legacy protocol & weak cipher (SCHANNEL/TLS), **disable PSv2**, **DNS service security**, IPsec/Domain Isolation |
| 05 | [Antivirus — Microsoft Defender Antivirus & EDR](05-antivirus-defender.md) | Pastikan semua lapisan Defender aktif & anti-tamper sebelum payload jalan. | Defender AV (RTP/behavior/cloud/BAFS), PUA, **ASR rules**, Controlled Folder Access, Network Protection, **Tamper Protection**, exclusions, Exploit Protection, SmartScreen, **AMSI**, Defender for Endpoint (EDR) |
| 06 | [Logging & Auditing](06-logging-auditing.md) | Mata & telinga sistem: aktifkan audit granular, sentralisasi log, baca Event ID. | **Advanced Audit Policy**, **daftar Event ID**, command-line auditing (4688), **PowerShell logging**, **Sysmon**, **WEF/WEC**, ukuran/retensi/integritas log, sinkronisasi waktu untuk korelasi |

---

## Urutan Belajar yang Disarankan

Ikuti **urutan numerik 01 → 06**. Modul memang ditulis untuk dibaca berurutan: Modul 01–02 membangun model ancaman + fondasi identitas yang diasumsikan modul-modul berikutnya, lalu pertahanan bergerak keluar dari identitas ke jaringan, endpoint, dan akhirnya visibilitas.

1. **Modul 01 — PAM** → kerangka berpikir (assume breach, tiering, Tier 0). Pondasi *kenapa*.
2. **Modul 02 — AD Security** → nilai keras fondasi domain (password, Kerberos, NTLM, LDAP).
3. **Modul 03 — GPO** → mekanisme yang mengirim semua kebijakan ke host.
4. **Modul 04 — Network** → tutup permukaan serang jaringan & protokol legacy.
5. **Modul 05 — Defender** → pertahanan endpoint & anti-tamper.
6. **Modul 06 — Logging** → deteksi & forensik; ditaruh terakhir karena dipakai untuk **memverifikasi** semua kontrol sebelumnya benar-benar bekerja.

> **Catatan praktik:** **Modul 03 memiliki mekanisme GPO** yang dirujuk oleh Modul 01/02/04/05/06 ("terapkan via GPO → lihat Modul 03"). Sebelum **Lab Praktik** pertama, buka Modul 03 dan kuasai dulu mekanika link/scope/security filtering serta `gpupdate` & `gpresult` — buat ia tetap terbuka sebagai referensi saat mengerjakan lab modul lain.

---

## Peta Serangan → Modul

Teknik penyerang umum dan modul yang **memitigasinya**. Untuk mitigasi yang sah merentang beberapa modul (mis. credential dumping), semua modul terkait ditampilkan — ini memperkuat cerita kepemilikan.

| Teknik penyerang | MITRE ATT&CK | Modul yang memitigasi |
|---|---|---|
| **Pass-the-Hash** | T1550.002 | 01 (LAPS, Protected Users, Credential Guard) · 02 (NTLM hardening) |
| **Pass-the-Ticket** | T1550.003 | 01 (Protected Users AES-only, Auth Silo) · 02 (Kerberos lifetime) |
| **LLMNR / NBT-NS poisoning (Responder)** | T1557.001 | 04 (matikan LLMNR/NBT-NS/mDNS/WPAD) |
| **NTLM / SMB relay** | T1557.001 | 02 (LDAP signing + channel binding, Restrict NTLM) · 04 (SMB signing) |
| **Forced authentication (PetitPotam)** | T1187 | 04 (SMB signing) · 02 (LDAP signing, batasi anonim) |
| **Kerberoasting** | T1558.003 | 01 (gMSA) · 02 (matikan RC4 / paksa AES, PSO, armoring) |
| **AS-REP Roasting** | T1558.004 | 02 (cegah akun tanpa pre-auth, AES) |
| **Golden Ticket** | T1558.001 | 02 (rotasi KRBTGT 2x) · 01 (lindungi Tier 0) |
| **Silver Ticket** | T1558.002 | 02 (password service + AES) · 01 (gMSA) |
| **DCSync** | T1003.006 | 02 (hygiene grup, batasi hak replikasi) · 01 (tiering) · 06 (deteksi Event 4662) |
| **Credential dumping LSASS** | T1003.001 | 01 (Credential Guard) · 03 (`RunAsPPL`, batasi `SeDebugPrivilege`) · 05 (ASR LSASS) · 06 (Sysmon Event 10) |
| **Credential dumping SAM** | T1003.002 | 01 (Windows LAPS — password local admin unik per host) |
| **Ransomware (enkripsi massal)** | T1486 | 05 (Controlled Folder Access, ASR ransomware) · 03 (AppLocker/WDAC) |
| **EternalBlue** | T1210 | 04 (hapus SMBv1) |
| **BlueKeep (RDP pra-auth)** | T1210 | 04 (NLA wajib, TLS, firewall scope) |
| **PrintNightmare** | T1210 / T1068 | 04 (disable Print Spooler di DC) |
| **RDP brute force** | T1110 / T1021.001 | 04 (batasi user, RD Gateway, scope) · 02 (account lockout) |
| **Password spraying** | T1110.003 | 02 (password/lockout policy) · 06 (deteksi 4625/4776) |
| **GPO modification** | T1484.001 | 03 (delegasi minimal, backup, GPO Tier 0) · 06 (deteksi perubahan) |
| **`cpassword` di SYSVOL** | T1552.006 | 02 / 03 (bersihkan XML lama) · 01 (ganti dengan Windows LAPS) |
| **AMSI bypass** | T1562.001 / T1059.001 | 05 (AMSI) · 03 (Constrained Language Mode + WDAC) · 06 (Script Block Logging) |
| **PowerShell ter-obfuscate / encoded** | T1059.001 | 06 (Script Block Logging 4104) · 04 (disable PSv2) |
| **PsExec / WMI lateral movement** | T1569.002 / T1047 | 05 (ASR PsExec/WMI — uji Audit dulu) |
| **BYOVD (driver rentan)** | T1068 | 05 (ASR block vulnerable signed drivers) |
| **Disable / impair AV** | T1562.001 | 05 (Tamper Protection) · 06 (alert 4719) |
| **Log clearing** | T1070.001 | 06 (WEF off-host, alert pada 1102 / 104) |
| **Exfil / infeksi via USB** | T1052 / T1091 | 03 (deny removable storage) · 05 (ASR USB) · 06 (audit PnP 6416) |
| **DNS cache poisoning / amplification** | T1498 | 04 (disable recursion, cache locking, RRL, socket pool) |

---

## Cara Pakai Saat Latihan / Lomba

1. **Snapshot dulu.** Ambil snapshot VM lab sebelum mengubah apa pun — banyak setting berisiko lockout atau memutus layanan.
2. **Audit → verifikasi → enforce.** Selalu mulai di mode audit/non-enforce untuk kontrol yang bisa mematahkan akses, lalu naikkan ke enforce setelah memverifikasi tidak ada yang rusak:
   - ASR rules (`AuditMode` → `Enabled`), Controlled Folder Access, Network Protection (Modul 05)
   - AppLocker (`Audit only` → `Enforce`) (Modul 03)
   - NTLM Restrict & LDAP channel binding (`Audit`/`When supported` → `Deny`/`Always`) (Modul 02)
   - Authentication Policy Silo (tanpa `-Enforce` dulu) (Modul 01)
   - Nonaktifkan RC4: **reset password akun** dulu agar kunci AES tergenerasi (Modul 02)
3. **Pakai blok "Perintah Audit/Verifikasi" sebagai scorecard.** Tiap modul menutup dengan perintah PowerShell/cmd yang menyebutkan **output yang diharapkan**. Jadikan ini checklist pembuktian bahwa setiap kontrol benar-benar aktif.
4. **Waspadai toggle yang tidak bisa dibatalkan:** mengaktifkan **PAM optional feature** (JIT, Modul 01) dan **AD Recycle Bin** (Modul 02) bersifat **permanen** — pahami sebelum dijalankan di forest lomba.
5. **Jaga akun darurat.** Siapkan breakglass dan **jangan** masukkan ke Protected Users / Auth Silo (Modul 01) agar tidak mengunci diri sendiri saat kontrol diperketat.
6. **Verifikasi penerapan GPO** dengan `gpresult /h` dan `rsop.msc` (Modul 03) sebelum menganggap setting "selesai".

### Catatan Etika

- Materi ini **hanya** untuk lab pribadi, lingkungan kompetisi, atau sistem dengan **izin tertulis eksplisit**. Tool ofensif (Responder, nmap, Mimikatz, EICAR/AMSI test) di Lab Praktik dipakai **untuk menguji pertahanan sendiri**, bukan menyerang sistem lain.
- Perintah destruktif/berisiko diberi peringatan di materi — mis. clear log (`wevtutil cl Security`) di Modul 06 ditandai **"JANGAN di production tanpa izin"**, dan menonaktifkan RC4/NTLM forest-wide bisa memutus trust & sistem legacy.
- Hormati aturan lomba: hardening, bukan sabotase. Jangan menonaktifkan kontrol yang dinilai juri demi "kemenangan" yang justru melemahkan postur keamanan.

---

## Sumber Rujukan Utama

Seluruh modul mengankor angka dan setting ke sumber otoritatif berikut:

- **Microsoft Security Baseline** (Windows Server 2022 & Windows 11) — bagian dari **Microsoft Security Compliance Toolkit (SCT)**: **Security Baselines** (GPO backup), **Policy Analyzer** (bandingkan baseline vs kebijakan efektif), **LGPO.exe** (terapkan baseline ke Local GPO mesin standalone), **SetObjectSecurity.exe**.
- **CIS Benchmarks** — *CIS Microsoft Windows Server 2022 Benchmark* & *CIS Microsoft Windows 11 Enterprise Benchmark* (Level 1/2): rujukan tunggal nilai numerik & registry (password, lockout, Kerberos, ukuran log, ASR, firewall logging).
- **Microsoft Learn** — dokumentasi resmi per-topik (Windows LAPS, Protected Users, JEA, gMSA, Credential Guard, AD Forest Recovery / KRBTGT, LDAP signing, AppLocker/WDAC, Defender ASR reference, Advanced Audit Policy, WEF).
- **MITRE ATT&CK** ([attack.mitre.org](https://attack.mitre.org)) — pemetaan teknik (T1003, T1550, T1557, T1558, T1110, T1484, T1486, T1562, T1070, dan lainnya).
- Rujukan tambahan: **NIST SP 800-63B** (kebijakan password modern), **MS14-025** (GPP `cpassword`), dan konfigurasi **Sysmon** komunitas (SwiftOnSecurity `sysmon-config`, Olaf Hartong `sysmon-modular`).

> Selalu cek ulang nilai numerik ke teks benchmark/baseline versi terbaru sebelum dipakai di lomba — bila juri memakai CIS, ikuti CIS; bila memakai filosofi Microsoft Baseline, dokumentasikan pilihannya.
