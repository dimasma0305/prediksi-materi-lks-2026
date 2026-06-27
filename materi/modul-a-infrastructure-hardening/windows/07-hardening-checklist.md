# Modul 07 — Hardening Checklist Konsolidasi (Runbook Tempur LKS)

> Runbook ini menggabungkan seluruh bagian **"Hardening Checklist (Modul Ini)"** dari Modul 01–06 menjadi satu daftar berurutan yang siap dieksekusi saat lomba. Pakai **Tabel Urutan Eksekusi** untuk tahu mulai dari mana ketika waktu terbatas, lalu kerjakan tiap area mengikuti dua tingkat prioritas: **Quick wins / Kritis** (risiko rendah, nilai tinggi, kerjakan duluan) dan **Lanjutan** (butuh uji bertahap, dependensi, atau cakupan luas).

## Cara Pakai

- **Tiap item** = checkbox + aksi singkat + perintah/lokasi + satu baris **`Verifikasi:`** untuk membuktikan setting benar-benar aktif.
- **Perintah dijaga asli** persis seperti di modul sumber. Ganti placeholder domain/OU (`lks.local`, `contoso.local`, `corp.local`, `lab.local`, `WKS-01`, dst.) dengan nilai lab Anda.
- Tanda **(DC)** = hanya relevan/diverifikasi di Domain Controller — jangan jalankan verifikasinya di member server/klien.
- Item yang setting-nya "dimiliki" modul lain ditandai dengan pointer `-> Modul 0X` agar tidak dikerjakan dua kali.
- Prinsip berulang sepanjang runbook: **audit dulu, baru enforce** (NTLM, RC4, ASR, AppLocker) dan **aktifkan logging lebih dulu** supaya semua perubahan berikutnya terekam.

---

## Tabel Urutan Eksekusi Saat Lomba

| # | Area | Aksi inti (klaster) | Alasan urutan |
|---|------|---------------------|----------------|
| 1 | Semua | Snapshot kondisi awal: `gpresult /h C:\before.html /f`, `Get-MpComputerStatus`, `auditpol /get /category:*`, `Get-NetFirewallProfile` | Tahu baseline & punya bukti "before". |
| 2 | Logging | Force subcategory (`SCENoApplyLegacyAuditPolicy`) **lalu** Advanced Audit Policy + 4688 command line | Aktifkan deteksi dulu agar perubahan berikutnya tercatat; force-subcategory wajib sebelum subkategori. |
| 3 | Logging | PowerShell Script Block + Module + Transcription logging | Tangkap aktivitas PowerShell sejak awal. |
| 4 | Network | Nonaktifkan PowerShell v2 engine | Tutup bypass logging/AMSI sebelum hardening lain. |
| 5 | AV | Pastikan Defender on, `Update-MpSignature`, Tamper Protection On | Pertahanan endpoint + anti-tamper sebelum manuver lain. |
| 6 | AV | Cloud High + PUA + BAFS + Network Protection; ASR & CFA mulai **AuditMode** | Quick win; audit-before-block agar app sah tidak putus. |
| 7 | Network | Firewall 3 profile **On** + Inbound **Block** + logging dropped | Kurangi attack surface jaringan segera. |
| 8 | Network | Matikan LLMNR / NBT-NS / mDNS + WPAD | Hentikan pencurian NetNTLM (Responder) — risiko rendah. |
| 9 | Network | SMBv1 off + SMB signing on; RDP NLA+TLS+High; Print Spooler off (DC); service tak terpakai off | Tutup EternalBlue / relay / BlueKeep / PrintNightmare. |
| 10 | AD | Password & Lockout policy + 1 PSO admin; Guest disabled; Administrator rename | Dasar akun, risiko rendah. |
| 11 | AD | Kerberos policy (TGT/TGS/skew/renew) + Kerberos Armoring (FAST) | Persempit jendela penyalahgunaan tiket. |
| 12 | AD | NTLM (audit→deny), LDAP signing+CBT, AES (audit→enforce, RC4 off) | Audit dulu agar layanan sah tidak putus; reset password sebelum matikan RC4. |
| 13 | AD | AD Recycle Bin, SYSVOL `cpassword` bersih, hygiene grup, AdminSDHolder, delegasi, sinkronisasi waktu PDC | Kebersihan direktori & kemampuan pemulihan. |
| 14 | AD | Rotasi KRBTGT **2x** dengan jeda replikasi penuh | Lakukan setelah replikasi sehat; jeda wajib antar reset. |
| 15 | PAM | OU tiering + URA tier separation (-> Modul 03) | Fondasi isolasi tier sebelum kontrol PAM lain. |
| 16 | PAM | Protected Users (uji 1 akun), Auth Silo, Credential Guard + Remote Credential Guard | Lindungi kredensial Tier 0; uji bertahap hindari lockout. |
| 17 | PAM | Windows LAPS: schema extend → self-permission → GPO → ambil password | Schema extend wajib lebih dulu. |
| 18 | PAM | PAM TTL feature, JEA endpoint, gMSA (KDS root key dulu), breakglass | Hapus standing access; KDS root key prasyarat gMSA. |
| 19 | GPO | Central Store, import baseline MS, Enforced, filtering MS16-072, loopback, Security Options/UAC/RunAsPPL, AppLocker (audit→enforce), removable storage | Terapkan baseline & application control terpusat. |
| 20 | GPO | `Backup-GPO -All` + audit delegasi GPO | Change control & lindungi GPO sebagai aset Tier 0. |
| 21 | Logging | Sysmon + naikkan ukuran log + WEF/WEC + alert 1102/4719 + batasi akses Security log | Sentralisasi & integritas log di luar jangkauan attacker. |
| 22 | Semua | Sweep verifikasi akhir: jalankan ulang one-liner tiap area + `gpresult /h C:\after.html /f` | Buktikan setiap setting aktif untuk penilaian. |

---

## 1. PAM — Privileged Access Management

`-> detail Modul 01 (01-privileged-access-management.md)`

### Quick wins / Kritis

- [ ] **Bangun struktur OU tiering** (Tier 0/1/2: Accounts/Groups/Devices) terlindungi dari penghapusan. Jalankan skrip OU Modul 01 §2.
  Verifikasi: `Get-ADOrganizationalUnit -Filter * -SearchBase "OU=Admin,DC=lks,DC=local" | Select Name`
- [ ] **URA logon-restriction lintas-tier** agar akun tier tidak bisa logon silang. Setting mekanisme `-> Modul 03` (GPO area, URA tier separation).
  Verifikasi: `secedit /export /cfg C:\eff.inf` (periksa `[Privilege Rights]` → `SeDenyNetworkLogonRight`, `SeDenyRemoteInteractiveLogonRight`)
- [ ] **Built-in Administrator di-rename/disable** & **standing Domain/Enterprise/Schema Admins dikosongkan** (pakai JIT/TTL). `Disable-LocalUser -Name "Administrator"` / Security Options.
  Verifikasi: `Get-ADGroupMember "Domain Admins" | Select-Object SamAccountName` (hanya breakglass + akun JIT sementara)
- [ ] **Akun breakglass** dibuat, password panjang offline, dimonitor; **tidak** dimasukkan Protected Users/Silo.
  Verifikasi: `Get-ADGroupMember -Identity "Protected Users" | Select-Object SamAccountName` (akun breakglass TIDAK boleh muncul)

### Lanjutan

- [ ] **Akun admin bernilai tinggi masuk `Protected Users`** (uji satu akun dulu; tanpa breakglass/akun NTLM-dependent). `Add-ADGroupMember -Identity "Protected Users" -Members "t0-admin01"`.
  Verifikasi: `Get-ADGroupMember -Identity "Protected Users" | Select-Object SamAccountName`
- [ ] **Authentication Policy Silo** membatasi akun Tier 0 hanya logon dari DC/PAW Tier 0 (uji mode audit dulu, lalu `-Enforce`).
  Verifikasi: `Get-ADAuthenticationPolicySilo -Filter * | Select-Object Name,Enforce`
- [ ] **PAW Tier 0** disiapkan (tanpa email/browsing umum) dengan **Credential Guard aktif** di atasnya.
  Verifikasi: `(Get-CimInstance -ClassName Win32_DeviceGuard -Namespace 'root\Microsoft\Windows\DeviceGuard').SecurityServicesRunning` (koleksi memuat nilai 1)
- [ ] **Credential Guard (Enabled with UEFI lock)** + **Remote Credential Guard / Restricted Admin** untuk RDP. GPO Device Guard / `LsaCfgFlags`.
  Verifikasi: `reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LsaCfgFlags` (0x1 = UEFI lock, 0x2 = tanpa lock)
- [ ] **Windows LAPS**: schema di-extend (`Update-LapsADSchema`), self-permission diset, GPO aktif, password terambil & terenkripsi (DFL 2016+).
  Verifikasi: `Get-LapsADPassword -Identity "WKS-01"` (berisi Account, Password/terenkripsi, ExpirationTimestamp di masa depan)
- [ ] **PAM optional feature aktif** (forest 2016) & keanggotaan grup berhak via **TTL**, bukan permanen.
  Verifikasi: `Get-ADOptionalFeature -Filter {Name -like 'Privileged*'} | Select-Object Name,EnabledScopes` (EnabledScopes terisi)
  Verifikasi TTL: `Get-ADGroup "Tier 1 Server Admins" -Property member -ShowMemberTimeToLive` (anggota tampil dengan `<TTL=...>`)
- [ ] **Minimal satu JEA endpoint constrained** (`RestrictedRemoteServer` + `RunAsVirtualAccount`) untuk operator.
  Verifikasi: `Get-PSSessionConfiguration -Name OpsEndpoint | Select-Object Name,RunAsVirtualAccount` (RunAsVirtualAccount=True)
- [ ] **Service account berhak diganti gMSA** (KDS root key dibuat lebih dulu).
  Verifikasi: `Test-ADServiceAccount -Identity "gmsa-web01"` (harus True)

---

## 2. AD — Konfigurasi Keamanan Dasar Active Directory

`-> detail Modul 02 (02-active-directory-security.md)`

### Quick wins / Kritis

- [ ] **Password Policy**: min length 14, history 24, complexity on, reversible encryption **off**. `Set-ADDefaultDomainPasswordPolicy`.
  Verifikasi: `Get-ADDefaultDomainPasswordPolicy` (MinPasswordLength=14, ComplexityEnabled=True, ReversibleEncryptionEnabled=False)
- [ ] **Max password age** diputuskan sesuai sumber juri (CIS 365 / filosofi Microsoft no-expiry) dan **didokumentasikan**.
  Verifikasi: `Get-ADDefaultDomainPasswordPolicy | Select MaxPasswordAge`
- [ ] **Account Lockout**: threshold 5–10, duration ≥15 mnt, reset counter ≤ duration, threshold **bukan 0**.
  Verifikasi: `Get-ADDefaultDomainPasswordPolicy | Select LockoutThreshold,LockoutDuration,LockoutObservationWindow`
- [ ] **Guest disabled**; **Administrator (RID 500) di-rename** + dibatasi penggunaannya.
  Verifikasi: `Get-ADUser -Filter * -Properties Enabled | Where-Object { $_.SID -like "*-501" -or $_.SID -like "*-500" } | Select-Object Name,Enabled,SID`
- [ ] **`ms-DS-MachineAccountQuota = 0`** — cegah user biasa membuat computer account; menutup jalur **RBCD / noPac / mitm6-relay-ke-LDAP** (-> Modul 02). `Set-ADDomain -Identity lks.local -Replace @{"ms-DS-MachineAccountQuota"="0"}`.
  Verifikasi: `Get-ADObject (Get-ADDomain).DistinguishedName -Properties ms-DS-MachineAccountQuota | Select-Object ms-DS-MachineAccountQuota` (0)
- [ ] **(DC) Logon ke DC dibatasi ke Tier 0** via URA. Setting mekanisme `-> Modul 03`.
  Verifikasi: `secedit /export /cfg C:\eff.inf` (periksa `[Privilege Rights]` → `SeInteractiveLogonRight`, `SeDenyRemoteInteractiveLogonRight`)
- [ ] **(DC) Peran minimal** (AD DS + DNS), Server Core bila memungkinkan, tanpa software pihak ketiga.
  Verifikasi: `Get-WindowsFeature | Where-Object Installed | Select-Object Name`

### Lanjutan

- [ ] **Minimal 1 PSO ketat** untuk Domain Admins (precedence unik). `New-ADFineGrainedPasswordPolicy` + `Add-ADFineGrainedPasswordPolicySubject`.
  Verifikasi: `Get-ADFineGrainedPasswordPolicy -Filter * | Select-Object Name,Precedence,MinPasswordLength`
- [ ] **Kerberos policy**: TGT ≤10 jam, TGS ≤600 mnt, renew ≤7 hari, clock skew ≤5 mnt. GPO `Account Policies > Kerberos Policy`.
  Verifikasi: `secedit /export /cfg C:\eff.inf` (periksa seksi `[Kerberos Policy]`)
- [ ] **Kerberos Armoring (FAST)** diaktifkan (DC + klien, DFL 2012+). GPO KDC + Kerberos client `-> Modul 03`.
  Verifikasi: `gpresult /h C:\rsop.html /f` (pastikan GPO KDC/Kerberos client tampil di Applied GPOs) atau `rsop.msc`
- [ ] **AES dipaksa, RC4/DES dinonaktifkan** (`msDS-SupportedEncryptionTypes`); **audit akun lebih dulu**, reset password sebelum mematikan RC4.
  Verifikasi: `Get-ADObject -Filter * -Properties msDS-SupportedEncryptionTypes | Where-Object { $_.'msDS-SupportedEncryptionTypes' -band 0x4 } | Select-Object Name` (kosong setelah penegakan)
- [ ] **NTLM**: `LmCompatibilityLevel = 5` (NTLMv2 only), `NoLMHash = 1`, Restrict NTLM (audit → deny).
  Verifikasi: `reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel` (0x5)
- [ ] **(DC) LDAP** server signing = Require, `LdapEnforceChannelBinding = 2`, LDAP client signing = Require.
  Verifikasi: `reg query "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /v LDAPServerIntegrity` (0x2) dan `... /v LdapEnforceChannelBinding` (0x2)
- [ ] **Grup privileged ramping**; Schema/Enterprise Admins kosong; Account/Backup Operators kosong.
  Verifikasi: `'Domain Admins','Enterprise Admins','Schema Admins' | ForEach-Object { "=== $_ ==="; Get-ADGroupMember $_ -ErrorAction SilentlyContinue | Select-Object SamAccountName }`
- [ ] **AdminSDHolder ACL diaudit**; orphaned `adminCount=1` ditinjau.
  Verifikasi: `Get-ADUser -LDAPFilter "(adminCount=1)" -Properties adminCount,memberOf | Select-Object Name,SamAccountName`
- [ ] **Tidak ada unconstrained delegation di luar DC**; akun Tier 0 ber-`AccountNotDelegated`.
  Verifikasi: `Get-ADComputer -Filter { TrustedForDelegation -eq $true } -Properties TrustedForDelegation | Where-Object { $_.Name -notin (Get-ADDomainController -Filter *).Name } | Select-Object Name` (kosong)
- [ ] **KRBTGT dirotasi 2x** dengan jeda replikasi penuh; rotasi periodik dijadwalkan. Pakai `New-KrbtgtKeys.ps1` + `repadmin /syncall /AdeP`.
  Verifikasi: `Get-ADUser krbtgt -Properties PasswordLastSet | Select-Object Name,PasswordLastSet` (tanggal baru setelah rotasi)
- [ ] **AD Recycle Bin aktif** (FFL 2008 R2+).
  Verifikasi: `(Get-ADOptionalFeature -Filter "Name -eq 'Recycle Bin Feature'").EnabledScopes` (tidak kosong)
- [ ] **SYSVOL bersih dari `cpassword`**; permission SYSVOL ditinjau. (Pembersihan via GPP `-> Modul 03`.)
  Verifikasi: `Get-ChildItem "\\contoso.local\SYSVOL\contoso.local\Policies" -Recurse -Include *.xml -ErrorAction SilentlyContinue | Select-String -Pattern "cpassword"` (tanpa hasil)
- [ ] **(DC) System State backup rutin** + **DSRM password** diset & disimpan aman.
  Verifikasi: `reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v DsrmAdminLogonBehavior`
- [ ] **RODC dipakai di lokasi tak aman**; akun Tier 0 tidak masuk PRP RODC.
  Verifikasi: `Get-ADDomainController -Filter { IsReadOnly -eq $true } | Select-Object Name`
- [ ] **(DC) PDC emulator sinkron ke NTP eksternal** andal. `w32tm /config ... /reliable:yes /update`.
  Verifikasi: `w32tm /query /status` (Source = NTP eksternal, tanpa skew besar)
- [ ] **(DC) Zona AD-integrated DNS = Secure dynamic updates only**. Hardening DNS lain `-> Network (Modul 04)`.
  Verifikasi: `Get-DnsServerZone -Name "contoso.local" | Select-Object ZoneName,DynamicUpdate` (Secure)

---

## 3. GPO — Local & Active Directory Policy

`-> detail Modul 03 (03-gpo-policy.md)`

### Quick wins / Kritis

- [ ] **Security Options inti**: `RunAsPPL=1`, `LmCompatibilityLevel=5`, `RestrictAnonymous(SAM)=1`, `DontDisplayLastUserName=1`, `LimitBlankPasswordUse=1`.
  Verifikasi: `Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" | Select-Object RunAsPPL,LmCompatibilityLevel,RestrictAnonymous,RestrictAnonymousSAM,LimitBlankPasswordUse`
- [ ] **UAC**: `EnableLUA=1`, `PromptOnSecureDesktop=1`, `FilterAdministratorToken=1`.
  Verifikasi: `Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" | Select-Object EnableLUA,PromptOnSecureDesktop,FilterAdministratorToken,DontDisplayLastUserName`
- [ ] **URA tier separation** di-set (Deny network & RDP logon untuk tier mismatch) — pemilik mekanisme untuk PAM/AD.
  Verifikasi: `secedit /export /cfg C:\eff.inf` (periksa `[Privilege Rights]` → `SeDenyNetworkLogonRight`, `SeDenyRemoteInteractiveLogonRight`)
- [ ] **`SeDebugPrivilege`, `SeBackupPrivilege`, `SeImpersonatePrivilege`** dibatasi ke grup minimal.
  Verifikasi: `secedit /export /cfg C:\eff.inf` (periksa baris `SeDebugPrivilege`, `SeBackupPrivilege`, `SeImpersonatePrivilege`)
- [ ] **Tidak ada `cpassword` tersisa di SYSVOL** (jangan pakai GPP untuk password; pakai Windows LAPS `-> Modul 01`).
  Verifikasi: `Get-ChildItem "\\corp.local\SYSVOL" -Recurse -Include *.xml -ErrorAction SilentlyContinue | Select-String "cpassword"` (kosong)
- [ ] **Verifikasi penerapan** dengan `gpresult /h` dan `rsop.msc`.
  Verifikasi: `gpresult /h C:\rsop.html /f` (cek daftar Applied GPOs + nilai efektif)

### Lanjutan

- [ ] **Central Store ADMX** dibuat di `\\<domain>\SYSVOL\<domain>\Policies\PolicyDefinitions`.
  Verifikasi: `Get-ChildItem "\\corp.local\SYSVOL\corp.local\Policies\PolicyDefinitions"` (berisi file .admx; GPMC menampilkan tag "(central store)")
- [ ] **GPO baseline Microsoft** (Server 2022 / Windows 11) di-import via `Import-GPO` dan di-link ke OU yang benar.
  Verifikasi: `Get-GPInheritance -Target "OU=Servers,DC=corp,DC=local" | Select-Object -ExpandProperty GpoLinks`
- [ ] **Baseline penting di-set Enforced**; OU sensitif dipertimbangkan Block Inheritance dengan sadar.
  Verifikasi: `Get-GPInheritance -Target "OU=Servers,DC=corp,DC=local"` (lihat GpoLinks `Enforced` & `InheritanceBlocked`)
- [ ] **Security Filtering kustom selalu menyertakan Read untuk `Domain Computers`** (gotcha MS16-072).
  Verifikasi: `Get-GPPermission -Name "Hardening - Servers (Lab)" -All | Select-Object Trustee,Permission`
- [ ] **WMI Filter** memisahkan DC (`ProductType=2`) / member server (`3`) / klien (`1`) bila perlu.
  Verifikasi: `gpresult /r /scope computer` (pastikan GPO ber-WMI filter hanya apply di tipe host yang benar) atau `rsop.msc`
- [ ] **Loopback (Merge/Replace) aktif** pada OU jump host / RDS / kiosk.
  Verifikasi: `reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v UserPolicyMode` (1=Merge, 2=Replace)
- [ ] **AppLocker** default rules + **Audit-only dulu lalu Enforce**; `AppIDSvc` Automatic.
  Verifikasi: `Get-Service AppIDSvc | Select-Object Name,Status,StartType` (Running/Automatic) dan `Get-AppLockerPolicy -Effective -Xml`
- [ ] **Removable storage Deny all** (host sensitif); **RDP NLA wajib** `-> Network (Modul 04)`; **macro Office dari internet diblok**.
  Verifikasi: `reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices" /v Deny_All` (0x1)
- [ ] **GPO dibackup** (`Backup-GPO -All`), **delegasi/permission GPO di-audit** (cari trustee Edit berlebih).
  Verifikasi: `Get-GPO -All | ForEach-Object { $g=$_; Get-GPPermission -Guid $g.Id -All | Where-Object { $_.Permission -match "Edit|GpoEditDeleteModifySecurity" } | Select-Object @{n="GPO";e={$g.DisplayName}},Trustee,Permission }`

---

## 4. Network — Network Service Security

`-> detail Modul 04 (04-network-service-security.md)`

### Quick wins / Kritis

- [ ] **Ketiga firewall profile (Domain/Private/Public) On**, Inbound = **Block**, Outbound = Allow.
  Verifikasi: `Get-NetFirewallProfile | Format-Table Name,Enabled,DefaultInboundAction,DefaultOutboundAction`
- [ ] **Firewall logging dropped packets** aktif, `LogMaxSizeKilobytes ≥ 16384`.
  Verifikasi: `Get-NetFirewallProfile | Format-Table Name,LogBlocked,LogMaxSizeKilobytes`
- [ ] **LLMNR off** (`EnableMulticast 0`), **NBT-NS off** (`NetbiosOptions 2`), **mDNS off** (`EnableMDNS 0`).
  Verifikasi: `Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' EnableMulticast -EA SilentlyContinue` ; `Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' EnableMDNS -EA SilentlyContinue` ; `Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE" | Select Description,TcpipNetbiosOptions`
- [ ] **mitm6 / IPv6 DNS takeover dimitigasi** (Modul 04 §5.5): **RA Guard + DHCPv6 Guard** di switch, atau blok **DHCPv6 (UDP 546/547)** + **ICMPv6 RA (type 134)** via firewall GPO bila IPv6 tak dipakai. Rantai relay-nya juga ditutup oleh **LDAP signing+CBT & `MachineAccountQuota=0`** (AD, §2) + **SMB signing** (§4).
  Verifikasi: `Get-NetFirewallRule -DisplayName "*DHCPv6*","*Router Advertisement*" -EA SilentlyContinue | Select-Object DisplayName,Enabled,Direction,Action`
- [ ] **SMBv1 dinonaktifkan/dihapus** (`EnableSMB1Protocol $false` + feature removed).
  Verifikasi: `Get-SmbServerConfiguration | Select EnableSMB1Protocol` dan `Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol | Select FeatureName,State`
- [ ] **SMB signing wajib** di server & client (`RequireSecuritySignature $true`).
  Verifikasi: `Get-SmbServerConfiguration | Select RequireSecuritySignature` dan `Get-SmbClientConfiguration | Select RequireSecuritySignature`
- [ ] **RDP: NLA wajib**, SecurityLayer = TLS (2), Encryption = High (3).
  Verifikasi: `Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' | Select UserAuthentication,SecurityLayer,MinEncryptionLevel` (1 / 2 / 3)
- [ ] **(DC) Print Spooler disabled**; service tak terpakai (RemoteRegistry, WinHttpAutoProxySvc, dll.) dimatikan.
  Verifikasi: `Get-Service Spooler,RemoteRegistry,WinHttpAutoProxySvc | Select Name,Status,StartType` (Stopped/Disabled)

### Lanjutan

- [ ] **Rule inbound hanya untuk port yang dibutuhkan**, dengan `RemoteAddress` scope ke subnet management.
  Verifikasi: `Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True | Get-NetFirewallAddressFilter | Format-Table RemoteAddress`
- [ ] **Firewall dikelola via GPO** (`-> Modul 03`), bukan per-host.
  Verifikasi: `gpresult /r /scope computer` (GPO firewall tampil di Applied GPOs)
- [ ] **SMB encryption** aktif untuk share sensitif (`EncryptData $true`).
  Verifikasi: `Get-SmbServerConfiguration | Select EncryptData,RejectUnencryptedAccess`
- [ ] **Insecure guest logons disabled**; null session/anonymous dibatasi (`-> Modul 03`).
  Verifikasi: `Get-SmbClientConfiguration | Select EnableInsecureGuestLogons`
- [ ] **User RDP dibatasi**; **3389 tidak terekspos ke internet** (RD Gateway/VPN). URA `-> Modul 03`.
  Verifikasi: `Get-NetTCPConnection -State Listen | Select LocalAddress,LocalPort | Sort-Object LocalPort` (3389 hanya pada interface management)
- [ ] **WPAD dimitigasi** (service disabled + GQBL/DNS sinkhole).
  Verifikasi: `Get-Service WinHttpAutoProxySvc | Select Name,Status,StartType` dan `Get-DnsServerGlobalQueryBlockList` (memuat `wpad`,`isatap`)
- [ ] **WinRM**: listener HTTPS, Basic auth & AllowUnencrypted **disabled**, TrustedHosts dibatasi.
  Verifikasi: `Get-Item WSMan:\localhost\Service\Auth\Basic, WSMan:\localhost\Service\AllowUnencrypted` (keduanya false) atau `winrm get winrm/config/service`
- [ ] **TLS 1.0/1.1 & SSL 2.0/3.0 disabled**; **RC4/3DES disabled** (SCHANNEL).
  Verifikasi: `Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -EA SilentlyContinue` (Enabled=0)
- [ ] **PowerShell v2 dinonaktifkan** (juga menutup bypass logging/AMSI — dirujuk Modul 06).
  Verifikasi: `Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 | Select State` (Disabled)
- [ ] **(DC) DNS**: secure dynamic updates, recursion sesuai peran, cache locking 100%, RRL aktif.
  Verifikasi: `Get-DnsServerRecursion | Select Enable` ; `Get-DnsServerCache | Select LockingPercent` ; `Get-DnsServerGlobalQueryBlockList`

---

## 5. AV — Microsoft Defender Antivirus & EDR

`-> detail Modul 05 (05-antivirus-defender.md)`

### Quick wins / Kritis

- [ ] **Engine status**: `AMRunningMode = Normal`, semua engine `*Enabled = True`.
  Verifikasi: `Get-MpComputerStatus | Select AMRunningMode,RealTimeProtectionEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,OnAccessProtectionEnabled,NISEnabled,IsTamperProtected`
- [ ] **Real-time, behavior, IOAV, script scanning aktif** (`Disable* = $false`).
  Verifikasi: `Get-MpComputerStatus | Select RealTimeProtectionEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled`
- [ ] **Tamper Protection = On** (via Windows Security app / Intune — bukan GPO).
  Verifikasi: `Get-MpComputerStatus | Select-Object IsTamperProtected,TamperProtectionSource` (IsTamperProtected=True)
- [ ] **Signature ter-update** (`AntivirusSignatureLastUpdated` ≤ 24 jam). `Update-MpSignature`.
  Verifikasi: `Get-MpComputerStatus | Select AntivirusSignatureVersion,AntivirusSignatureLastUpdated`
- [ ] **Cloud protection**: `MAPSReporting = Advanced`, `CloudBlockLevel = High`, `CloudExtendedTimeout = 50`; **BAFS aktif** (`DisableBlockAtFirstSeen = $false`); `SubmitSamplesConsent` mengizinkan kirim sample; **PUA = Enabled**.
  Verifikasi: `Get-MpPreference | Select-Object MAPSReporting,SubmitSamplesConsent,CloudBlockLevel,CloudExtendedTimeout,DisableBlockAtFirstSeen,PUAProtection`

### Lanjutan

- [ ] **ASR rules inti aktif** (LSASS, Office child process, email exec, obfuscated scripts, Win32 API macro, PsExec/WMI) — minimal Audit, target **Block**.
  Verifikasi: `$p=Get-MpPreference; for($i=0;$i -lt $p.AttackSurfaceReductionRules_Ids.Count;$i++){ '{0} => {1}' -f $p.AttackSurfaceReductionRules_Ids[$i],$p.AttackSurfaceReductionRules_Actions[$i] }` (GUID inti = 1/Block)
- [ ] **Controlled Folder Access = Enabled** dengan allowed apps tepat; **Network Protection = Enabled**.
  Verifikasi: `Get-MpPreference | Select-Object EnableControlledFolderAccess,EnableNetworkProtection` (keduanya 1)
- [ ] **Exclusion minim, spesifik, terdaftar di baseline**, tidak ada folder writable-user.
  Verifikasi: `Get-MpPreference | Select-Object ExclusionPath,ExclusionExtension,ExclusionProcess,ExclusionIpAddress`
- [ ] **Exploit Protection (DEP/ASLR/CFG)** terkonfigurasi & didistribusi via GPO.
  Verifikasi: `Get-ProcessMitigation -System | Out-String`
- [ ] **SmartScreen = Enabled** (Warn and prevent bypass).
  Verifikasi: `reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableSmartScreen` (0x1) dan `... /v ShellSmartScreenLevel` (Block)
- [ ] **Kebijakan AV dikelola GPO/Intune**, bukan hanya lokal (`-> Modul 03`).
  Verifikasi: `Get-ChildItem "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"` (subkey terisi = policy didorong GPO/Intune, bukan hanya `Set-MpPreference` lokal)
- [ ] **(Jika ada) host ter-onboard MDE & EDR in block mode** aktif.
  Verifikasi: `Get-Service Sense,WinDefend | Select-Object Name,Status,StartType` (WinDefend Running; Sense Running bila onboarded)

---

## 6. Logging — Logging & Auditing

`-> detail Modul 06 (06-logging-auditing.md)`

### Quick wins / Kritis

- [ ] **`SCENoApplyLegacyAuditPolicy` = Enabled** (force subcategory) via GPO — wajib lebih dulu.
  Verifikasi: `reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v SCENoApplyLegacyAuditPolicy` (0x1)
- [ ] **Advanced Audit Policy subkategori wajib** (tabel Modul 06 §4) diterapkan via GPO ke server, DC, dan klien.
  Verifikasi: `auditpol /get /category:*` (kolom Inclusion Setting terisi Success/Failure)
- [ ] **Audit Process Creation = Success** **dan** "Include command line in process creation events" = Enabled (4688 + cmdline).
  Verifikasi: `reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled` (0x1)
- [ ] **PowerShell Script Block Logging (4104) + Module Logging (4103) + Transcription** = Enabled via GPO.
  Verifikasi: `(Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -EA SilentlyContinue).EnableScriptBlockLogging` (1)
- [ ] **Windows PowerShell 2.0 Engine di-disable** (tutup bypass PSv2) `-> Modul 04 (Network)`.
  Verifikasi: `Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 | Select State` (Disabled)
- [ ] **(DC) DS Access** (Directory Service Access & Changes) = Success+Failure.
  Verifikasi: `auditpol /get /subcategory:"Directory Service Access","Directory Service Changes"`

### Lanjutan

- [ ] **Sysmon terinstal** dengan config matang (SwiftOnSecurity/Olaf Hartong); channel `Microsoft-Windows-Sysmon/Operational` aktif.
  Verifikasi: `Get-Service Sysmon64 | Select Name,Status` dan `Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' | Select RecordCount,IsEnabled`
- [ ] **Max log size dinaikkan** minimal ke nilai CIS (Security ≥ 196,608 KB; App/System/Setup ≥ 32,768 KB).
  Verifikasi: `Get-WinEvent -ListLog Security | Select-Object LogName,MaximumSizeInBytes,LogMode,RecordCount` (MaximumSizeInBytes ≥ 201326592)
- [ ] **Retention = overwrite as needed** + **forwarding** ke collector/SIEM dikonfigurasi.
  Verifikasi: `Get-WinEvent -ListLog Security | Select LogName,LogMode` (Circular) dan `wecutil es`
- [ ] **WEF/WEC aktif**: subscription source-initiated via GPO (contoh `subscription.xml` di Modul 06 §9), event masuk ke `ForwardedEvents`. Untuk transport WinRM **5985 vs 5986**, lihat *Catatan Lintas-Modul* (jangan blokir 5985 buta — scope ke collector, atau pakai HTTPS 5986).
  Verifikasi: `wecutil es` (ada subscription Active) — jalankan di collector
- [ ] **Alert real-time pada Event 1102** (log cleared) **dan 4719** (audit policy changed).
  Verifikasi: `Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102} -MaxEvents 1` (uji clear di lab → muncul 1102)
- [ ] **Akses baca/hapus Security log dibatasi** (admin + `Event Log Readers` saja).
  Verifikasi: `wevtutil gl Security` (periksa SDDL `channelAccess`)
- [ ] **Waktu tersinkron ke hierarki domain** (PDC -> NTP eksternal); skew terverifikasi.
  Verifikasi: `w32tm /query /source` dan `w32tm /query /status`

---

## Catatan Lintas-Modul

- **Port 5985 (WinRM HTTP) — rekonsiliasi Modul 04 vs Modul 06.** Modul 04 (§6) menutup **5985** untuk **management interaktif** (PowerShell Remoting) dan mengutamakan **5986/HTTPS**. Modul 06 (§9) **WEF source-initiated** memang memakai 5985, tetapi itu listener WinRM untuk **forwarding event** dan payload-nya **tetap terenkripsi Kerberos** antar mesin domain (bukan kredensial polos). **Jangan blokir 5985 secara buta**: *scope* rule firewall agar 5985 hanya menerima dari **collector WEF + subnet management**, dan tetap tolak 5985 dari segmen user. Paling bersih: jalankan **WEF over HTTPS 5986** sehingga hanya satu port (5986) yang perlu terbuka. Pastikan keputusan ini konsisten saat mengerjakan item WinRM (§4) dan WEF (§6) di bawah.
- **PSv2 disable** dimiliki **Network (Modul 04)**; Logging (Modul 06) hanya merujuk.
- **SYSVOL `cpassword`** pembersihan GPP dimiliki **GPO (Modul 03)**; audit isi SYSVOL ada di **AD (Modul 02)**.
- **URA tier separation / logon restriction** mekanismenya dimiliki **GPO (Modul 03)**; dipakai oleh **PAM (Modul 01)** & **AD (Modul 02)**.
- **RDP NLA** + transport TLS dimiliki **Network (Modul 04)**; **GPO (Modul 03)** menyediakan path setting-nya.
- **AD-integrated DNS secure updates** ada di **AD (Modul 02)**; hardening service DNS (recursion/cache/RRL/GQBL) dimiliki **Network (Modul 04)**.
- **Credential Guard / Remote Credential Guard** dimiliki **PAM (Modul 01)**; **AV/Defender** (Modul 05) melengkapinya untuk proteksi LSASS.

> Untuk nilai numerik & rasional tiap setting, selalu kembali ke modul sumber yang ditunjuk `-> Modul 0X`. Saat ragu antara CIS dan Microsoft Security Baseline, tampilkan kedua nilai dan ikuti sumber yang dipakai juri.
