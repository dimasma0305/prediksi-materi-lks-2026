# Laporan Kekurangan Materi — Paket LKSN 2026

> **Audit kedalaman konten, bukan struktur.** Dokumen ini merangkum hasil review per-kategori oleh para reviewer otomatis. Fokusnya pada *winning-edge*: contoh/payload/solver yang dapat dijalankan, subtopik kisi-kisi yang benar-benar didemokan, akurasi teknis, dan kesiapan lab — **bukan** pada plumbing indeks/navigasi (yang dinilai sudah solid: 82/82 topik cocok kisi-kisi, bobot/skoring akurat, tidak ada link `.md` putus).
>
> Hasil review otomatis · disusun 2026-06-26 · cakupan: 13 kelompok review, 144 temuan.

---

## Ringkasan Eksekutif

| Severity | Jumlah |
|----------|--------|
| **Critical** | **0** |
| **Major** | **54** |
| **Minor** | **90** |
| **Total** | **144** |

**Tidak ada temuan critical.** Setiap reviewer memverifikasi bahwa tidak ada sub-poin kisi-kisi yang hilang total dan tidak ada kesalahan teknis fatal yang lolos verifikasi (identifier padat seperti GUID ASR, tabel Event ID, byte shellcode, caveat versi glibc, matematika RSA/ECC/GCM semuanya akurat saat di-spot-check). Kekurangan terkonsentrasi pada **kedalaman untuk menang lomba** dan **konsistensi/akurasi minor**.

### Tema kekurangan terbesar lintas kategori

1. **Solver/payload yang BISA DIJALANKAN menipis tepat di teknik tersulit & bernilai-tertinggi.** Triase/pengenalan unggul, tetapi kode runnable menghilang di CBC padding oracle, GCM forbidden, Wiener (Crypto); heap UAF/double-free, FSOP, SROP/ret2csu/ret2dlresolve (Binary); OOB/second-order/Oracle SQLi, SSTI engine ekstra, CSP-bypass XSS (Web).
2. **Subtopik kisi-kisi/teknik bernama hilang di lokasi yang seharusnya.** NFS (Linux 03 + boot2root), cron wildcard injection, mitm6/IPv6 DNS takeover, Json.NET deserialization, second-order SQLi, ms-DS-MachineAccountQuota, AD CS/PKI, perimeter/IDS.
3. **Coverage Windows dangkal di modul yang justru dibingkai Windows.** RE (x64dbg & anti-debug Windows hanya Linux gdb/ptrace), Upload (bypass Apache-centric tanpa padanan `web.config` IIS).
4. **Jalur foothold AD & cracking offline tidak pernah dieksekusi** padahal dijual sebagai jalan masuk utama. AS-REP/Kerberoast/secretsdump + hashcat/john absen di boot2root 02 dan tak punya perintah enumerasi di Windows AD 02.
5. **Dimensi blue-team/defender yang dijanjikan absen.** RE "Deteksi & Mitigasi" (README butir 6) tidak ada di satu pun halaman; sisi dynamic/sandbox & Zeek forensik hanya nongkrong di tabel Tools; format SIEM threat-hunting/anomaly-detection (objektif resmi Modul C 40%) tak terindeks.
6. **Mini-lab dangkal: tidak runnable, tidak ada target, atau tidak membuktikan mitigasi.** Solver heap berisi stub `...`; mini-lab RE menunjuk biner yang tak bisa diperoleh; lab SMB hanya capture hash tanpa membuktikan signing memutus relay; boot2root tak punya capstone end-to-end.
7. **Inkonsistensi template README & artefak generasi berulang.** Daftar template README menghilangkan "Indikator"/menamai salah "Deteksi & Mitigasi" di ≥5 README; broken-ref `(#)` dan "Modul C — Hardening" (tidak ada); dua file menyimpan literal `</content>`/`</invoke>`.
8. **Setup-lab tidak menyokong 60% bobot modul.** Tidak ada toolchain analisis B+C, tidak ada VM SIEM (§4.2.3), tidak ada persyaratan perangkat resmi §5.2 (converter LAN), dan tidak ada panduan POC/writeup padahal Judgement ~30% skor.

---

## Temuan Kritis (Critical)

**Tidak ada temuan critical (0).** Semua reviewer mengonfirmasi tidak ada sub-poin kisi-kisi yang absen total dan tidak ada error fatal yang lolos verifikasi.

Untuk transparansi, berikut tiga temuan yang **paling mendekati critical** (di-soften ke major) dan layak ditangani lebih dulu karena merusak materi/lab atau menyesatkan peserta:

| Area | Masalah | Fix |
|------|---------|-----|
| `modul-c-defensive-ctf/digital-forensic/05-memory-forensic.md` | Bug kolom: `awk '{print $2}'` mengambil **PPID** bukan PID (Vol3: `$1`=PID, `$2`=PPID), sehingga teknik andalan pslist-vs-psscan untuk menemukan proses tersembunyi **gagal/menyesatkan** dan disalin apa adanya. | Ubah kedua perintah ke `awk 'NR>1{print $1}'` sebelum `sort`/`comm`. |
| `modul-c-defensive-ctf/reverse-engineering/README.md` (berdampak 01-09) | README butir 6 menjanjikan dimensi **"Deteksi & Mitigasi" sisi defender**, tetapi TIDAK ada di satu halaman pun — seluruh dimensi blue-team hilang pada modul yang dibingkai defensif & berbobot 40%. | Tambah blok "Deteksi & Mitigasi" di tiap halaman (anti-debug berlapis, integrity check, strip simbol, deteksi attach) ATAU revisi framing README agar tidak menjanjikan konten yang absen. |
| `modul-b-offensive-ctf/cryptography/02-attack-on-rsa.md` | Mini-Lab menyuruh cross-check `RsaCtfTool --attack common_modulus_related_message` — **attack itu tidak ada** dan RsaCtfTool tidak mengimplementasikan common-modulus klasik; cross-check mustahil dijalankan & menyesatkan. | Hapus cross-check RsaCtfTool untuk common-modulus (andalkan solver manual yang sudah benar); pertahankan `--attack fermat` hanya untuk skenario twin-prime. |

---

## Temuan Major (54)

### Windows Hardening (Modul A)

| Area | Masalah | Fix ringkas |
|------|---------|-------------|
| `windows/01-privileged-access-management.md` | Bagian PAW sepenuhnya konseptual (hanya tabel prinsip), TANPA satu pun command — padahal semua bagian lain punya contoh PowerShell/registry. | Tambah snippet konkret: AppLocker/WDAC allow-list PAW, `New-NetFirewallRule` blok outbound, Deny removable storage, `LsaCfgFlags=1` (Credential Guard), URA deny-logon + langkah konfirmasi. |
| `windows/01-privileged-access-management.md` | Contoh Auth Policy Silo pakai `-Enforce` tapi hanya assign akun user; komputer Tier 0 (DC/PAW) tak pernah di-assign & tak ada `AllowedToAuthenticateFrom` → bisa **lockout total** admin Tier 0; kontradiksi internal dengan tip audit-only. | Assign computer DC/PAW ke silo + kondisi `-UserAllowedToAuthenticateFrom` (SDDL); tulis contoh tanpa `-Enforce` dulu (audit), baru enforce setelah validasi. |
| `windows/02-active-directory-security.md` | `ms-DS-MachineAccountQuota` (default 10) & rekomendasi set 0 tidak dibahas — membuka jalur RBCD/noPac yang justru dibahas modul tapi tak ditutup. | Tambah `Set-ADDomain -Replace @{'ms-DS-MachineAccountQuota'=0}`, jelaskan kaitan ke RBCD/noPac, masukkan ke checklist. |
| `windows/02-active-directory-security.md` | AS-REP Roasting & Kerberoasting ada di tabel serangan tapi tak ada perintah enumerasi akun rentan (padahal RC4 & unconstrained delegation punya). | Tambah `Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}` dan `Get-ADUser -Filter {ServicePrincipalName -like '*'}` + cek RC4. |
| `windows/04-network-service-security.md` | §5 Name Resolution Poisoning menghilangkan **mitm6/IPv6 DHCPv6 DNS takeover** — teknik modern setara Responder yang dirantai ke ntlmrelayx→DA. | Tambah §5.5 mitm6 (rantai rogue DHCPv6→WPAD IPv6→relay NTLM) + mitigasi RA Guard/DHCPv6 Guard, rujuk SMB/LDAP signing & MAQ=0; propagasi ke checklist 07. |
| `windows/04-network-service-security.md` | Lab membuktikan Responder *capture* hash tapi tak pernah mendemokan **SMB relay (ntlmrelayx)** — peserta tak melihat bukti signing memutus relay. | Tambah langkah lab `ntlmrelayx.py -t smb://<target>`: tunjukkan relay GAGAL setelah `RequireSecuritySignature=$true` vs berhasil sebelumnya. |
| `windows/06-logging-auditing.md` | §9 WEF/WEC merujuk `wecutil cs subscription.xml` tapi tak pernah menyertakan contoh isi XML — bagian tersulit & paling rawan gagal saat lab. | Sisipkan blok XML subscription minimal source-initiated (SubscriptionType, Query `Select Path='Security'`, `AllowedSourceDomainComputers` SDDL) siap pakai. |

### Linux Infrastructure Hardening (Modul A)

| Area | Masalah | Fix ringkas |
|------|---------|-------------|
| `linux/03-common-linux-misconfigurations.md` | Kisi-kisi menaruh **NFS** di sini, tapi file 03 tak menyebut NFS sama sekali; privesc klasik no_root_squash (mount + SUID root) tak didemokan di mana pun. | Tambah seksi NFS: enum (`showmount -e`, `/etc/exports`), mekanisme no_root_squash, mini-lab attack→hardening (root_squash/all_squash/subnet/nosuid). |
| `linux/03-common-linux-misconfigurations.md` | Cron (§4) menutup writable-script & PATH absolut tapi tak membahas **wildcard/argument injection** (tar `--checkpoint-action`, chown/rsync). | Tambah contoh wildcard injection + mini-lab attack→fix (quote argumen, `./` prefix, `--` end-of-options). |
| `linux/01-privileged-access-management-pam.md` | Halaman menegaskan `pam_faillock` "paling sering diuji" & menyuruh "sisipkan baris", tapi **baris `.so` konkret tak pernah ditampilkan**. | Tampilkan eksplisit: `auth required pam_faillock.so preauth` / `[default=die] authfail` / `sufficient authsucc` / `account required`; + contoh profil `pam-configs/` & baris `pam_pwquality.so`/`pam_pwhistory.so`. |

### Cryptography (Modul B)

| Area | Masalah | Fix ringkas |
|------|---------|-------------|
| `cryptography/04-attack-on-aes.md` | **CBC padding oracle** — serangan AES paling ikonik & disebut eksplisit kisi-kisi — tak punya satu pun solver Python (hanya CLI padbuster). | Tambah snippet solver: loop per-posisi brute 256 nilai `C_{i-1}` sampai padding valid → `intermediate = guess XOR pad` → `P = intermediate XOR C_orig`, dengan antarmuka `oracle(ct)->bool`. |
| `cryptography/04-attack-on-aes.md` | **ECB cut-and-paste** (dinamai kisi-kisi) hanya prosa, sedangkan byte-at-a-time justru punya kode penuh. | Tambah contoh konkret: profil terstruktur, penyelarasan batas blok 16-byte agar `admin`+pad menempati satu blok, lalu perangkaian ulang indeks blok ciphertext. |
| `cryptography/04-attack-on-aes.md` | **GCM nonce-reuse/forbidden** matematis benar tapi Contoh hanya placeholder `python3 gcm_forbidden.py`. | Sertakan kerangka `galois`/SageMath: bangun `GF(2^128)`, bentuk polinomial selisih tag, faktorkan → kandidat H, verifikasi, forge — atau rujuk solver writeup nyata. |
| `cryptography/02-attack-on-rsa.md` | Cross-check `RsaCtfTool --attack common_modulus_related_message` tidak ada & RsaCtfTool tak mendukung common-modulus klasik — mustahil dijalankan & menyesatkan. | Hapus cross-check itu (andalkan solver manual); pertahankan RsaCtfTool hanya untuk Fermat/twin-prime; koreksi baris Tools. |
| `cryptography/02-attack-on-rsa.md` | **Wiener** (d kecil) disebut 2× tapi tak ada solver/payload. | Tambah solver continued-fraction convergents (`e/n`, uji `k/d`, cek `(e*d-1)%k==0`), atau tunjukkan `RsaCtfTool --attack wiener` sebagai jalur konkret. |

### Web Exploitation (Modul B)

| Area | Masalah | Fix ringkas |
|------|---------|-------------|
| `web-exploitation/01-account-takeover.md` | Pola ATO paling sering (token reset/OTP dikembalikan langsung di body/Location response) tak dibahas. | Tambah sub-poin + payload response-disclosure + mitigasi (jangan kembalikan token di response). |
| `web-exploitation/02-oauth-misconfiguration.md` | Parameter **`nonce`** OIDC tak disebut sama sekali; vektor OIDC SSRF (dynamic client registration / `request_uri`) absen. | Tambah `nonce` ke validasi id_token + paragraf OIDC SSRF + lab PortSwigger terkait. |
| `web-exploitation/11-insecure-deserialization.md` | Emphasis .NET diklaim tapi cakupan hanya BinaryFormatter/LosFormatter/ViewState — **Json.NET `TypeNameHandling`** & formatter ysoserial.net lain hilang. | Tambah `ysoserial.net -f Json.Net -c "<cmd>"` + `JavaScriptSerializer`/`DataContractSerializer`/`SoapFormatter` + trigger-nya. |
| `web-exploitation/15-json-web-token.md` | Kelas **`jku`/`jwk`/`x5u` injection** ada di tabel & dirujuk lab, tapi bagian Payload tak punya satu pun contoh konkret (kelas lain semua punya). | Tambah payload `jku`→JWKS attacker + embedded `jwk` + flag `jwt_tool -X i/-X s`. |
| `web-exploitation/24-sql-injection.md` | **OOB** terdaftar + Collaborator/interactsh disebut, tapi tak ada payload OOB DNS/HTTP exfil. | Tambah payload MSSQL `xp_dirtree`, MySQL `LOAD_FILE(CONCAT(...))`, Oracle `UTL_HTTP`/`EXTRACTVALUE`. |
| `web-exploitation/24-sql-injection.md` | **Second-order (stored) SQLi** tak dibahas sama sekali (subtopik standar PortSwigger/CTF). | Tambah paragraf + contoh injeksi via registrasi/profil yang lolos insert tapi disambung mentah saat dibaca ulang. |
| `web-exploitation/24-sql-injection.md` | **Oracle** in-scope (fingerprint `v$version`) tapi tak ada payload Oracle (UNION butuh `FROM dual`, enumerasi `all_tables`, time-based bukan `SLEEP()`). | Tambah kolom Oracle: `UNION ... FROM dual`, `all_tables`/`all_tab_columns`, `DBMS_PIPE.RECEIVE_MESSAGE`. |
| `web-exploitation/27-server-side-template-injection.md` | Fingerprint daftarkan Thymeleaf/Handlebars/Pug tapi tak ada RCE konkret untuk ketiganya ("butuh teknik khusus"). | Tambah payload nyata Thymeleaf (`T(java.lang.Runtime)...`), Handlebars (`constructor`/`require`), Pug (`#{global.process...}`). |
| `web-exploitation/22-request-smuggling.md` | Manifest menyebut "capture request korban" & "cache poisoning" tapi hanya skenario bypass `/admin` yang end-to-end. | Tambah contoh capture-request (smuggle prefix simpan request korban) + rantai cache-poisoning. |
| `web-exploitation/29-upload-insecure-files.md` | Dibingkai "Windows + IIS" + webshell ASPX, tapi semua trik bypass Apache-centric (`.htaccess`); tak ada padanan IIS `web.config`. | Tambah payload `web.config` yang diunggah untuk enable handler ASP/ASPX + catatan kapan IIS honor per-direktori. |
| `web-exploitation/31-web-sockets.md` | CSWSH menyatakan browser "otomatis menyertakan cookie" TANPA caveat **SameSite** — dengan `Lax` default modern, handshake lintas-origin umumnya tak bawa cookie. | Tambah caveat: viabilitas CSWSH bergantung SameSite cookie sesi (lab pakai cookie longgar); kaitkan ke pembahasan SameSite/CSRF. |
| `web-exploitation/34-xss-injection.md` | **CSP bypass** dijanjikan manifest & disebut di Langkah tapi tak ada satu payload konkret (JSONP/AngularJS hanya disebut). | Tambah payload JSONP gadget, AngularJS CSP bypass (`{{constructor.constructor(...)()}}`), base-uri/dangling-markup. |

### Binary Exploitation (Modul B)

| Area | Masalah | Fix ringkas |
|------|---------|-------------|
| `binary-exploitation/09-heap-exploitation.md` | Dari 3 sub-poin heap, hanya UAF dicoba — dan solvernya **tak runnable**: wrapper create/delete/edit/show berisi stub `...`, snippet C rentan tak punya `main()`/loop menu. Topik "paling kompleks" justru satu-satunya yang tak bisa dijalankan. | Sediakan program rentan lengkap (`main()` + parser menu) & isi penuh wrapper agar solver UAF→tcache poisoning runnable end-to-end. |
| `binary-exploitation/09-heap-exploitation.md` | **Double Free** hanya prosa (tak ada PoC); **Heap overflow** tak punya solver tersendiri. | Tambah solver double-free valid glibc modern (isi 7 slot tcache → fastbin dup) + contoh heap-overflow (timpa size/fd chunk tetangga). |
| `binary-exploitation/08-bypass-protection.md` + `09-heap-exploitation.md` | **FSOP / `_IO_FILE`** dipromosikan WAJIB pasca glibc 2.34 (hook dihapus) tapi tak pernah ditunjukkan konkret → jalur glibc modern + Full RELRO buntu. | Tambah contoh FSOP minimal (overwrite vtable/flags `_IO_2_1_stdout_` / sketsa House of Apple2) + leak libc via unsorted bin. |
| `binary-exploitation/05-rop-chain.md` | **ret2csu, SROP, ret2dlresolve** hanya disebut satu baris tanpa payload — padahal bahan inti pwn level menang (tanpa-leak via SROP/ret2dlresolve). | Tambah sketsa pwntools `SigreturnFrame()`, `Ret2dlresolvePayload`, ret2csu (set rdx) — masing-masing 5-10 baris. |

### Boot2Root (Modul B)

| Area | Masalah | Fix ringkas |
|------|---------|-------------|
| `boot2root/02-service-level-exploitation.md` | File 01 menjual AD sebagai "jalan masuk utama", tapi 02 tak pernah membahas AS-REP Roasting/Kerberoasting/secretsdump (inkonsistensi + subtopik hilang). | Tambah blok AD: `impacket-GetNPUsers ... -no-pass`, `impacket-GetUserSPNs ... -request`, jelaskan crack tiket `$krb5asrep$`/`$krb5tgs$` offline. |
| `boot2root/02-service-level-exploitation.md` | Kisi-kisi sebut "reverse shell" tapi hanya ada msfvenom; one-liner interaktif (paling sering dipakai saat RCE) absen. | Tambah bash `>& /dev/tcp/...`, `nc -e`, python3, php, PowerShell IEX; sebut revshells.com. |
| `boot2root/02-service-level-exploitation.md` | Tak ada cracking hash offline (hashcat/john) — hanya brute online; padahal hash hasil dump WAJIB di-crack. | Tambah tabel mode hashcat: `-m 1000` NTLM, `-m 18200` AS-REP, `-m 13100` Kerberoast, `-m 5600` NetNTLMv2 + padanan john. |
| `boot2root/03-vertical-dan-horizontal-privilege-escalati.md` | PrivEsc **horizontal** (co-equal di kisi-kisi) hanya ~4 baris vs vertical yang punya tabel penuh; PtH/PtT tak dibingkai lateral movement. | Perluas: lokasi cred (history/.env/web.config/KeePass), reuse lintas user/host, PtH/PtT (netexec/evil-winrm `-H`, impacket `-hashes`/`-k`). |
| `boot2root/03-vertical-dan-horizontal-privilege-escalati.md` | Kernel/local exploit hanya rujuk generik tanpa menamai exploit andalan. | Tambah daftar bernama + kategori BENAR: PwnKit/CVE-2021-4034 (polkit, **userland**), Baron Samedit/CVE-2021-3156 (sudo), Dirty Pipe/DirtyCOW (kernel) + PoC pkexec. |
| `boot2root/03-vertical-dan-horizontal-privilege-escalati.md` | Indikator sebut `SeBackupPrivilege` tapi Payload hanya `SeImpersonate` (Potato) — inkonsistensi indikator vs payload. | Tambah resep `reg save hklm\sam`/`system` → `impacket-secretsdump -sam -system LOCAL`; singgung diskshadow/SeRestore. |
| `boot2root/01-service-level-enumerations.md` | Enumerasi **NFS** (port 111/2049) absen total, padahal 02 menyebut no_root_squash sebagai vektor — rantai boot2root klasik terputus. | Tambah `rpcinfo -p`, `showmount -e`; di 03 tambah resep mount + SUID `/bin/bash` (uid 0) → jalankan `-p`. |

### Reverse Engineering (Modul C)

| Area | Masalah | Fix ringkas |
|------|---------|-------------|
| `reverse-engineering/02-dynamic-analysis.md` | Kisi-kisi sebut x64dbg & modul bertema Windows, tapi SELURUH contoh hanya Linux gdb/strace/ltrace/qemu; x64dbg/WinDbg TTD cuma baris tabel. | Tambah workflow Windows konkret: breakpoint x64dbg, baca argumen RCX/RDX/R8/R9 (ABI MS x64), hardware bp, dump string; opsional sesi WinDbg TTD; label "jalur Windows" vs "jalur Linux". |
| `reverse-engineering/04-anti-re.md` | Menjelaskan anti-debug Windows (IsDebuggerPresent/PEB/NtQueryInformationProcess) & cantumkan ScyllaHide, tapi ketiga contoh bypass semuanya Linux ptrace. | Tambah bypass Windows konkret: patch `IsDebuggerPresent`→0, set `PEB->BeingDebugged=0` di x64dbg, atau aktifkan ScyllaHide + langkah nyata. |
| `reverse-engineering/README.md` (→01-09) | Butir 6 menjanjikan **"Deteksi & Mitigasi" defender** tapi tak ada di satu file pun (semua pakai "Anti-Forensik & Pitfall") — seluruh dimensi defender hilang di modul 40%. | Tambah blok "Deteksi & Mitigasi" tiap halaman (anti-debug berlapis + integrity check; anti-tamper/self-checksum; strip simbol; deteksi attach ptrace) ATAU revisi framing README. |

### Digital Forensic (Modul C)

| Area | Masalah | Fix ringkas |
|------|---------|-------------|
| `digital-forensic/02-network-forensic.md` | **Zeek** dinamai eksplisit kisi-kisi tapi hanya muncul di tabel Tools; bagian Contoh murni tshark. | Tambah `zeek -r capture.pcap` + analisis `conn.log`/`http.log`/`dns.log`/`files.log` (mis. `zeek-cut query` untuk DNS tunneling, `files.log` carving). |
| `digital-forensic/05-memory-forensic.md` | Akuisisi RAM Linux (LiME/AVML) ditunjukkan tapi tak ada satu plugin analisis **Linux Vol3** (`linux.*`) — diajarkan dump tapi tak analisis. | Tambah `linux.pslist`/`pstree`/`bash`/`malfind`/`check_syscall`/`lsmod` + mini-lab image Linux. |
| `digital-forensic/05-memory-forensic.md` | Daftar plugin Vol3 Windows belum optimal: `cmdscan`/`consoles` (lokasi flag klasik), `filescan`+`dumpfiles`, `svcscan`, `vadinfo`/`vadyarascan`/`vaddump`, `userassist` hilang. | Tambah plugin-plugin tsb + contoh (`windows.cmdscan`/`consoles`, `vadyarascan`). Catatan: `windows.clipboard` **TIDAK** ada di Vol3 (Vol2-only) — jangan ditambah. |
| `digital-forensic/06-malware-analysis.md` | Kisi menuntut static+dynamic+sandbox tapi Contoh/Mini-Lab nyaris seluruhnya statis; CAPE/INetSim/Procmon/Regshot hanya di tabel tanpa walkthrough detonasi. | Tambah blok behavioral-run: snapshot → INetSim/FakeNet-NG → Procmon+Regshot diff → Wireshark, tunjukkan IOC (Run key, beacon C2) + submit CAPE. |
| `digital-forensic/03-log-forensic.md` | Kisi sebut SIEM/Splunk tapi Splunk hanya satu query trivial `stats count by`. | Perdalam: korelasi `4625→4624` (brute sukses) via `transaction`/`stats earliest/latest`, deteksi webshell via `rex`, `timechart` + index/sourcetype. |
| `digital-forensic/05-memory-forensic.md` | **Bug akurasi:** `awk '{print $2}'` ambil PPID bukan PID → lab pslist-vs-psscan (proses tersembunyi) gagal/menyesatkan. | Ubah ke `awk 'NR>1{print $1}'` sebelum sort/comm. |

### Meta / Paket-level (Indeks, Setup, Audit)

| Area | Masalah | Fix ringkas |
|------|---------|-------------|
| `modul-c-defensive-ctf/README.md` | Dari dua objektif resmi Modul C (40%), hanya RE+forensik yang tersurat; **SIEM threat-hunting & anomaly-detection** (§4.2.3) bukan kategori bernama — hanya tanda kurung di "Log Forensic". | Angkat "SIEM Threat Hunting & Anomaly Detection" jadi kategori kelas-satu (atau rename/expand DF Log Forensic) + surahkan format §4.2.3 (live VM SIEM, hunting query). |
| `setup-lab/README.md` | §4.2.3 mewajibkan unduh **VM SIEM** tapi setup tak cantumkan satu platform (Wazuh/Splunk/Security Onion/Elastic). | Tambah seksi SIEM + link unduh + panduan RAM + opsi ringan (Wazuh single-node / EVTX offline via chainsaw/hayabusa). |
| `setup-lab/README.md` | Persyaratan perangkat peserta resmi §5.2 (CPU 8-core, RAM 8GB, HDD 256GB, **wajib converter USB-to-LAN**, familiarisasi ≤2 jam H-1) tak pernah disebut. | Tambah kotak "Persyaratan Perangkat Peserta (resmi §5.2)" + catatan §5.1 alat juri tak tergantikan. |
| `setup-lab/README.md` | Seksi Tooling hanya tool hardening Windows; toolchain analisis Modul B+C (60% bobot: Ghidra/Volatility3/Burp/pwntools/SageMath/x64dbg/jadx/z3) tak disetup. | Tambah tabel "Toolchain Analisis (Modul B & C)" memetakan kategori→tool→perintah instal. |
| `README.md` (utama) | **Judgement = POC ~30% skor** (§3.2.3 J10/modul, rubrik §3.5 0-3) tapi tak ada satu halaman pun yang mengajarkan cara menulis POC/writeup/executive summary. | Buat halaman "Panduan Menulis POC/Writeup & Executive Summary" (template + pemetaan rubrik 0-3 + contoh baik/buruk), tautkan dari README modul-b & modul-c. |
| `audit-kompetisi-2024-2025.md` / `latihan-wsa-2025/README.md` | WSA menguji **AD CS 2-tier** (ESC1-8 sisi Red + deteksi Blue) — paket tak punya halaman AD CS/PKI sama sekali (diakui kandidat, di luar kisi resmi 2026). | Bangun modul AD CS/PKI (deploy 2-tier+autoenroll, ESC1-8 Certify/Certipy, deteksi certutil/event) ATAU scope-out eksplisit di README. |
| `audit-kompetisi-2024-2025.md` / `latihan-wsa-2025/README.md` | WSA menguji **firewall perimeter/IDS** (default-deny, OpenVPN, Snort custom rule) — paket hanya ajarkan Defender Firewall; setup cantumkan pfSense/OPNsense tanpa konten. | Tambah modul perimeter/IDS (pfSense default-deny + VLAN + OpenVPN + Snort/Suricata diuji nmap) ATAU scope-out eksplisit. |

---

## Temuan Minor (90) — ringkas

**Windows (9):** PAM JIT/TTL native (KDC pangkas lifetime TGT) membaur dengan Shadow Principal MIM · Restricted Admin tanpa caveat PtH (utamakan Remote Credential Guard) · gMSA tak sebut sMSA/dMSA(BadSuccessor)/SPN · audit ACL DCSync (`1131f6aa`/`1131f6ad`) tak ada · audit constrained/RBCD delegation tak ada · lab AD hanya latih ~5/17 topik (NTLM/LDAP signing/FAST tak hands-on) · Kerberos Armoring/FAST diklaim memitigasi Kerberoasting tanpa nuansa (auth Kerberoast klasik tetap perlu AES) · AppLocker default PATH rule rawan bypass sub-folder writable (`%WINDIR%\Tasks/Temp`) · lab GPO tak import baseline Domain Controller.

**Windows 04-07 (9):** RC4 SChannel (TLS) dikelirukan memitigasi Kerberoasting (subsistem berbeda) · RDP TLS tanpa ganti cert default self-signed (rawan MITM) · enumerasi SCHANNEL\Ciphers tak lengkap (RC4 40/56/64, DES 56/56, NULL) · ASR per-rule exclusions (`-AttackSurfaceReductionOnlyExclusions`) tak disebut · label `(ManagedProductsConfigured)` tak terdokumentasi Microsoft · tabel Logon Type tak lengkap (kurang 4/5/7/8 cleartext/9 NewCredentials) · Sysmon Event 6 (Driver loaded/BYOVD) hilang · cross-ref `(#)` anchor kosong di 06 · konflik port 5985 antar Modul 04 vs 06 tak direkonsiliasi di checklist 07.

**Linux (7):** `pam_unix.so nullok` (password kosong) tak disebut · sudo I/O logging (`log_input`/`log_output`+`sudoreplay`) tak ada · auditd lewat kategori CIS (wtmp/btmp watch, EACCES/EPERM, mount, MAC-policy) · remediasi default-cred Tomcat (`tomcat-users.xml`) + tabel default-cred umum tak ada · iptables legacy & blok `Match` sshd_config tak dicontohkan · unit/timer systemd writable (vektor privesc) tak disinggung · README Linux janjikan seksi "Tools"/"Indikator" yang tak ada di 5 file.

**Crypto (7):** substitution (26!) satu-satunya cipher tanpa contoh terkerja · repeating-key XOR tanpa kode Python (hanya xortool) · singular curve tanpa snippet pemetaan · HNP/lattice tanpa konstruksi matriks konkret · Bleichenbacher e=3 tak tunjukkan konstruksi blok PKCS#1 · referensi "HTB BBGun06" tak terverifikasi · README crypto melewatkan "Indikator" di daftar template.

**Web 01-19 (10):** artefak `</content>`/`</invoke>` di akhir `08-directory-traversal` · 2FA broken logic/state-machine tak didaftar (03) · argument injection vs OS command injection tak dibahas (06) · double-submit cookie CSRF tanpa PoC (05) · favicon hash tanpa command (mmh3/Shodan) (04) · SnakeYAML/JNDI Java deser tak disinggung (11) · Jenkins `/script` "tanpa auth" tidak akurat (butuh Administer) (13) · V8 `Math.random` tanpa solver z3 (14) · DN injection (RFC 4514) tanpa contoh (17) · `javascriptEnabled` masih default `true` (deprecate 8.0, bukan dimatikan) (19).

**Web 20-37 (15):** WAF-bypass SQLi tipis (24) · Tornado digabung Jinja2 padahal sintaks beda (27) · cross-ref smuggling→`30-web-cache-deception` hilang (22) · string `gopher://` literal & Singularity/rbndr tak ditampilkan (26) · sisi JS type-juggling tanpa contoh/ cross-ref ke NoSQL (28) · Pug PP↔SSTI tak saling rujuk (20/27) · KeyInfo/cert substitution SAML hanya tersirat (23) · webshell ASPX tak echo stdout + ImageTragick tanpa payload (29) · WS proxy ke sqlmap/format socket.io tak ditunjukkan (31) · mXSS tanpa contoh payload (34) · `system-property('xsl:product-name')` khusus XSLT 2.0 (kosong di libxslt) + contoh Xalan tak baca stream (33) · label payload XPath #2 bertentangan isinya (TRUE, password diabaikan) (32) · XXE error-based via local DTD reuse tak dibahas (35) · API6/7/10 tipis + API7 tanpa cross-ref ke SSRF (37) · cache-poisoning header dijanjikan manifest tapi tak dibahas/di-cross-ref (30).

**Binary (6):** artefak `</content>`/`</invoke>` di akhir `09-heap` · broken-ref "Modul C — Hardening" (seharusnya Modul A 07-hardening-checklist) & "Log Forensic" tak ditautkan (05/08) · one_gadget tanpa penjelasan CONSTRAINT/contoh output · C++ vtable confusion hanya pseudo-code komentar (06) · walkthrough cyclic pakai placeholder abstrak + tanpa catatan 32-bit (01) · README binary melewatkan "Indikator" di template.

**Boot2Root (6):** grup docker/lxd privesc tak di tabel vektor (03) · gobuster dinamai kisi-kisi tapi contoh hanya feroxbuster/ffuf (01) · fingerprint CMS (wpscan/joomscan/droopescan) tak disinggung (01) · cron wildcard & writable `/etc/passwd` tanpa payload konkret (03) · README melewatkan "Indikator" di template · tiga mini-lab happy-path terisolasi tanpa capstone end-to-end.

**RE (7):** README template 8 vs struktur 9 bagian (Indikator + nama butir 6 salah) · arah assemble (keystone/smali/wat2wasm) tak dicontohkan, hanya disassembly (03) · cabang KNOWN crypto (AES/RC4/TEA) tanpa contoh dekripsi baku (08) · angr hanya 4 baris (tanpa state-explosion/find-avoid via xref) (01) · anti-disassembly hanya 1 teknik konkret (04) · Unicorn Engine tanpa contoh emulasi (06) · mini-lab tanpa biner target yang bisa diperoleh/di-link.

**Forensic (9):** Follow Stream FTP-DATA mode ASCII merusak biner (perlu raw/hex) (02) · BAM/DAM, Timeline/ActivitiesCache.db, VSS absen dari tabel artefak (04) · dekripsi Chromium DPAPI (Local State AES-GCM) tak disebut, hanya Firefox (04) · YARA tanpa contoh rule + CyberChef tak disebut (06) · Sysmon ID bernilai tinggi hilang (7/8/10 lsass/22 DNS) (03) · kolom "Cakupan" Malware Analysis kosong `—` + nama section template README tak sinkron · tak ada cross-ref antar-file forensik · NTFS ADS + scalpel/bulk_extractor tanpa contoh (01).

**Meta (6):** blok "Status & Cakupan" README terbaca "tuntas" tanpa caveat gap (AD CS/perimeter/POC/SIEM) · indeks Linux jauh lebih miskin dari Windows (tanpa peta serangan/MITRE/RHEL-vs-Debian) · kolom DF README "Malware Analysis | —" kosong · nama file `audit-kompetisi-2024-2025.md` usang (isi mencakup 2026) · `07-hardening-checklist.md` (scorecard hari-H) discoverability rendah di navigasi utama · "Phone/Media Forensic" (label "Contoh" TD §3.3, keyakinan rendah) tak terindeks eksplisit.

---

## Pola Lintas-Kategori

| Pola berulang | Manifestasi (contoh) | Skala |
|---------------|----------------------|-------|
| **Solver/payload tak runnable di teknik tersulit** | CBC oracle/GCM/Wiener (Crypto); heap UAF stub/double-free/FSOP/SROP (Binary); OOB/second-order/Oracle SQLi, SSTI engine, CSP bypass, jku/jwk (Web) | ~20 temuan, mayoritas **major** |
| **Subtopik/teknik bernama hilang di lokasi tepat** | NFS (Linux 03 + boot2root), cron wildcard, mitm6/IPv6, Json.NET, MAQ, AD CS, perimeter/IDS | ~12 temuan |
| **Coverage Windows dangkal di modul Windows-themed** | RE x64dbg/anti-debug hanya Linux; Upload bypass Apache-only tanpa `web.config` | 3 major |
| **Jalur AD foothold & cracking offline tak dieksekusi** | AS-REP/Kerberoast/secretsdump + hashcat absen (boot2root 02, Windows 02) | 4 major |
| **Dimensi blue-team/defender yang dijanjikan absen** | RE "Deteksi & Mitigasi"; Zeek & dynamic/sandbox hanya tabel Tools; SIEM hunting tak terindeks | 5+ temuan |
| **Mini-lab tak dapat dieksekusi / tak buktikan mitigasi / tanpa target** | solver heap stub; mini-lab RE tanpa biner; lab SMB hanya capture; tanpa capstone boot2root | 5 weak-lab |
| **Inkonsistensi template README (Indikator / Deteksi&Mitigasi)** | Crypto, Binary, Boot2root, RE, Forensic README | 5+ inconsistency |
| **Broken-ref & artefak generasi** | `</content>`/`</invoke>` (web 08, binary 09); `(#)` anchor (06); "Modul C — Hardening" (05/08); cross-ref hilang | ~7 temuan |
| **Tool disebut tanpa cara pakai** | one_gadget (constraint), Unicorn, bulk_extractor/scalpel, YARA, keystone, favicon mmh3 | ~7 temuan |

---

## Rekomendasi Berprioritas

### P0 — Dampak tertinggi (kerjakan lebih dulu)

1. **Perbaiki bug/akurasi yang merusak lab atau menyesatkan** (cepat, dampak besar):
   - `digital-forensic/05-memory-forensic.md`: ganti `awk '{print $2}'` → `awk 'NR>1{print $1}'` (lab proses-tersembunyi).
   - Hapus literal `</content>`/`</invoke>` di `web-exploitation/08-directory-traversal-dan-file-inclusion.md` & `binary-exploitation/09-heap-exploitation.md`.
   - `cryptography/02-attack-on-rsa.md`: hapus cross-check `RsaCtfTool --attack common_modulus...` yang mustahil.
   - `windows/01-privileged-access-management.md`: perbaiki footgun Auth Silo `-Enforce` (audit-only dulu + assign computer Tier 0).
   - `web-exploitation/32-xpath-injection.md`: koreksi label payload #2; `web-exploitation/31-web-sockets.md`: tambah caveat SameSite CSWSH.

2. **Tambahkan solver/payload yang BISA DIJALANKAN pada teknik bernilai-tertinggi.** Crypto: CBC padding oracle, GCM forbidden, Wiener (`04-attack-on-aes.md`, `02-attack-on-rsa.md`). Binary: program rentan + wrapper UAF lengkap, double-free, FSOP, SROP/ret2csu/ret2dlresolve (`09-heap-exploitation.md`, `08-bypass-protection.md`, `05-rop-chain.md`). Web: OOB/second-order/Oracle SQLi (`24`), SSTI engine (`27`), CSP bypass (`34`), `web.config` upload (`29`), jku/jwk JWT (`15`), Json.NET (`11`).

3. **Bangun jalur AD foothold + cracking end-to-end.** `boot2root/01-03` (NFS enum, AS-REP/Kerberoast/secretsdump, hashcat modes, reverse-shell one-liner, named privesc PwnKit/SeBackupPrivilege, horizontal/PtH) + `windows/02-active-directory-security.md` (perintah enumerasi AS-REP/Kerberoast/MAQ=0).

4. **Tutup subtopik kisi-kisi yang hilang di lokasi tepat.** NFS (`linux/03`+boot2root), cron wildcard (`linux/03`+boot2root), mitm6/IPv6 (`windows/04`+`07`), baris `pam_faillock` konkret (`linux/01-privileged-access-management-pam.md`).

### P1 — Kedalaman untuk menang + blue-team

5. **Coverage Windows nyata di RE & dimensi defender.** `reverse-engineering/02` (x64dbg/WinDbg TTD), `04` (bypass anti-debug Windows), dan blok "Deteksi & Mitigasi" di seluruh halaman RE (atau revisi framing README).
6. **Perdalam forensik dinamis/SIEM.** Zeek (`02`), Linux Vol3 + plugin Vol3 Windows tambahan (`05`), dynamic/sandbox run (`06`), Splunk SPL hunting + korelasi 4625→4624 (`03`).
7. **Perkuat setup-lab & Judgement.** Tabel toolchain analisis B+C, seksi VM SIEM, kotak persyaratan perangkat §5.2 (`setup-lab/README.md`); buat halaman Panduan POC/Writeup & Executive Summary (tautkan dari README modul-b/c).
8. **Lengkapi artefak hands-on bernilai tinggi.** WEF `subscription.xml` (`windows/06`), PAW konkret (`windows/01`), MachineAccountQuota di checklist (`windows/02`+`07`).

### P2 — Konsistensi, polish, scope

9. **Selaraskan template README & perbaiki referensi.** Tambah "Indikator"/perbaiki nama "Deteksi & Mitigasi" di README crypto/binary/boot2root/RE/forensic; perbaiki `(#)` anchor (`windows/06`), "Modul C — Hardening" (`binary 05/08`), cross-ref smuggling→`30` & antar-file forensik; rename `audit-kompetisi-2024-2026.md`; tambah caveat di blok "Status & Cakupan" README utama; expose `07-hardening-checklist.md` & perkaya indeks Linux.
10. **Putuskan scope modul kandidat.** AD CS/PKI dan perimeter/IDS (firewall/Snort): bangun modulnya ATAU scope-out eksplisit di README utama agar klaim kelengkapan tidak berlebihan.
11. **Sisa enrichment minor.** WAF-bypass SQLi, SnakeYAML/JNDI, string gopher SSRF, mXSS, XXE local-DTD, default-cred Tomcat, BAM/DAM+VSS, Chromium DPAPI, YARA/CyberChef, Sysmon ID 7/8/10/22, one_gadget constraint, dll.
