# 1. Privileged Access Management (PAM)

> Privileged Access Management di Linux adalah disiplin mengelola **siapa boleh menjadi root**, **dengan cara apa**, dan **terekam di mana**. Dari sudut pandang penyerang, satu shell user biasa hampir tidak pernah jadi tujuan akhir — yang dikejar adalah UID 0. Jalur tercepat ke sana adalah `sudo` yang terlalu longgar, `su` yang terbuka untuk semua, `pkexec`/polkit yang bisa di-abuse, atau login root langsung lewat SSH. Modul ini menutup jalur-jalur itu dengan prinsip *least privilege*, *separation of duties* (sudo menggantikan su/root langsung), dan *defense-in-depth* pada lapisan autentikasi.

> **Penting — dua makna "PAM".** Judul bab ini memakai **PAM = Privileged Access Management** (payung konsep, paralel dengan modul Windows). Tetapi di dunia Linux singkatan **PAM** juga berarti **Pluggable Authentication Modules** — kerangka `pam.d` yang menjadi salah satu *sub-topik* bab ini. Sepanjang halaman, "Privileged Access Management" ditulis lengkap; "PAM/`pam.d`" merujuk ke Pluggable Authentication Modules.

> Paralel konsep di Windows (tiering, PAW, JIT, LAPS): [../windows/01-privileged-access-management.md](../windows/01-privileged-access-management.md). Halaman ini tidak mengajarkan ulang Windows — hanya menautkan saat konsepnya mirip.

## Daftar Isi

1. [Konsep & Tujuan](#1-konsep--tujuan)
2. [Kerangka PAM (`pam.d`) — Struktur & Alur Kontrol](#2-kerangka-pam-pamd--struktur--alur-kontrol)
3. [Password Quality, History & Account Lockout via PAM](#3-password-quality-history--account-lockout-via-pam)
4. [`sudo` & `sudoers` — Eskalasi Privilege Terkendali](#4-sudo--sudoers--eskalasi-privilege-terkendali)
5. [`su` — Membatasi dengan `pam_wheel`](#5-su--membatasi-dengan-pam_wheel)
6. [polkit & `pkexec`](#6-polkit--pkexec)
7. [Root Login & Higiene UID 0](#7-root-login--higiene-uid-0)
8. [Serangan Umum & Mitigasi](#serangan-umum--mitigasi)
9. [Hardening Checklist (Modul Ini)](#hardening-checklist-modul-ini)
10. [Lab Praktik](#lab-praktik)
11. [Perintah Audit/Verifikasi](#perintah-auditverifikasi)
12. [Referensi](#referensi)

---

## 1. Konsep & Tujuan

Privileged Access Management di Linux bertumpu pada empat prinsip. Penilai LKS sering bertanya *kenapa*, bukan hanya *bagaimana* — kuasai definisinya.

| Prinsip | Definisi singkat | Implikasi praktis di Linux |
|---|---|---|
| **Least Privilege** | Beri hak seminimal mungkin untuk satu tugas. | `sudo` per-perintah, bukan `(ALL) ALL`; tidak ada UID 0 ganda. |
| **Separation of Duties** | Eskalasi privilege harus eksplisit, terkontrol, dan terlog. | Pakai `sudo` (terlog, granular) menggantikan `su`/login root langsung. |
| **Defense-in-Depth** | Banyak lapisan: kebijakan password, lockout, pembatasan `su`, polkit, root login. | Satu kontrol jebol tidak langsung memberi root. |
| **Auditability** | Setiap penggunaan privilege harus terekam dan terverifikasi. | Log `sudo`, integritas `pam.d`, jejak `auth.log`/`secure` (-> **Modul 05**). |

**Permukaan privilege yang dikelola bab ini:**

| Mekanisme | File/komponen inti | Risiko bila salah konfigurasi |
|---|---|---|
| Pluggable Authentication Modules | `/etc/pam.d/`, `/etc/security/*.conf` | Password lemah, tanpa lockout, modul backdoor |
| `sudo` | `/etc/sudoers`, `/etc/sudoers.d/` | Privilege escalation instan (GTFOBins, `NOPASSWD`) |
| `su` | `/etc/pam.d/su`, group `wheel`/`sudo` | Switch ke root tanpa kontrol/audit |
| polkit | `/etc/polkit-1/`, `pkexec` (SUID) | LPE (PwnKit), authz bypass |
| root login | `sshd_config`, `/etc/passwd`, `/etc/shadow` | Brute force langsung ke akun paling kuat |

**Tujuan modul:** menjadikan `sudo` sebagai satu-satunya jalur eskalasi yang sah dan terekam, mematikan jalur liar (root SSH, `su` bebas, `pkexec` rentan), dan mengeraskan lapisan autentikasi (`pam.d`) agar password lemah dan brute force tidak lolos.

**Batas kepemilikan (jangan diajarkan ulang di sini):** SSH hardening menyeluruh (cipher, key-only, `MaxAuthTries`) milik **Modul 04**; SUID/SGID, capabilities, `PATH`, dan cron yang bisa di-eskalasi milik **Modul 03**; `auditd`, `rsyslog`/`journald`, dan retensi log milik **Modul 05**. Bab ini hanya menyentuh `PermitRootLogin` seperlunya karena terkait langsung akses root.

> **Build acuan:** Ubuntu/Debian (utama). Padanan RHEL/Rocky diberi catatan saat berbeda. Nilai numerik diankor ke **CIS Benchmark** (Ubuntu 22.04 / RHEL 9) dan *man page*; selalu cek ulang angka ke teks benchmark versi terbaru sebelum dipakai di lomba.

---

## 2. Kerangka PAM (`pam.d`) — Struktur & Alur Kontrol

**APA.** **Pluggable Authentication Modules (PAM)** adalah lapisan abstraksi yang dipanggil oleh layanan (`login`, `sshd`, `sudo`, `su`, `passwd`, `cron`) untuk mengautentikasi user, tanpa tiap program menulis logika auth sendiri. Konfigurasi per-layanan ada di `/etc/pam.d/<service>`; modul `.so` ada di `/lib/x86_64-linux-gnu/security/` (Debian/Ubuntu) atau `/lib64/security/` (RHEL).

**KENAPA.** Hampir semua kontrol akses bab ini (kompleksitas password, lockout, pembatasan `su`) ditegakkan sebagai baris di `pam.d`. Salah satu baris → kontrol tidak menyala (Measurement = 0). Sebaliknya, modul `pam.d` jahat yang disisipkan penyerang (`pam_exec.so` yang mencatat password, atau modul backdoor) adalah teknik *persistence* nyata — **MITRE T1556.003**. Karena itu memahami alur dan menjaga integritas `pam.d` adalah inti.

**Cara kerja — empat tipe & flag kontrol.**

| Komponen | Nilai | Arti |
|---|---|---|
| **Tipe (management group)** | `auth` | Membuktikan identitas (password, dsb). |
| | `account` | Validasi non-auth: akun expired? jam akses? |
| | `password` | Saat **mengganti** kredensial (kebijakan kekuatan). |
| | `session` | Setup/teardown sesi (mount home, log, limits). |
| **Control flag** | `required` | Harus sukses; kegagalan dicatat tapi sisa stack tetap dijalankan. |
| | `requisite` | Harus sukses; kegagalan **langsung** menghentikan stack. |
| | `sufficient` | Sukses langsung meloloskan (bila tak ada `required` gagal sebelumnya). |
| | `optional` | Hasil diabaikan kecuali ia satu-satunya modul. |
| | `include` / `substack` | Sisipkan stack file lain (mis. `common-auth`). |

Bentuk modern memakai sintaks granular `[success=1 default=ignore]` menggantikan flag sederhana.

**CARA — JANGAN edit `common-*` mentah-mentah.** Ini kesalahan klasik yang membuat kontrol "hilang" diam-diam:

- **Ubuntu/Debian:** file `common-auth`, `common-account`, `common-password`, `common-session` dikelola oleh **`pam-auth-update`**. Edit tangan bisa **ditimpa** saat paket/`pam-auth-update` berjalan. Tambahkan profil lewat `/usr/share/pam-configs/` lalu jalankan `pam-auth-update`, atau edit dengan paham bahwa baris di luar penanda dapat bertahan tetapi blok auto-generate bisa direset.
- **RHEL/Rocky 8+:** `/etc/pam.d/system-auth` dan `password-auth` dikelola **`authselect`**. Edit tangan akan di-revert; pakai `authselect` dengan fitur seperti `with-faillock`, lalu `authselect apply-changes`.

```bash
# Lihat stack auth yang efektif untuk satu layanan
cat /etc/pam.d/sshd
cat /etc/pam.d/common-auth        # Ubuntu/Debian
# RHEL: cat /etc/pam.d/system-auth

# Integritas pam.d — bandingkan dengan paket (deteksi modul/baris disusupkan)
debsums -c | grep -i pam          # Debian/Ubuntu (paket: debsums)
rpm -Va | grep -E 'pam|/etc/pam'  # RHEL/Rocky

# RHEL: kelola lewat authselect, jangan edit system-auth langsung
authselect current
authselect enable-feature with-faillock && authselect apply-changes
```

> Hashing password disetel di `pam_unix.so` dan `/etc/login.defs` (`ENCRYPT_METHOD`). Default modern: **yescrypt** (Debian 11+ / Ubuntu 22.04+), **sha512** (RHEL). Hindari `md5`.

---

## 3. Password Quality, History & Account Lockout via PAM

**APA.** Tiga modul `pam.d` menegakkan kebijakan kredensial: `pam_pwquality.so` (kompleksitas — pengganti `pam_cracklib.so` yang usang), `pam_pwhistory.so` (larangan reuse), dan `pam_faillock.so` (lockout setelah gagal — pengganti `pam_tally2.so`/`pam_tally.so` yang sudah dihapus).

**KENAPA.** Password lemah + tanpa lockout = brute force (**T1110.001**) dan password guessing lolos langsung ke akun ber-`sudo`. Ketiganya adalah kontrol Measurement langsung di CIS dan paling sering diuji.

**CARA — kompleksitas (`/etc/security/pwquality.conf`).**

| Opsi | Nilai (CIS L1) | Arti |
|---|---|---|
| `minlen` | `14` | Panjang minimum. |
| `minclass` | `4` | Wajib 4 kelas (huruf besar/kecil/angka/simbol). |
| `dcredit` `ucredit` `lcredit` `ocredit` | `-1` (bila tak pakai `minclass`) | Minimal 1 tiap jenis (kredit negatif = wajib). |
| `maxrepeat` | `3` | Maksimal karakter berturut sama. |
| `difok` | `2` | Minimal karakter beda dari password lama. |
| `enforce_for_root` | (set) | Berlakukan juga untuk root. |

```bash
# Set kebijakan kompleksitas (sumber tunggal, dibaca pam_pwquality)
sudo sed -i 's/^# *minlen.*/minlen = 14/'     /etc/security/pwquality.conf
sudo sed -i 's/^# *minclass.*/minclass = 4/'  /etc/security/pwquality.conf
grep -E '^(minlen|minclass|maxrepeat|difok)' /etc/security/pwquality.conf
```

**CARA — lockout (`/etc/security/faillock.conf`).** Pendekatan modern memusatkan parameter di file ini; baris `pam_faillock.so` cukup memanggil tanpa argumen.

| Opsi | Nilai (CIS L1) | Arti |
|---|---|---|
| `deny` | `5` | Kunci setelah 5 gagal. |
| `unlock_time` | `900` | Buka otomatis setelah 900 detik. |
| `fail_interval` | `900` | Jendela penghitungan gagal. |
| `even_deny_root` / `root_unlock_time` | hati-hati | Kunci root juga (risiko lockout total — pikirkan akses fisik/recovery dulu). |

```bash
# Ubuntu 22.04+: parameter di faillock.conf
printf 'deny = 5\nunlock_time = 900\nfail_interval = 900\n' | sudo tee -a /etc/security/faillock.conf
# RHEL: aktifkan lewat authselect (mengelola baris pam secara aman)
# authselect enable-feature with-faillock && authselect apply-changes

# Lihat & reset hitungan gagal sebuah user (perintah resmi util faillock)
faillock --user alice
sudo faillock --user alice --reset
```

**CARA — baris `pam_faillock.so` konkret di stack (yang paling sering diuji).** Parameter ada di `faillock.conf`, tetapi **empat baris** ini yang membuat lockout benar-benar menyala. Posisi `{preauth|authfail|authsucc}` **harus** sesuai letaknya di stack `auth`, plus satu baris `account`. Bentuk apa adanya dari `/etc/pam.d/system-auth` RHEL 9 (dihasilkan `authselect` — **jangan** diedit tangan):

```text
# /etc/pam.d/system-auth (RHEL 9) — dikelola authselect
auth        required                  pam_faillock.so preauth   # 1) SEBELUM cek password: tolak bila akun sudah terkunci
auth        [success=1 default=bad]   pam_unix.so nullok        # modul auth utama (lihat catatan 'nullok' di bawah)
auth        [default=die]             pam_faillock.so authfail  # 2) SETELAH password GAGAL: catat kegagalan
auth        sufficient                pam_faillock.so authsucc  # 3) SETELAH password SUKSES: reset hitungan gagal
auth        required                  pam_deny.so
account     required                  pam_faillock.so           # 4) tahap ACCOUNT: tegakkan status terkunci
account     required                  pam_unix.so
```

- **`preauth`** dipanggil sebelum modul yang menanyakan password → menolak login bila user sudah melewati `deny`.
- **`[success=1 default=bad]` pada `pam_unix.so`** (bukan `sufficient`) penting: saat password **benar**, ia melompati 1 baris (`authfail`) dan mendarat tepat di `authsucc` agar hitungan gagal **di-reset**. Memakai `sufficient` akan men-*short-circuit* stack dan membuat baris `authsucc` **tak pernah** dijalankan (counter tak pernah bersih).
- **`authfail`** dipanggil setelah hasil auth diketahui **gagal** → mencatat kegagalan ke tally (`/var/run/faillock/<user>`).
- **`authsucc`** dipanggil setelah auth **sukses** → membersihkan hitungan gagal user.
- baris **`account`** wajib ada agar status terkunci ditegakkan; `pam_faillock` sebagai account module mensyaratkan `preauth` juga terpasang.

> **`nullok` (password kosong) — minor yang sering terlewat.** Argumen `nullok` pada `pam_unix.so` mengizinkan login ke akun yang **passwordnya kosong** (field hash kosong di `/etc/shadow`). CIS mensyaratkan **menghapus `nullok`** agar akun tanpa password tidak bisa login sama sekali. Verifikasi: `grep -E 'pam_unix.so.*nullok' /etc/pam.d/* /etc/pam.d/common-* 2>/dev/null` → idealnya **tidak ada** (RHEL: di `system-auth`/`password-auth`). Pada Ubuntu, hilangkan `nullok` dari `common-auth`/`common-password` lewat profil pam-configs, bukan edit mentah.

> **Ubuntu — pasang via pam-configs, bukan edit `common-auth` mentah.** Ubuntu 22.04+ menyertakan profil `faillock` & `faillock_notify` di `/usr/share/pam-configs/`. Aktifkan agar baris preauth/authfail/account disisipkan ke `common-auth`/`common-account` pada **urutan yang benar** (preauth sebelum `pam_unix`, authfail/account sesudahnya — diatur oleh field `Priority` di profil, bukan diketik manual):
>
> ```bash
> sudo pam-auth-update --enable faillock faillock_notify
> grep pam_faillock /etc/pam.d/common-auth /etc/pam.d/common-account   # konfirmasi baris terpasang
> ```

> **Ubuntu — `faillock.conf` tidak aktif sendirian.** Parameter di atas baru menyala bila baris `pam_faillock.so` (preauth/authfail/authsucc) benar-benar ada di stack `common-auth`/`common-account`. Stock Ubuntu **tidak** menambahkannya otomatis — sisipkan lewat profil `/usr/share/pam-configs/` lalu `pam-auth-update` (jangan edit `common-auth` mentah). Tanpa baris itu, `faillock.conf` "terkonfigurasi" tetapi lockout tak pernah jalan (Measurement = 0). Verifikasi: `grep pam_faillock /etc/pam.d/common-auth`. (RHEL: `authselect enable-feature with-faillock` menambah baris ini otomatis.)

**CARA — baris `password` konkret (pwquality + pwhistory).** Sama seperti faillock, kebijakan ini baru jalan bila baris modulnya benar-benar ada di stack `password`. Bentuk konkret di `common-password` (Ubuntu) / `system-auth` & `password-auth` (RHEL):

```text
# stack 'password' — kekuatan & larangan reuse
password requisite                    pam_pwquality.so retry=3              # kompleksitas (param di pwquality.conf)
password requisite                    pam_pwhistory.so remember=24 use_authtok  # larang reuse N password terakhir
password [success=1 default=ignore]   pam_unix.so obscure use_authtok try_first_pass yescrypt  # RHEL: sha512
password requisite                    pam_deny.so
```

- `pam_pwquality.so` membaca aturan dari `/etc/security/pwquality.conf` (sumber tunggal `minlen`/`minclass` di atas); `retry=3` = beri 3 kesempatan sebelum gagal.
- `pam_pwhistory.so remember=24` menolak 24 password terakhir (disimpan di `/etc/security/opasswd`); `use_authtok` memakai password yang sudah diminta modul sebelumnya, bukan bertanya ulang.
- Pada Ubuntu, sisipkan via `pam-auth-update` (paket `libpam-pwquality`), jangan tulis langsung ke `common-password` mentah.

**CARA — history & aging.** `pam_pwhistory.so remember=N` mencegah reuse (disimpan di `/etc/security/opasswd`). Aging password diatur di `/etc/login.defs`.

```bash
# /etc/login.defs — aging & hashing
PASS_MAX_DAYS   365
PASS_MIN_DAYS   1
PASS_WARN_AGE   7
ENCRYPT_METHOD  YESCRYPT      # RHEL: SHA512
```

> Nilai `remember` (riwayat password): CIS menetapkan **≥ 5**; banyak baseline hardening memakai **24**. Ini contoh angka yang **wajib dicek ulang** ke benchmark versi yang dipakai juri — jangan mengarang.

---

## 4. `sudo` & `sudoers` — Eskalasi Privilege Terkendali

**APA.** `sudo` menjalankan perintah sebagai user lain (default root) berdasarkan kebijakan di `/etc/sudoers` dan drop-in `/etc/sudoers.d/`. Inilah jalur eskalasi privilege yang **sah, granular, dan terlog** — pengganti `su`/root langsung.

**KENAPA.** `sudoers` yang longgar adalah penyebab privilege escalation paling umum (**T1548.003**). `(ALL) NOPASSWD: ALL`, atau mengizinkan editor/interpreter/`less`/`vi`/`find` lewat sudo, memberi root instan via **GTFOBins**. Wildcard dan path relatif memperparah. `sudo` juga punya CVE berdampak tinggi — **CVE-2021-3156 (Baron Samedit)** dan **CVE-2019-14287** (bypass `!root` via `-u#-1`): jaga `sudo` tetap ter-patch.

**CARA — selalu lewat `visudo`.** `visudo` mengunci file dan **memvalidasi sintaks** sebelum simpan; sintaks salah bisa mengunci semua akses sudo.

```bash
sudo visudo                      # edit /etc/sudoers (tervalidasi)
sudo visudo -f /etc/sudoers.d/ops   # edit drop-in
sudo visudo -c                   # cek sintaks semua file sudoers
```

**CARA — `Defaults` yang dianjurkan CIS.**

| `Defaults` | Nilai | KENAPA |
|---|---|---|
| `use_pty` | (set) | Jalankan di pseudo-tty; mempersempit pelarian shell anak. |
| `logfile` | `/var/log/sudo.log` | Log khusus sudo (korelasi -> **Modul 05**). |
| `log_input,log_output` | (set) | **I/O logging**: rekam seluruh input/output sesi sudo ke `/var/log/sudo-io/`, dapat diputar ulang dengan `sudoreplay` (forensik & akuntabilitas). |
| `!authenticate` | **JANGAN dipakai** | Mematikan permintaan password = eskalasi tanpa auth. |
| `timestamp_timeout` | `15` (jangan `-1`) | `-1` = timestamp tak pernah kedaluwarsa (berbahaya). |
| `passwd_tries` | `3` | Batasi percobaan password. |
| `env_reset` + `secure_path` | (default) | Bersihkan environment & paksa PATH aman. |

```bash
# Contoh isi /etc/sudoers.d/00-hardening (via: sudo visudo -f ...)
Defaults  use_pty
Defaults  logfile="/var/log/sudo.log"
Defaults  log_input, log_output
Defaults  iolog_dir="/var/log/sudo-io"
Defaults  timestamp_timeout=15
Defaults  passwd_tries=3
Defaults  !visiblepw

# Least privilege: beri perintah spesifik, bukan ALL
# (path absolut; hindari wildcard & program yang punya shell-escape)
%webops  ALL=(root)  /usr/bin/systemctl restart nginx, /usr/bin/systemctl status nginx
```

**CARA — I/O logging & `sudoreplay` (akuntabilitas penuh).** `log_input`/`log_output` merekam **seluruh keystroke dan output** tiap sesi sudo ke `/var/log/sudo-io/` (satu sub-direktori ber-ID per sesi, bukan teks polos). Ini menutup celah audit: `logfile` hanya mencatat *perintah apa* dijalankan, sedangkan I/O log merekam *apa yang sebenarnya terjadi* di dalam sesi interaktif (mis. shell yang di-spawn). Putar ulang dengan **`sudoreplay`**:

```bash
sudo sudoreplay -l                 # daftar sesi terekam (TSID, user, perintah, waktu)
sudo sudoreplay <TSID>             # putar ulang sesi seperti rekaman terminal (asciinema-style)
sudo sudoreplay -l user webops     # filter per-user
ls -ld /var/log/sudo-io            # direktori I/O log (default mode 700 root — jangan dibuat world-readable)
```

> I/O log bisa memuat data sensitif yang diketik dalam sesi (mis. password aplikasi). Jaga `/var/log/sudo-io` tetap `700 root:root`, dan forward salinannya off-host bersama log lain -> **Modul 05**.

**Hindari:** `user ALL=(ALL) NOPASSWD:ALL`; `Cmnd_Alias` berisi `/usr/bin/vi`, `less`, `awk`, `find`, `env`, `python`, `tar` (semua bisa spawn shell → root); wildcard seperti `/bin/chmod *`.

> **Pembatasan keanggotaan:** hanya user terpilih boleh ber-sudo. Di Ubuntu/Debian = group `sudo`; di RHEL/Rocky = group `wheel` (sudoers berisi `%wheel ALL=(ALL) ALL`). Audit anggotanya seperti audit Domain Admins di Windows.

---

## 5. `su` — Membatasi dengan `pam_wheel`

**APA.** `su` mengganti identitas ke user lain (default root) bila tahu password target. Secara default `su` bisa dicoba siapa saja — tanpa granularity dan dengan audit minim dibanding `sudo`.

**KENAPA.** Membiarkan `su` terbuka berarti setiap user bisa mencoba brute force password root secara lokal, dan eskalasi yang lolos tidak terekam serapi `sudo`. CIS menyarankan **membatasi `su`** sehingga eskalasi terpusat ke `sudo` yang terlog. Ini *separation of duties* dalam praktik.

**CARA.** Aktifkan `pam_wheel.so` di `/etc/pam.d/su`. Hanya anggota group penjaga yang boleh `su`.

```bash
# /etc/pam.d/su — uncomment / tambahkan:
auth  required  pam_wheel.so use_uid

# RHEL/Rocky: group penjaga = wheel (sudah ada). Pastikan baris di atas aktif.
grep -n pam_wheel /etc/pam.d/su
```

Pola CIS Ubuntu/Debian (di mana group `wheel` tak ada secara default): buat **group kosong** sebagai penjaga, sehingga praktis **tidak ada** yang boleh `su` — memaksa semua eskalasi lewat `sudo`.

```bash
sudo groupadd sugroup                       # group kosong sengaja
# /etc/pam.d/su:
# auth  required  pam_wheel.so use_uid group=sugroup
getent group sugroup                         # konfirmasi: tidak ada anggota
```

> `use_uid` mengevaluasi UID nyata pemanggil (bukan effective), mencegah bypass. Untuk hanya membatasi `su` **ke root** (bukan ke user lain), gunakan opsi `root_only`.

---

## 6. polkit & `pkexec`

**APA.** **polkit** (dulu *PolicyKit*) adalah kerangka otorisasi *fine-grained* agar proses tak-berhak meminta aksi privileged ke service sistem lewat D-Bus. `pkexec` adalah komponennya yang menjalankan program sebagai user lain — analog `sudo` untuk polkit, dan ber-**SUID root**.

**KENAPA.** `pkexec` adalah subjek **CVE-2021-4034 (PwnKit)** — memory corruption yang memberi root ke user lokal mana pun pada konfigurasi default, hadir 12+ tahun di hampir semua distro (**MITRE T1068**). polkit juga kena **CVE-2021-3560** (authz bypass via race `dbus-send`). Aturan polkit yang longgar dapat memberi *active session* hak admin tanpa password.

**CARA — patch & batasi.**

| Tindakan | Perintah / lokasi | Catatan |
|---|---|---|
| Patch polkit (utama) | `apt upgrade policykit-1` / `dnf update polkit` | Mitigasi definitif PwnKit & CVE-2021-3560. Di Ubuntu, patch PwnKit dikemas pada paket `policykit-1` (menarik `polkitd`+`pkexec`); paket `polkitd` saja tidak memuat binari `pkexec` yang rentan. |
| Cek versi | `pkexec --version` | Bandingkan dengan advisory distro. |
| Mitigasi darurat (bila belum bisa patch) | `sudo chmod u-s /usr/bin/pkexec` | Lepas SUID; bisa memutus fungsi pkexec yang sah. |
| Tetapkan admin identity | `/etc/polkit-1/rules.d/*.rules` | Default admin: group `sudo` (Ubuntu) / `wheel` (RHEL). |
| Audit aksi & otorisasi | `pkaction`, `pkcheck` | Lihat action terdaftar & default-nya. |

```bash
# Aturan polkit modern (JS) — tegaskan siapa "admin"
# /etc/polkit-1/rules.d/49-admin.rules
polkit.addAdminRule(function(action, subject) {
    return ["unix-group:sudo"];      # RHEL: "unix-group:wheel"
});

# Audit
pkaction | head                      # daftar action
pkaction --action-id org.freedesktop.policykit.exec --verbose
stat -c '%a %U' /usr/bin/pkexec      # default 4755 root (SUID)
```

> Action `.policy` (XML) ada di `/usr/share/polkit-1/actions/`; aturan (JS, polkit ≥ 0.106) di `/etc/polkit-1/rules.d/` & `/usr/share/polkit-1/rules.d/`. Sistem lama (polkit < 0.106) memakai `.pkla` di `/etc/polkit-1/localauthority/` — periksa keduanya saat audit.

---

## 7. Root Login & Higiene UID 0

**APA.** Mengontrol apakah root bisa login langsung — lewat SSH, konsol/tty — dan memastikan **hanya ada satu** akun ber-UID 0.

**KENAPA.** Login root langsung membuang jejak audit *siapa* yang bertindak (semua jadi "root") dan menyodorkan akun terkuat ke brute force (**T1110**, **T1078.003**). Akun UID 0 kedua adalah backdoor klasik (**T1136.001**). File `/etc/shadow` yang terbaca = panen hash root (**T1003.008**).

**CARA.**

| Tindakan | Perintah / lokasi | Catatan |
|---|---|---|
| Larang root SSH | `PermitRootLogin no` di `sshd_config` | Hardening SSH penuh -> **Modul 04**. |
| Kunci password root | `sudo passwd -l root` | Ubuntu mengunci root secara default; admin via `sudo`. |
| Pastikan UID 0 tunggal | `awk -F: '($3==0)' /etc/passwd` | Hanya `root` yang boleh muncul. |
| Lindungi shadow | `chmod 640 /etc/shadow; chown root:shadow /etc/shadow` | Cegah pembacaan hash. |
| Batasi tty root (legacy) | `/etc/securetty` + `pam_securetty.so` | **Usang**: dihapus di Debian 11+/RHEL 8+ — verifikasi keberadaannya dulu. |

```bash
# Larang root login SSH (drop-in lebih rapi daripada edit file utama)
echo 'PermitRootLogin no' | sudo tee /etc/ssh/sshd_config.d/10-rootlogin.conf
sudo sshd -t && sudo systemctl reload ssh   # validasi config sebelum reload

# Higiene UID 0 — tidak boleh ada UID 0 selain root
awk -F: '($3 == 0) { print $1 }' /etc/passwd

# Status kunci akun root (L = locked)
sudo passwd -S root
```

> **Jaga akses darurat (breakglass).** Sebelum `passwd -l root` + `PermitRootLogin no`, pastikan **minimal satu** akun non-root ber-`sudo` sudah teruji bisa login. Mengunci root **dan** kehilangan akun sudo = lockout total (paralel prinsip breakglass di [Windows 01](../windows/01-privileged-access-management.md)).

---

## Serangan Umum & Mitigasi

| Teknik penyerang | MITRE ATT&CK | Kontrol di modul ini yang memitigasi |
|---|---|---|
| Abuse Elevation Control — Sudo & Sudo Caching | T1548.003 | `sudoers` least-privilege, `use_pty`, no `NOPASSWD`/`!authenticate` (4) |
| Exploitation for Privilege Escalation (PwnKit, Baron Samedit) | T1068 | Patch polkit & sudo; lepas SUID `pkexec` darurat (6,4) |
| Brute Force / Password Guessing | T1110 / T1110.001 | `pam_faillock` lockout, batasi `su`, larang root SSH (3,5,7) |
| Valid Accounts — Local Accounts | T1078.003 | Pembatasan `su`, root login, kebijakan password kuat (3,5,7) |
| Create Account — Local Account (UID 0 ganda) | T1136.001 | Audit UID 0 tunggal (7) |
| OS Credential Dumping — /etc/passwd & /etc/shadow | T1003.008 | Permission `shadow` 640 root:shadow (7) |
| Modify Authentication Process — PAM | T1556.003 | Integritas `pam.d` (`debsums`/`rpm -Va`), kelola via pam-auth-update/authselect (2) |
| Account Manipulation | T1098 | Audit anggota group `sudo`/`wheel` (4) |

> SUID/SGID & capabilities umum (T1548.001) dibahas di **Modul 03**; deteksi berbasis log/audit (`auditd` rule untuk `/etc/sudoers`, `execve`) di **Modul 05**.

---

## Hardening Checklist (Modul Ini)

- [ ] `pam.d` dikelola dengan benar: Ubuntu via `pam-auth-update`/`/usr/share/pam-configs`, RHEL via `authselect` (bukan edit `system-auth` mentah).
- [ ] Integritas `pam.d` diverifikasi (`debsums -c` / `rpm -Va`) — tak ada modul/baris disusupkan.
- [ ] `pam_pwquality`: `minlen=14`, `minclass=4` (atau kredit `-1`), diankor ke CIS; baris `password ... pam_pwquality.so` ada di stack.
- [ ] `pam_faillock`: baris **preauth/authfail/authsucc** (`auth`) + **account** benar-benar terpasang di stack; `deny=5`, `unlock_time=900` aktif & teruji (tanpa mengunci diri sendiri).
- [ ] `pam_pwhistory remember` diset (cek angka CIS versi terpakai) + aging di `login.defs`.
- [ ] **`nullok` dihapus** dari `pam_unix.so` (tidak ada login ke akun berpassword kosong).
- [ ] `sudoers` least-privilege: perintah spesifik path-absolut; **tanpa** `NOPASSWD:ALL`/`!authenticate`/`timestamp_timeout=-1`.
- [ ] `Defaults use_pty` dan `logfile="/var/log/sudo.log"` aktif; **`log_input,log_output`** (I/O logging) aktif & `/var/log/sudo-io` = `700 root:root`; `visudo -c` bersih.
- [ ] `sudo` & `polkit` ter-patch (PwnKit/Baron Samedit ditutup).
- [ ] `su` dibatasi `pam_wheel.so use_uid` (group `wheel`/`sugroup` kosong).
- [ ] polkit admin identity tegas (`unix-group:sudo`/`wheel`); `pkexec` SUID-status diketahui.
- [ ] `PermitRootLogin no`; password root terkunci; **breakglass** sudo non-root teruji lebih dulu.
- [ ] Hanya **satu** akun UID 0 (`root`); `/etc/shadow` = `640 root:shadow`.

---

## Lab Praktik

**Prasyarat:** VM Ubuntu 22.04 (atau Rocky 9), login sebagai akun non-root ber-`sudo` (`alice`) untuk breakglass, paket `libpam-pwquality`/`libpam-modules` terpasang. **Snapshot dulu** — kontrol di bawah berisiko lockout. Semua perintah dijalankan dari shell `alice` dengan `sudo` kecuali disebut lain.

**Langkah 0 — Siapkan akun & grup uji (sekali saja).**
1. Buat user uji `testuser` (target kebijakan password/lockout) dan beri password awal yang KUAT (mis. ≥ 14 karakter agar lolos `minlen` nanti):
   ```bash
   sudo useradd -m -s /bin/bash testuser
   sudo passwd testuser
   ```
2. Buat grup `webops` (untuk Langkah 2) lalu masukkan `testuser`:
   ```bash
   sudo groupadd webops
   sudo usermod -aG webops testuser
   ```
3. Buat grup penjaga `su` yang **sengaja kosong** (untuk Langkah 3):
   ```bash
   sudo groupadd sugroup
   ```
4. (Ubuntu) Pasang baris `pam_faillock` ke stack — `faillock.conf` saja **tidak** mengaktifkan lockout:
   ```bash
   sudo pam-auth-update --enable faillock faillock_notify
   grep pam_faillock /etc/pam.d/common-auth     # → baris preauth/authfail muncul
   ```
   → tanpa langkah ini, lockout di Langkah 1 tidak akan pernah terpicu (Measurement = 0). (RHEL: dilakukan oleh `authselect enable-feature with-faillock` di Langkah 1.)

**Langkah 1 — Kebijakan password & lockout.**
1. Set kompleksitas password:
   ```bash
   sudo sed -i 's/^# *minlen.*/minlen = 14/'    /etc/security/pwquality.conf
   sudo sed -i 's/^# *minclass.*/minclass = 4/' /etc/security/pwquality.conf
   ```
2. Set parameter lockout (Ubuntu 22.04+; RHEL: `sudo authselect enable-feature with-faillock && sudo authselect apply-changes`):
   ```bash
   printf 'deny = 5\nunlock_time = 900\nfail_interval = 900\n' | sudo tee -a /etc/security/faillock.conf
   ```
3. Uji penolakan password lemah — masuk sebagai `testuser` (dari root tanpa password) lalu coba ganti password sendiri:
   ```bash
   sudo su - testuser
   passwd          # ketik password LAMA, lalu password BARU yang lemah (mis. "abc")
   exit            # kembali ke shell alice
   ```
   → ditolak: `BAD PASSWORD: The password is shorter than 14 characters` (di Ubuntu jangan andalkan `passwd --stdin` — flag itu khas RHEL).
4. Uji lockout — buka **terminal kedua**, login sebagai `alice` (BUKAN root), lalu jalankan `su - testuser` **5 kali** dan ketik password **SALAH** tiap kali (`su` membaca password dari tty, jadi tidak bisa di-pipe/loop):
   ```bash
   su - testuser     # ketik password salah → "su: Authentication failure"; ULANGI total 5x
   ```
5. Konfirmasi terkunci lalu reset (agar tidak mengganggu langkah berikutnya):
   ```bash
   sudo faillock --user testuser            # → 5 entri 'V' & status akun terkunci
   sudo faillock --user testuser --reset    # buka kunci untuk melanjutkan lab
   ```

**Langkah 2 — `sudoers` least-privilege.**
1. Buat drop-in tervalidasi:
   ```bash
   sudo visudo -f /etc/sudoers.d/00-hardening
   ```
   isi dengan:
   ```text
   Defaults  use_pty
   Defaults  logfile="/var/log/sudo.log"
   %webops  ALL=(root)  /usr/bin/systemctl restart nginx, /usr/bin/systemctl status nginx
   ```
2. Validasi sintaks:
   ```bash
   sudo visudo -c        # → setiap file "parsed OK"
   ```
3. Konfirmasi pembatasan — masuk ulang sebagai `testuser` (sesi login baru memuat keanggotaan `webops` yang ditambahkan di Langkah 0), lalu cek hak sudo-nya:
   ```bash
   sudo su - testuser
   id | grep webops       # → konfirmasi testuser kini anggota webops
   sudo -l                # (password testuser) → hanya 'systemctl restart/status nginx'
   sudo less /etc/shadow  # → ditolak: "user is not allowed to execute ... less"
   exit
   ```

**Langkah 3 — Batasi `su`.**
1. Tambahkan baris `pam_wheel` ke `/etc/pam.d/su` (Ubuntu pakai grup `sugroup` kosong dari Langkah 0):
   ```bash
   echo 'auth  required  pam_wheel.so use_uid group=sugroup' | sudo tee -a /etc/pam.d/su
   ```
   (RHEL/Rocky: grup penjaga = `wheel`; gunakan `auth required pam_wheel.so use_uid` tanpa `group=`.)
2. Konfirmasi — di terminal kedua sebagai `alice` (di luar `sugroup`), coba `su`:
   ```bash
   su -                                       # → "su: Permission denied"
   sudo grep pam_wheel /var/log/auth.log      # → tercatat penolakan pam_wheel
   ```

**Langkah 4 — polkit & root login.**
1. Update polkit (mitigasi PwnKit):
   ```bash
   sudo apt update && sudo apt upgrade -y policykit-1   # RHEL: sudo dnf update -y polkit
   ```
2. Larang root login SSH via drop-in, validasi, lalu reload:
   ```bash
   echo 'PermitRootLogin no' | sudo tee /etc/ssh/sshd_config.d/10-rootlogin.conf
   sudo sshd -t && sudo systemctl reload ssh            # RHEL: systemctl reload sshd
   ```
3. Konfirmasi:
   ```bash
   ssh root@localhost                          # → "Permission denied" tanpa sempat prompt password
   pkexec --version                            # → versi sudah dipatch sesuai advisory distro
   awk -F: '($3==0){print $1}' /etc/passwd     # → hanya 'root'
   ```

---

## Perintah Audit/Verifikasi

Semua perintah di bawah dijamin bisa dijalankan dan menyebut output yang diharapkan.

```bash
# 1) Sintaks sudoers valid?
sudo visudo -c
#   Harapan: setiap file "parsed OK".

# 2) Tidak ada NOPASSWD / !authenticate berbahaya?
sudo grep -REn 'NOPASSWD|!authenticate|timestamp_timeout=-1' /etc/sudoers /etc/sudoers.d/
#   Harapan: tidak ada baris keluar (kosong).

# 3) Defaults hardening sudo aktif?
sudo grep -RE 'use_pty|logfile' /etc/sudoers /etc/sudoers.d/
#   Harapan: muncul 'Defaults use_pty' dan logfile="/var/log/sudo.log".

# 4) su dibatasi pam_wheel?
grep -E '^auth.*pam_wheel.so' /etc/pam.d/su
#   Harapan: baris 'auth required pam_wheel.so use_uid' (aktif, tak di-comment).

# 5) Kebijakan password kuat (config DAN baris stack)?
grep -E '^(minlen|minclass)' /etc/security/pwquality.conf
grep -E 'pam_pwquality.so|pam_pwhistory.so' /etc/pam.d/common-password 2>/dev/null \
  || grep -E 'pam_pwquality.so|pam_pwhistory.so' /etc/pam.d/system-auth   # RHEL
#   Harapan: minlen = 14, minclass = 4 (atau setara CIS); baris pam_pwquality & pam_pwhistory ada di stack 'password'.

# 6) Lockout terkonfigurasi DAN keempat posisi terpasang di stack?
grep -E '^(deny|unlock_time)' /etc/security/faillock.conf
grep -nE 'pam_faillock.so.*(preauth|authfail|authsucc)' /etc/pam.d/common-auth 2>/dev/null \
  || grep -nE 'pam_faillock.so.*(preauth|authfail|authsucc)' /etc/pam.d/system-auth   # RHEL
grep -E '^account.*pam_faillock.so' /etc/pam.d/common-account /etc/pam.d/system-auth 2>/dev/null
#   Harapan: deny=5, unlock_time=900; preauth+authfail+authsucc (auth) DAN account pam_faillock muncul (tanpa ini, lockout tak jalan).

# 6b) Tidak ada nullok (password kosong tidak boleh login)?
grep -REn 'pam_unix.so.*nullok' /etc/pam.d/ 2>/dev/null
#   Harapan: kosong (nullok sudah dihapus).

# 6c) Sudo I/O logging aktif?
sudo grep -RE 'log_input|log_output' /etc/sudoers /etc/sudoers.d/ ; sudo sudoreplay -l 2>/dev/null | head
#   Harapan: Defaults log_input,log_output ada; sudoreplay -l mendaftar sesi terekam.

# 7) Root SSH dilarang?
sudo sshd -T 2>/dev/null | grep -i permitrootlogin
#   Harapan: permitrootlogin no.

# 8) Hanya satu UID 0?
awk -F: '($3==0){print $1}' /etc/passwd
#   Harapan: hanya 'root'.

# 9) Password root terkunci?
sudo passwd -S root
#   Harapan: kolom kedua 'L' (locked).

# 10) Integritas modul/konfig PAM?
rpm -Va | grep -E 'pam' || debsums -c 2>/dev/null | grep -i pam
#   Harapan: kosong (tidak ada file PAM yang termodifikasi di luar paket).

# 11) Status SUID pkexec & versi polkit (PwnKit)?
stat -c '%a %U %n' /usr/bin/pkexec; pkexec --version
#   Harapan: tahu status SUID (4755 default) & versi sudah dipatch sesuai advisory distro.
```

---

## Referensi

- **CIS Ubuntu Linux 22.04 LTS Benchmark** & **CIS Red Hat Enterprise Linux 9 Benchmark** — rujukan tunggal nilai numerik (`minlen`, `minclass`, `deny`, `unlock_time`, `remember`, `Defaults` sudo, pembatasan `su`/root). Selalu cek ulang angka ke teks benchmark versi terbaru.
- **Linux-PAM** — *man*: `pam.conf(5)`, `pam.d(5)`, `pam_unix(8)`, `pam_pwquality(8)`, `pam_pwhistory(8)`, `pam_faillock(8)`, `pam_wheel(8)`, `faillock(8)`, `pwquality.conf(5)`.
- **sudo** — *man* `sudoers(5)`, `visudo(8)`, `sudo(8)`, `sudoreplay(8)` (I/O log replay; `log_input`/`log_output`/`iolog_dir`); advisory **CVE-2021-3156 (Baron Samedit)**, **CVE-2019-14287**. **GTFOBins** (gtfobins.github.io) untuk daftar program yang bisa di-abuse via sudo.
- **polkit** — dokumentasi freedesktop (`pkexec(1)`, `pkaction(1)`, `pkcheck(1)`, rules `polkit(8)`); advisory **CVE-2021-4034 (PwnKit)** (Qualys; Red Hat RHSB-2022-001) & **CVE-2021-3560** (GitHub Security Lab / Kevin Backhouse; Red Hat RHSA-2021:2238).
- **Ubuntu** `pam-auth-update(8)` / `/usr/share/pam-configs`; **RHEL** `authselect(8)` — cara aman mengubah stack PAM.
- **MITRE ATT&CK** (attack.mitre.org) — T1548.003, T1068, T1110, T1078.003, T1136.001, T1003.008, T1556.003, T1098.

> Catatan modul terkait: SSH hardening menyeluruh & firewall (**Modul 04**), SUID/SGID/capabilities/`PATH`/cron (**Modul 03**), `auditd`/`rsyslog`/`journald` & retensi log (**Modul 05**). Paralel konsep Windows: [../windows/01-privileged-access-management.md](../windows/01-privileged-access-management.md).

> **Catatan etika.** Materi ini hanya untuk **lab pribadi, lingkungan kompetisi (CTF/LKS), atau sistem dengan izin tertulis eksplisit**. Tool dan teknik ofensif yang disebut (PwnKit, GTFOBins, brute force `su`) dipakai untuk **menguji dan mengeraskan pertahanan sendiri**, bukan menyerang sistem lain.
