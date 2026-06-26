# 3. Common Linux Misconfigurations

> Misconfiguration adalah celah paling sering dieksploitasi untuk **privilege escalation lokal** di Linux: bukan bug pada kode, melainkan izin, kepemilikan, dan jalur yang dibiarkan terlalu longgar. Dari sudut pandang penyerang yang sudah punya shell sebagai user biasa (post-exploitation), lima hal pertama yang dienumerasi adalah SUID/SGID binary, file/direktori world-writable, cron job yang bisa ditulis, PATH yang bisa dibajak, dan Linux capabilities yang salah pasang — masing-masing bisa langsung memberi root. Modul ini mengajarkan cara mengenali, menutup, dan memverifikasi kelima pola itu, dengan nilai di-anchor ke **CIS Benchmark** (Ubuntu/RHEL) dan best practice. Build acuan: **Ubuntu/Debian** sebagai utama; padanan **RHEL/Rocky** diberi catatan bila berbeda.

## Daftar Isi

1. [Konsep & Tujuan](#1-konsep--tujuan)
2. [SUID/SGID Binaries](#2-suidsgid-binaries)
3. [Permission File & Direktori Sensitif](#3-permission-file--direktori-sensitif)
4. [Cron & Scheduled Jobs](#4-cron--scheduled-jobs)
5. [PATH Hijacking](#5-path-hijacking)
6. [Linux Capabilities](#6-linux-capabilities)
7. [Serangan Umum & Mitigasi](#serangan-umum--mitigasi)
8. [Hardening Checklist (Modul Ini)](#hardening-checklist-modul-ini)
9. [Lab Praktik](#lab-praktik)
10. [Perintah Audit/Verifikasi](#perintah-auditverifikasi)
11. [Referensi](#referensi)

---

## 1. Konsep & Tujuan

Privilege escalation lewat misconfiguration bertumpu pada satu kenyataan: **kernel mengevaluasi izin, bukan niat.** Jika sebuah binary milik root berjalan dengan hak root (SUID), atau sebuah script yang dijalankan root bisa ditulis user biasa (cron/PATH), maka user biasa dapat memerintah kode berjalan sebagai root — tanpa exploit memori apa pun.

| Pola misconfig | Mekanisme eskalasi | Anchor kontrol |
|---|---|---|
| **SUID/SGID** | Binary berjalan dengan UID/GID pemilik (root), bukan pemanggil. | CIS — audit & minimalkan SUID/SGID, `nosuid` mount |
| **Permission longgar** | File sensitif terbaca (shadow) / world-writable bisa diubah. | CIS 6.1.x — mode & owner file sistem |
| **Cron writable** | Script yang dieksekusi root dapat diedit user biasa. | CIS 5.1.x — mode cron file/dir, restrict `cron.allow` |
| **PATH hijacking** | Direktori writable / relatif mendahului direktori sistem di `$PATH`. | Best practice — PATH absolut, hilangkan `.` |
| **Capabilities** | Bit kapabilitas (mis. `cap_setuid`) memberi hak parsial root. | CIS — audit `getcap`, hapus yang tak perlu |

**Tujuan modul:** menghapus *standing privilege* yang tidak perlu pada binary, file, dan task terjadwal, lalu memverifikasi tiap perubahan dengan perintah yang pasti jalan. Konsep ini adalah padanan Linux dari pengelolaan hak istimewa di Windows — lihat [`../windows/01-privileged-access-management.md`](../windows/01-privileged-access-management.md) (least privilege, assume breach) tanpa mengulang materi Windows.

**Batas modul (cross-ref):** pengelolaan **sudo/sudoers, su, PAM, polkit** ada di [`01-privileged-access-management-pam.md`](01-privileged-access-management-pam.md) — di sini hanya disinggung saat relevan. **Service berbahaya/terbuka** -> [`02-dangerous-exposed-services.md`](02-dangerous-exposed-services.md). **SSH/firewall/binding** -> [`04-network-service-security.md`](04-network-service-security.md). **auditd & sentralisasi log** dibahas tuntas di [`05-logging.md`](05-logging.md); rule audit di sini hanya cuplikan.

---

## 2. SUID/SGID Binaries

**APA.** Bit **SUID** (`chmod u+s`, mode `4xxx`) membuat program berjalan dengan **UID pemilik file** (umumnya root), bukan UID pemanggil. **SGID** (`g+s`, `2xxx`) memberi **GID grup pemilik**; pada direktori, SGID memaksa file baru mewarisi grup direktori. Pada listing `ls -l`, SUID tampak sebagai `s` di kolom owner (`-rwsr-xr-x`), SGID sebagai `s` di kolom group.

**KENAPA.** Sebagian SUID memang diperlukan (`passwd`, `sudo`, `su`, `mount`, `ping` pada distro lama). Bahaya muncul ketika binary **dengan fungsi shell-out** diberi SUID: penyerang memanfaatkannya untuk menjalankan perintah arbitrer sebagai root. Daftar binary yang bisa disalahgunakan ada di **GTFOBins**. Contoh klasik: `find` SUID -> `find . -exec /bin/sh -p \; -quit` memberi root shell; `cp`, `nano`, `vim`, `python`, `bash`, `tar`, `awk` SUID semuanya jalan menuju root.

**CARA — enumerasi seluruh SUID/SGID.** Jalankan baseline dan bandingkan terhadap daftar yang sah:

```bash
# SUID (bit 4000), SGID (bit 2000), atau keduanya (6000) — file reguler saja
find / -xdev -type f -perm -4000 2>/dev/null         # SUID
find / -xdev -type f -perm -2000 2>/dev/null         # SGID
find / -xdev -type f -perm -6000 -exec ls -l {} \;   # keduanya, dengan detail
```

`-xdev` membatasi pada satu filesystem (hindari menyusuri NFS/mount eksternal). Bandingkan output dengan daftar GTFOBins untuk menandai yang berbahaya.

**CARA — hapus bit yang tak perlu.** Cabut SUID/SGID dari binary yang tidak butuh hak root, jangan dihapus binary-nya:

```bash
chmod u-s /path/ke/binary        # cabut SUID
chmod g-s /path/ke/binary        # cabut SGID
```

**CARA — defense in depth via opsi mount.** Cegah SUID *baru* dieksekusi pada partisi data dengan flag `nosuid` (juga `nodev`, `noexec`) — sesuai rekomendasi CIS untuk `/tmp`, `/var/tmp`, `/dev/shm`, dan `/home`:

```bash
# /etc/fstab — contoh untuk /tmp
tmpfs   /tmp   tmpfs   defaults,nosuid,nodev,noexec   0 0
# terapkan tanpa reboot:
mount -o remount,nosuid,nodev,noexec /tmp
```

> RHEL/Rocky: idem; banyak distro modern memakai `tmp.mount` (systemd) — atur opsi via `systemctl edit tmp.mount` atau `/etc/fstab`.

---

## 3. Permission File & Direktori Sensitif

**APA.** Izin POSIX (mode + owner/group) yang salah pada file kredensial atau direktori sistem. Dua kelas utama: **file sensitif terlalu terbuka** (mis. `/etc/shadow` terbaca) dan **objek world-writable** (siapa pun bisa menulis), termasuk file tanpa pemilik (`-nouser`).

**KENAPA.** `/etc/shadow` yang terbaca = hash password siap di-crack offline (Hashcat/John). Direktori world-writable tanpa sticky bit memungkinkan user mengganti/menghapus file milik user lain. File `-nouser` (UID pemilik tak ada di `/etc/passwd`) sering jadi titik tumpang penyerang.

**CARA — nilai mode/owner yang benar (CIS 6.1.x).**

| File | Ubuntu/Debian | RHEL/Rocky | Catatan |
|---|---|---|---|
| `/etc/passwd` | `644 root:root` | sama | world-readable wajar (tanpa hash) |
| `/etc/group` | `644 root:root` | sama | |
| `/etc/shadow` | `640 root:shadow` | `0000 root:root` | hash password — beda grup per distro |
| `/etc/gshadow` | `640 root:shadow` | `0000 root:root` | |
| `/etc/passwd-`,`/etc/shadow-` (backup) | mirip file aslinya | mirip | sering terlupakan |

```bash
# Perbaiki contoh (Ubuntu): jadikan shadow tak terbaca publik
chown root:shadow /etc/shadow && chmod 640 /etc/shadow
# Verifikasi mode + owner sekaligus:
stat -c '%n %a %U:%G' /etc/passwd /etc/shadow /etc/gshadow /etc/group
```

**CARA — buru objek berisiko.**

```bash
# File world-writable
find / -xdev -type f -perm -0002 2>/dev/null
# Direktori world-writable TANPA sticky bit (paling berbahaya)
find / -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null
# File/dir tanpa pemilik atau grup yang valid
find / -xdev \( -nouser -o -nogroup \) 2>/dev/null
```

Perbaiki: cabut bit world-write (`chmod o-w`), set sticky pada direktori shared (`chmod +t`), dan tetapkan pemilik valid (`chown`). `/tmp` & `/var/tmp` harus `1777` (sticky) — itu *benar*, bukan temuan.

**CARA — umask default.** Pastikan file baru tidak lahir terlalu terbuka. CIS mensyaratkan umask **027** atau lebih ketat di `/etc/login.defs` (`UMASK 027`) dan `/etc/profile` / `/etc/bash.bashrc`:

```bash
grep -E '^\s*UMASK' /etc/login.defs        # harapkan 027
```

---

## 4. Cron & Scheduled Jobs

**APA.** `cron`/`at` menjalankan task terjadwal. Job di `/etc/crontab`, `/etc/cron.d/`, dan direktori `cron.{hourly,daily,weekly,monthly}` berjalan sebagai **root**. Crontab per-user (`crontab -e`) tersimpan di `/var/spool/cron/`.

**KENAPA.** Jika **script yang dipanggil cron root bisa ditulis** user biasa, penyerang menyisipkan perintah dan menunggu cron mengeksekusinya sebagai root — eskalasi pasif yang sangat umum. Begitu pula file/direktori cron yang world-writable.

**CARA — kunci mode & owner (CIS 5.1.x).**

| Objek | Mode | Owner | Tujuan |
|---|---|---|---|
| `/etc/crontab` | `600` | `root:root` | hanya root baca/tulis |
| `/etc/cron.hourly` (dan daily/weekly/monthly) | `700` | `root:root` | direktori → butuh bit `x` |
| `/etc/cron.d` | `700` | `root:root` | |
| `/etc/cron.allow`, `/etc/at.allow` | `640` | `root:root` | whitelist user; hilangkan `cron.deny`/`at.deny` |

```bash
chown root:root /etc/crontab && chmod 600 /etc/crontab
chmod 700 /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d
# Batasi siapa yang boleh pakai cron/at (allow-list), bukan deny-list:
echo root > /etc/cron.allow && chmod 640 /etc/cron.allow && chown root:root /etc/cron.allow
rm -f /etc/cron.deny /etc/at.deny
```

**CARA — periksa skrip yang dipanggil cron bisa ditulis.** Job yang aman pun berbahaya bila *targetnya* writable:

```bash
# Tampilkan semua entri cron sistem, lalu audit izin file targetnya
cat /etc/crontab /etc/cron.d/* 2>/dev/null
find /etc/cron.* /etc/crontab -perm -0002 2>/dev/null   # cron object world-writable
```

Set `PATH` eksplisit dan absolut di header crontab (mis. `PATH=/usr/sbin:/usr/bin:/sbin:/bin`) dan panggil binary dengan path penuh — ini menutup celah PATH (§5) pada konteks cron.

---

## 5. PATH Hijacking

**APA.** `$PATH` menentukan urutan direktori yang dicari shell saat sebuah perintah dipanggil **tanpa path absolut**. Hijacking terjadi bila direktori yang **bisa ditulis user** muncul di PATH (terutama di depan), atau bila PATH memuat **`.` (current dir)** atau elemen kosong (`::`, `:` di awal/akhir — keduanya berarti direktori kerja).

**KENAPA.** Jika script/binary yang dijalankan root memanggil perintah secara relatif (mis. `tar`, `cat`, `service`) dan penyerang menaruh binary jahat bernama sama di direktori writable yang lebih awal di PATH, kernel menjalankan versi jahat itu **sebagai root**. Pola ini berpasangan dengan SUID (§2) dan cron (§4).

**CARA — bersihkan PATH root & global.**

```bash
echo "$PATH"                       # cari '.', '::', ':' di awal/akhir, atau dir writable
# Periksa tiap direktori PATH apakah world-writable:
echo "$PATH" | tr ':' '\n' | while read d; do
  [ -d "$d" ] && find "$d" -maxdepth 0 -perm -0002 2>/dev/null && echo "  ^ WRITABLE: $d"
done
```

- Hilangkan `.` dan elemen kosong dari `PATH` di `/etc/profile`, `/etc/environment`, `/root/.bashrc`, dan header crontab.
- Pastikan tidak ada direktori PATH milik non-root atau world-writable.
- Dalam script root, panggil binary dengan **path absolut** (`/usr/bin/tar`) atau set PATH eksplisit di awal script.

> Konsep ini analog dengan *unquoted service path* / *DLL search-order hijacking* di Windows — lihat [`../windows/01-privileged-access-management.md`](../windows/01-privileged-access-management.md) untuk padanannya tanpa mengulang.

---

## 6. Linux Capabilities

**APA.** Capabilities memecah hak monolitik root menjadi unit-unit kecil (mis. `cap_net_bind_service` untuk bind port < 1024). Disetel pada file dengan `setcap`, dibaca dengan `getcap`. Format flag: `cap_xxx+ep` — **e** = effective, **p** = permitted (artinya kapabilitas aktif saat binary dijalankan).

**KENAPA.** Capabilities ditujukan untuk **mengurangi** kebutuhan SUID penuh. Tapi salah pasang sama bahayanya: sebuah interpreter dengan `cap_setuid+ep` setara root. Beberapa capability bersifat "setara root":

| Capability | Risiko bila pada binary salah |
|---|---|
| `cap_setuid` / `cap_setgid` | Ubah UID/GID ke 0 → root langsung (mis. `python -c 'import os;os.setuid(0);os.system("/bin/sh")'`) |
| `cap_dac_read_search` | Lewati cek izin baca → baca `/etc/shadow`, file siapa pun |
| `cap_dac_override` | Lewati semua cek baca/tulis/eksekusi file |
| `cap_sys_admin` | "Mini-root" — mount, namespace, banyak operasi admin |
| `cap_sys_ptrace` | Inject ke proses lain (termasuk milik root) |
| `cap_sys_module` | Muat kernel module → kompromi total |
| `cap_net_raw` | Sniff/spoof paket mentah |

**CARA — enumerasi & cabut.**

```bash
# Daftar semua file dengan capability (butuh paket libcap2-bin di Ubuntu / libcap di RHEL)
getcap -r / 2>/dev/null
# Saring yang paling berbahaya:
getcap -r / 2>/dev/null | grep -Ei 'cap_setuid|cap_dac_|cap_sys_admin|cap_sys_module|cap_sys_ptrace'
# Cabut SEMUA capability dari sebuah binary:
setcap -r /path/ke/binary
# atau set ulang ke nilai minimal yang sah, mis. hanya bind port rendah:
setcap cap_net_bind_service=+ep /usr/bin/contoh
```

Prinsipnya: capability hanya boleh ada pada binary yang **memang dirancang** untuknya (mis. `ping` boleh `cap_net_raw` pada distro modern). Interpreter umum (`python`, `perl`, `node`, `bash`) **tidak boleh** punya capability apa pun.

---

## Serangan Umum & Mitigasi

| Serangan | Teknik / contoh | MITRE ATT&CK | Mitigasi di modul ini |
|---|---|---|---|
| **SUID abuse (GTFOBins)** | `find -exec`, `bash -p`, `vim`/`python` SUID → root | T1548.001 (Setuid/Setgid) | §2 audit & cabut SUID, `nosuid` mount |
| **PwnKit** | CVE-2021-4034, `pkexec` (SUID polkit) | T1548.001 / T1068 | §2 patch + audit SUID; polkit -> Modul 01 |
| **Writable cron job** | Edit script root → eksekusi terjadwal | T1053.003 (Cron) | §4 mode cron, audit target writable |
| **PATH hijack** | Binary palsu di dir writable di depan PATH | T1574.007 (Path Interception by PATH Env Var) | §5 PATH absolut, hapus `.`/dir writable |
| **Capability abuse** | `python` `cap_setuid+ep` → setuid(0) | T1548.001 / T1068 (tak ada sub-ID khusus capabilities) | §6 audit `getcap`, cabut yang tak perlu |
| **Shadow disclosure** | Baca `/etc/shadow` (perm longgar / `cap_dac_read_search`) → crack offline | T1003.008 (/etc/passwd & /etc/shadow) | §3 mode `640/000`, §6 cabut `cap_dac_read_search` |
| **Permission weakness** | World-writable file sistem diubah | T1222.002 (Linux File & Dir Perms Mod) | §3 buru world-writable, set owner/sticky |
| **Kernel/local exploit** | Setelah enumerasi misconfig gagal | T1068 (Exploitation for Priv Esc) | Patch kernel; di luar cakupan modul ini |
| **Sudo misconfig (Baron Samedit)** | CVE-2021-3156 | T1548.003 (Sudo and Sudo Caching) | -> Modul 01 (sudoers) |

---

## Hardening Checklist (Modul Ini)

- [ ] Baseline **SUID/SGID** diambil; binary tak perlu dicabut bit-nya; tidak ada interpreter/`find`/`vim`/`python` SUID.
- [ ] Partisi `/tmp`, `/var/tmp`, `/dev/shm`, `/home` di-mount **`nosuid,nodev,noexec`** (sesuai peran).
- [ ] `/etc/shadow` & `/etc/gshadow` **tidak terbaca publik** (`640 root:shadow` di Ubuntu / `0000 root:root` di RHEL); `/etc/passwd` & `/etc/group` `644 root:root`.
- [ ] **Tidak ada** file world-writable tak terkelola; direktori world-writable punya **sticky bit**; tidak ada objek `-nouser`/`-nogroup`.
- [ ] `umask` default **027** atau lebih ketat di `/etc/login.defs`.
- [ ] Mode cron benar: `/etc/crontab` **600**, `cron.d` & `cron.{hourly,daily,weekly,monthly}` **700**, owner `root:root`.
- [ ] **`cron.allow`/`at.allow`** dipakai (allow-list, `640 root:root`); `cron.deny`/`at.deny` dihapus.
- [ ] Script yang dipanggil cron **tidak writable** oleh non-root; cron memakai **PATH absolut**.
- [ ] `$PATH` root/global tidak memuat **`.`**, elemen kosong, atau direktori **world-writable**.
- [ ] **`getcap -r /`** bersih: hanya binary yang dirancang untuknya punya capability; interpreter tanpa capability.
- [ ] (Opsional) Rule **auditd** untuk eksekusi SUID/privileged dipasang -> detail di [`05-logging.md`](05-logging.md).

---

## Lab Praktik

**Topologi:** satu host Linux lab (`target`, Ubuntu 22.04/24.04) dengan akun `lowpriv` (user biasa) dan akses root untuk hardening. Semua latihan dilakukan di VM/lab terisolasi.

### Lab 1 — SUID abuse lalu tutup

1. Sebagai root, buat misconfig sengaja: `cp /usr/bin/find /tmp/find && chmod 4755 /tmp/find`.
2. **Lakukan (sebagai `lowpriv`):** `/tmp/find . -exec /bin/sh -p \; -quit` → dapat shell `# ` (euid root). **Konfirmasi:** `id` menunjukkan `euid=0(root)`.
3. **Hardening:** `chmod u-s /tmp/find` (atau hapus). **Konfirmasi dengan:** ulangi langkah 2 → shell kini berjalan sebagai `lowpriv`, bukan root.

### Lab 2 — Capability `cap_setuid`

1. Root: `cp /usr/bin/python3 /tmp/py && setcap cap_setuid+ep /tmp/py`.
2. **Lakukan (`lowpriv`):** `/tmp/py -c 'import os;os.setuid(0);os.system("id")'` → tampil `uid=0(root)`.
3. **Hardening:** `setcap -r /tmp/py`. **Konfirmasi dengan:** `getcap /tmp/py` → output kosong; ulangi langkah 2 → tetap `lowpriv`.

### Lab 3 — Cron writable

1. Root buat job tiap menit: tulis `/etc/cron.d/backup` berisi `* * * * * root /opt/backup.sh`, lalu `chmod 777 /opt/backup.sh` (misconfig).
2. **Lakukan (`lowpriv`):** `echo 'cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash' >> /opt/backup.sh`; tunggu ≤ 60 detik; jalankan `/tmp/rootbash -p` → root shell.
3. **Hardening:** `chown root:root /opt/backup.sh && chmod 750 /opt/backup.sh`. **Konfirmasi:** `lowpriv` tidak bisa lagi menulis (`echo x >> /opt/backup.sh` → Permission denied).

### Lab 4 — PATH hijack

1. Buat script root `/usr/local/sbin/runjob` yang memanggil `tar` secara relatif; pastikan `/tmp` (writable) ada di depan PATH konteks itu (mis. `PATH=/tmp:$PATH runjob`).
2. **Lakukan (`lowpriv`):** taruh `/tmp/tar` berisi `#!/bin/sh` + payload, `chmod +x /tmp/tar` → saat `runjob` jalan sebagai root, `/tmp/tar` dieksekusi.
3. **Hardening:** ganti panggilan jadi `/usr/bin/tar` (absolut) dan set PATH eksplisit di awal script. **Konfirmasi:** `tar` jahat di `/tmp` tidak lagi dipanggil.

---

## Perintah Audit/Verifikasi

```bash
# === SUID/SGID === (harapkan hanya binary sistem yang sah; tak ada interpreter)
find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -exec ls -l {} \; 2>/dev/null

# === Permission file sensitif === (Ubuntu: shadow 640 root:shadow)
stat -c '%n %a %U:%G' /etc/passwd /etc/group /etc/shadow /etc/gshadow \
                      /etc/passwd- /etc/shadow- 2>/dev/null

# === World-writable & unowned === (harapkan kosong / hanya sticky-dir yang wajar)
find / -xdev -type f -perm -0002 2>/dev/null
find / -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null
find / -xdev \( -nouser -o -nogroup \) 2>/dev/null

# === umask === (harapkan 027 atau lebih ketat)
grep -E '^\s*UMASK' /etc/login.defs

# === Cron permission === (crontab 600; direktori cron 700; owner root)
stat -c '%n %a %U:%G' /etc/crontab /etc/cron.d \
     /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
ls -l /etc/cron.allow /etc/at.allow 2>/dev/null   # harapkan ada (allow-list)
ls -l /etc/cron.deny  /etc/at.deny  2>/dev/null   # harapkan TIDAK ada

# === PATH === (harapkan tak ada '.', elemen kosong, atau dir world-writable)
echo "$PATH"
echo "$PATH" | tr ':' '\n' | while read d; do
  [ -d "$d" ] && find "$d" -maxdepth 0 -perm -0002 2>/dev/null
done

# === Capabilities === (harapkan hanya binary yang dirancang; interpreter bersih)
getcap -r / 2>/dev/null
```

> Catatan: `getcap`/`setcap` butuh paket **libcap2-bin** (Ubuntu/Debian) atau **libcap** (RHEL/Rocky). `find`, `stat`, `grep`, `tr` tersedia default. Tool enumerasi otomatis seperti **LinPEAS**, **linux-smart-enumeration (lse.sh)**, atau **pspy** (memantau cron/proses tanpa root) berguna untuk validasi cepat di lab.

---

## Referensi

- **CIS Benchmarks** — *CIS Ubuntu Linux 22.04/24.04 LTS Benchmark* & *CIS Red Hat Enterprise Linux 9 Benchmark*: §1 Filesystem (`nosuid`/`nodev`/`noexec`, sticky), §5.1 Cron/at, §6.1 System File Permissions (passwd/shadow/gshadow), audit SUID/SGID & world-writable.
- **MITRE ATT&CK:** T1548.001 (Setuid/Setgid), T1548.003 (Sudo & Sudo Caching), T1053.003 (Scheduled Task: Cron), T1574.007 (Path Interception by PATH Env Var), T1222.002 (Linux File & Dir Perms Mod), T1003.008 (OS Cred Dumping: /etc/passwd & /etc/shadow), T1068 (Exploitation for Privilege Escalation).
- **GTFOBins** (`gtfobins.github.io`) — daftar binary Unix yang bisa disalahgunakan via SUID, sudo, dan capabilities.
- **man pages:** `capabilities(7)`, `setcap(8)`, `getcap(8)`, `find(1)`, `crontab(5)`, `umask(2)`, `chmod(1)`.
- **CVE acuan:** CVE-2021-4034 (PwnKit/`pkexec`, SUID), CVE-2021-3156 (Baron Samedit, sudo — lihat Modul 01).
- **Lintas modul:** [`01-privileged-access-management-pam.md`](01-privileged-access-management-pam.md) (sudo/PAM/polkit), [`02-dangerous-exposed-services.md`](02-dangerous-exposed-services.md), [`04-network-service-security.md`](04-network-service-security.md), [`05-logging.md`](05-logging.md) (auditd, rule privileged-exec). Padanan Windows: [`../windows/01-privileged-access-management.md`](../windows/01-privileged-access-management.md).

---

> **Catatan etika.** Seluruh teknik eskalasi di modul ini ditujukan untuk **memahami dan menutup** celah pada sistem milik sendiri, lab terisolasi, atau lingkungan CTF/LKS resmi tempat Anda diberi izin tertulis. Mengeksploitasi sistem tanpa otorisasi adalah pelanggaran hukum. Gunakan hanya untuk pembelajaran dan pertahanan.
