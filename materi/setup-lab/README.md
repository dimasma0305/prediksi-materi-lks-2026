# Setup Lab — Download OS (Gratis & Legal)

> Daftar **link resmi** untuk semua OS yang dipakai paket materi ini: Windows (versi *Evaluation*, fitur penuh, dibatasi waktu) dan Linux (gratis penuh), plus firewall & mesin penyerang untuk latihan **WSA**. Semua legal untuk lab. Verifikasi **checksum** setelah unduh, dan jalankan di lab pribadi / range berizin.

---

## 1. Windows (Microsoft Evaluation Center)

Semua via **[Microsoft Evaluation Center](https://www.microsoft.com/en-us/evalcenter)** — perlu login akun Microsoft, format **ISO/VHD/Azure**.

| OS | Link unduh resmi | Masa eval | Peran di lab |
|---|---|---|---|
| **Windows Server 2025** | <https://www.microsoft.com/en-us/evalcenter/download-windows-server-2025> | ±180 hari | DC (terbaru; SMB signing default-on) |
| **Windows Server 2022** | <https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2022> | ±180 hari | **DC default materi** |
| **Windows 11 Enterprise** | <https://www.microsoft.com/en-us/evalcenter/evaluate-windows-11-enterprise> | ±90 hari | Client domain (uji GPO/LAPS/Defender) |
| **Windows 10 Enterprise** | <https://www.microsoft.com/en-us/evalcenter/evaluate-windows-10-enterprise> | ±90 hari | Client alternatif |

> Pilih **Desktop Experience** (bukan Server Core) untuk latihan GUI. Aktivasi eval wajib online dalam **10 hari** pertama. Perpanjang: `slmgr /rearm` lalu reboot (cek sisa: `slmgr /dlv`).

---

## 2. Linux

### 2a. Hardening RHEL-family — **dipakai WSA (LINSRV1)**

`firewalld` + **SELinux** + `httpd` + `realm`/`sssd`. Pakai ini untuk latihan WSA yang setia (→ lihat [latihan WSA 2025](../latihan-wsa-2025/README.md)).

| Distro | Link unduh resmi | Catatan |
|---|---|---|
| **Rocky Linux 9** | <https://rockylinux.org/download> | Penerus CentOS, paling umum di kompetisi |
| **AlmaLinux 9** | <https://almalinux.org/get-almalinux/> | Alternatif setara Rocky (DVD/Boot/Minimal) |

### 2b. Hardening Debian-family — **default modul Linux paket ini**

`ufw`/`nftables` + AppArmor + `apache2`. Cocok mengikuti [modul Linux](../modul-a-infrastructure-hardening/linux/README.md) apa adanya.

| Distro | Link unduh resmi | Catatan |
|---|---|---|
| **Ubuntu Server LTS** | <https://ubuntu.com/download/server> | Default & paling mudah |
| **Debian** | <https://www.debian.org/distrib/> | Minimalis, stabil |

### 2c. Mesin Penyerang / Red Team

| Distro | Link unduh resmi | Catatan |
|---|---|---|
| **Kali Linux** | <https://www.kali.org/get-kali/> | Installer / VM (VMware-VirtualBox) / WSL. Untuk Lab Modul 04/06 & CTF Red (nmap, Metasploit, sqlmap, Responder) |

> Alternatif: **Parrot Security OS** (<https://parrotsec.org/download/>) bila lebih suka.

---

## 3. Firewall / Perimeter (untuk latihan WSA)

WSA memakai **pfSense** (default-deny, OpenVPN, Snort). Keduanya gratis:

| Produk | Link unduh resmi | Catatan |
|---|---|---|
| **pfSense CE** | <https://www.pfsense.org/download/> | Community Edition; ikuti alur Netgate installer |
| **OPNsense** | <https://opnsense.org/download/> | Fork pfSense, ISO langsung, IDS Suricata bawaan |

---

## 4. Hypervisor (gratis)

| Tool | Link | Catatan |
|---|---|---|
| **VirtualBox** | <https://www.virtualbox.org/wiki/Downloads> | Termudah untuk pemula, lintas-OS |
| **VMware Workstation Pro** | Resmi (login Broadcom): <https://www.vmware.com/products/desktop-hypervisor/workstation-and-fusion> · Unduh langsung (build **26H1 25388281**): [VMware-Workstation-Full-26H1-25388281.exe](https://downloads2.broadcom.com/?file=VMware-Workstation-Full-26H1-25388281.exe&oid=47222852&id=1UtZD8cOL3IId_p4IrJBoCcbRK-f4PQYFPtXtFZT5xV2f1nscx1SvZ5GpJJ7RcvE8nh-QphW&verify=1782454620-%2FVBWXveOr8yxb40Dh9iTYzz5e8jI0VtxTPFw5LbpcV8%3D) | **Gratis untuk personal** (Broadcom) — sama seperti WSA. ⚠️ Link langsung ber-token & bisa **kedaluwarsa**; bila mati, pakai halaman resmi (login Broadcom). |
| **Hyper-V** | Fitur bawaan Windows 11 Pro/Enterprise | Aktifkan via *Optional Features* |

---

> 📦 **Sudah punya image VM jadi** (`.ovf` / `.vmdk` / **`.vhdx`** / `.qcow2`)? Cara **import & konversi ke VMware** — termasuk **install `qemu-img`** dan mengubah `.vhdx` (Hyper-V) → `.vmdk` — ada di **[Import & Konversi VM Image](import-konversi-vm-image.md)**.

## 5. Peta OS → Kebutuhan Modul

| Skenario / Modul | OS yang diunduh |
|---|---|
| [Modul A — Windows Hardening](../modul-a-infrastructure-hardening/windows/README.md) | Windows Server 2022 (DC) + Windows 11 Enterprise (client) |
| [Modul A — Linux Hardening](../modul-a-infrastructure-hardening/linux/README.md) (default paket) | Ubuntu Server LTS |
| [Latihan WSA — LINSRV1](../latihan-wsa-2025/README.md) | **Rocky / AlmaLinux 9** (RHEL-family) |
| [Latihan WSA — perimeter](../latihan-wsa-2025/README.md) | pfSense CE / OPNsense |
| [Modul B Offensive](../modul-b-offensive-ctf/) & [Modul C Defensive](../modul-c-defensive-ctf/) + penyerang | Kali Linux (+ target rentan dari HTB/TryHackMe/VulnHub) |

---

## 6. Tooling Pendukung (gratis)

- **RSAT** — modul PowerShell `ActiveDirectory`/`GroupPolicy` (Windows *Optional Features*).
- **Microsoft Security Compliance Toolkit** (Security Baseline + **LGPO.exe** + Policy Analyzer): <https://www.microsoft.com/en-us/download/details.aspx?id=55319> (Modul 03).
- **Sysmon** (Sysinternals): <https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon> (Modul 06).
- File uji **EICAR**: <https://www.eicar.org/download-anti-malware-testfile/> (Modul 05).

---

## 7. Target Latihan (Practice Boxes)

Mesin/target rentan **legal** untuk melatih Modul B/C — terutama [Boot2Root](../modul-b-offensive-ctf/boot2root/README.md):

| Sumber | Link | Catatan |
|---|---|---|
| **NetSecFocus Trophy Room** (TJ Null) | <https://docs.google.com/spreadsheets/u/1/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/htmlview?pli=1> | **Rujukan utama** — daftar kurasi mesin HTB/PG/VulnHub bergaya OSCP/PNPT per OS & difficulty |
| **HackTheBox** | <https://www.hackthebox.com> | Lab online (machines, Sherlocks DFIR) |
| **TryHackMe** | <https://tryhackme.com> | Jalur belajar bertahap |
| **VulnHub** | <https://www.vulnhub.com> | VM rentan untuk diunduh & dijalankan lokal (offline) |
| **OffSec Proving Grounds** | <https://www.offsec.com/labs/> | Box bergaya OSCP |
| **CyberDefenders / BTLO** | <https://cyberdefenders.org> · <https://blueteamlabs.online> | Latihan **Blue Team / DFIR** (Modul C) |

---

> **Etika & lisensi:** versi *Evaluation* Windows gratis tapi tetap tunduk EULA Microsoft (hanya untuk evaluasi/lab). Semua distro Linux di atas open-source/gratis. Jangan pakai untuk produksi atau menyerang sistem tanpa izin. Selalu **verifikasi checksum/signature** unduhan.
