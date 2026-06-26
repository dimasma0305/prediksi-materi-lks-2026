# Studi Kasus & Latihan — WorldSkills ASEAN 2025 (Cyber Security)

> Skenario latihan **end-to-end** yang diturunkan dari materi kompetisi **WorldSkills ASEAN (WSA) 2025 — Skill 54 Cyber Security** (Test Project *TP54 MA2 — Infrastructure Security* + checklist "To Win"). Tujuannya: menambatkan setiap modul di paket materi ini ke **tugas hardening nyata** yang pernah diujikan, supaya latihan tidak abstrak. WSA berformat tim & berbeda struktur dari LKSN, tetapi **skill yang diuji sangat beririsan** (Infrastructure Hardening, Forensics, Red/Blue CTF) — dan Deskripsi Teknis LKSN 2026 sendiri menyebut acuannya **ASC/WSC standards**.
>
> Sumber: arsip workspace Notion WSA (latihan pribadi). Halaman ini **memetakan**, bukan menyalin soal — pakai sebagai blueprint latihan.

---

## 1. Format WSA 2025 vs LKSN 2026

| Aspek | WorldSkills ASEAN 2025 | LKSN 2026 (paket ini) |
|---|---|---|
| Struktur | 4 kriteria × **25%** | 3 modul (Hardening 15% · Offensive 20% · Defensive 40%) |
| Kriteria A | Enterprise Infrastructure Security | = **Modul A** (Windows + Linux Hardening) |
| Kriteria B | Incident Response & Forensics | = **Modul C** (Digital Forensic) |
| Kriteria C | Red CTF (eksploitasi) | = **Modul B** (Offensive) |
| Kriteria D | Blue CTF (defensif) | = **Modul C** + kontrol **Modul A** |
| Infrastruktur | ESXi + VMware Workstation, pfSense, AD, PKI 2-tier, Linux DMZ | Server 2022 + Win10/11 + Kali (lihat [setup lab](../setup-lab/README.md)) |

**Inti:** Kriteria A WSA ≈ tepat sasaran Modul A kita. Sisanya melatih Modul B & C secara terintegrasi.

---

## 2. Topologi Test Project (TP54 MA2)

Jaringan klien yang "berfungsi tapi belum aman" — tugas peserta: **mengeraskannya**.

| VM | VLAN | IP | Peran |
|---|---|---|---|
| **FIREWALL** (pfSense) | semua VLAN | `.254` tiap subnet | Default-deny; segmentasi LAN/Servers/DMZ/WAN |
| **WINSRV1** | Servers | `192.168.2.10` | **AD DC** + DNS + DHCP |
| **WINSRV3** | Servers | `192.168.2.30` | **Issuing CA** (AD CS) |
| **WINSRV4** | Servers | `192.168.2.50` | **Offline Root CA** (dimatikan) |
| **LINSRV1** | DMZ | `192.168.1.10` | Web publik (httpd) + DNS publik |
| **Client1/2** | LAN | DHCP | Uji internal |
| **Client3** | Internet | DHCP | Uji VPN & akses DMZ dari luar |

> Prinsip yang diuji = persis filosofi paket ini: **segmentasi jaringan, default-deny, least privilege, dan uji fungsional setiap konfigurasi** (jangan hanya percaya setting).

---

## 3. Tugas Hardening → Modul Materi

### 3.1 Firewall & Jaringan (pfSense) → Modul 04 Network

| Tugas WSA | Pelajari di |
|---|---|
| Ganti password admin default pfSense (`pfsense` → kuat) | [Win 04 — Network](../modul-a-infrastructure-hardening/windows/04-network-service-security.md) · [Linux 04](../modul-a-infrastructure-hardening/linux/04-network-service-security.md) |
| **Default-deny** + allow-list port AD: `53, 88, 135, 137-139, 389, 443, 445, 464, 636, 3268-3269`; PKI `9389` | [Win 04 — Network](../modul-a-infrastructure-hardening/windows/04-network-service-security.md) |
| Segmentasi VLAN (LAN/Servers/DMZ/WAN), batasi DMZ→Servers | konsep firewall profile/scope — [Win 04](../modul-a-infrastructure-hardening/windows/04-network-service-security.md) |
| OpenVPN + sertifikat dari CA (bukan self-signed) | terkait PKI (§3.3) + [Linux 04](../modul-a-infrastructure-hardening/linux/04-network-service-security.md) |
| **Snort IDS** — custom rule drop "XMAS scan" (`flags: FPU`), uji dengan `nmap` | deteksi → [Logging](../modul-a-infrastructure-hardening/windows/06-logging-auditing.md) + Blue [Network Forensic](../modul-c-defensive-ctf/digital-forensic/02-network-forensic.md) |

> **Catatan alat:** WSA pakai **pfSense**; paket kita mengajarkan **Windows Defender Firewall**. Konsep identik (default-deny + allow-list per layanan); terjemahkan aturan pfSense ↔ `New-NetFirewallRule`.

### 3.2 Active Directory & GPO (WINSRV1) → Modul 02 / 03 / 06

| Tugas WSA | Pelajari di |
|---|---|
| Password policy domain (8 char, ganti tiap bulan) | [AD 02 §Password Policy](../modul-a-infrastructure-hardening/windows/02-active-directory-security.md) |
| **Fine-Grained Password Policy** (grup `executive` 10 char) | [AD 02 §PSO](../modul-a-infrastructure-hardening/windows/02-active-directory-security.md) |
| **Login banner** (caption "WorldSkills ASEAN Manila" + text "authorized access only") | [GPO 03 §Security Options](../modul-a-infrastructure-hardening/windows/03-gpo-policy.md) (`legalnotice`) |
| GPO `control` — batasi Control Panel (grup accounting) | [GPO 03](../modul-a-infrastructure-hardening/windows/03-gpo-policy.md) |
| GPO `registry` — blokir `regedit` (user Manila) | [GPO 03](../modul-a-infrastructure-hardening/windows/03-gpo-policy.md) |
| GPO `google` — **ADMX Chrome**, paksa homepage `w3.manila.com` | [GPO 03 §ADMX Central Store](../modul-a-infrastructure-hardening/windows/03-gpo-policy.md) |
| Share `pictures` — NTFS least privilege (CS=Read, Graphics=Modify, IT=FC, lainnya none) | [AD 02 §least privilege / share](../modul-a-infrastructure-hardening/windows/02-active-directory-security.md) |
| **Auditing file** `manila.jpg` (log saat dibaca) | [Logging 06 §Object Access / SACL](../modul-a-infrastructure-hardening/windows/06-logging-auditing.md) (Event **4663**) |

### 3.3 PKI / AD CS 2-Tier (WINSRV3/4) → terkait Modul 02 & 03

| Tugas WSA | Catatan |
|---|---|
| Offline Root CA (WINSRV4) + Issuing CA (WINSRV3) | Pola industri: root **offline** demi proteksi kunci |
| GPO `certenroll` — **autoenroll** sertifikat ke domain | mekanisme via GPO → [GPO 03](../modul-a-infrastructure-hardening/windows/03-gpo-policy.md) |
| Sertifikat IIS (WINSRV3) & web LINSRV1 dipercaya via root-CA policy | — |

> ⚠️ **Gap modul:** **AD CS / PKI** belum punya halaman khusus di paket ini — **kandidat modul tambahan** (lihat §6). Untuk sekarang, AD CS sering jadi target serangan (ESC1-ESC8) yang relevan ke Red/Blue.

### 3.4 Linux Hardening (LINSRV1) → Modul A / Linux

> **OS LINSRV1 = RHEL-family (CentOS / Rocky Linux / AlmaLinux), bukan Ubuntu.** Bukti dari Test Project & writeup: `firewalld` (`firewall-cmd --list-all --permanent`), **SELinux** enforcing (`sestatus`, `semanage port -a -t ssh_port_t -p tcp 2022`, context `httpd_sys_content_t` untuk `/var/www`), paket web `httpd` (bukan `apache2`), dan domain-join via `realm`/**`sssd`**. Versi pasti tidak disebut di catatan, tapi seluruh tooling Red Hat-based.
>
> **Catatan penting:** modul Linux kita **Ubuntu/Debian-primary**. Untuk latihan WSA yang setia, pakai **Rocky/AlmaLinux 9** dan terjemahkan perintahnya: `ufw`/`nftables` → **`firewalld`**, AppArmor → **SELinux** (`semanage`/`restorecon`), `apache2` → **`httpd`**, `adduser`/`/etc/apt` → `useradd`/`dnf`.

| Tugas WSA | Pelajari di |
|---|---|
| **SSH**: port `2022`, **root tidak boleh login**, hanya user C1/C2 | [Linux 04 §SSH hardening](../modul-a-infrastructure-hardening/linux/04-network-service-security.md) |
| `sudo` penuh untuk C1/C2; user lain tanpa privilege | [Linux 01 — PAM/sudoers](../modul-a-infrastructure-hardening/linux/01-privileged-access-management-pam.md) |
| Password aging & kompleksitas (10 char, ganti/bulan, lower+upper+digit+symbol) | [Linux 01 — PAM (`pam_pwquality`, `chage`, `login.defs`)](../modul-a-infrastructure-hardening/linux/01-privileged-access-management-pam.md) |
| **Local firewall** aktif & persisten setelah reboot | [Linux 04](../modul-a-infrastructure-hardening/linux/04-network-service-security.md) |
| **SELinux** enforcing **tapi httpd tetap jalan** (context `/var/www`) | [Linux 03 — Misconfigurations](../modul-a-infrastructure-hardening/linux/03-common-linux-misconfigurations.md) · [Linux 02 — Services](../modul-a-infrastructure-hardening/linux/02-dangerous-exposed-services.md) |
| httpd → **HTTPS** dengan sertifikat CA (atau self-signed bila gagal) | terkait PKI (§3.3) |

---

## 4. "To Win" — Checklist 4 Kriteria → Modul

### Kriteria A — Enterprise Infrastructure Security (25%) → **Modul A**
- [ ] Vulnerability assessment server Linux/Apache (SSL lemah, LDAP cleartext, SELinux mati) + **executive summary** → [Linux 02/03](../modul-a-infrastructure-hardening/linux/03-common-linux-misconfigurations.md)
- [ ] Firewall default-deny + OpenVPN + Snort → §3.1
- [ ] Hardening Windows (GPO, share, audit) + Linux (SSH, SELinux, password) → §3.2 & §3.4

### Kriteria B — Incident Response & Forensics (25%) → **Modul C / Digital Forensic**
- [ ] **Volatility** — proses tersembunyi di memory dump → [05 — Memory Forensic](../modul-c-defensive-ctf/digital-forensic/05-memory-forensic.md)
- [ ] **Autopsy** — recover file terhapus (disk) → [01 — File Carving](../modul-c-defensive-ctf/digital-forensic/01-file-carving.md)
- [ ] **Steghide** — flag steganografi → [04 — OS Forensic](../modul-c-defensive-ctf/digital-forensic/04-os-forensic.md)
- [ ] **Wireshark** — anomali TLS / decrypt traffic → [02 — Network Forensic](../modul-c-defensive-ctf/digital-forensic/02-network-forensic.md)
- [ ] Analisis IIS log untuk pola SQLi → [03 — Log Forensic](../modul-c-defensive-ctf/digital-forensic/03-log-forensic.md)
- [ ] Reverse malware (IDA/Ghidra) → [RE 01 Static](../modul-c-defensive-ctf/reverse-engineering/01-static-analysis.md) · [06 — Malware Analysis](../modul-c-defensive-ctf/digital-forensic/06-malware-analysis.md)

### Kriteria C — Red CTF (25%) → **Modul B / Offensive**
- [ ] **Buffer overflow** binary custom → [Binary 01](../modul-b-offensive-ctf/binary-exploitation/01-buffer-overflow.md)
- [ ] Crack NTLM dengan **Hashcat** (`-m 1000`) → [Crypto 07 — Hashing](../modul-b-offensive-ctf/cryptography/07-hashing.md)
- [ ] **sqlmap** untuk SQLi web → [Web 24 — SQL Injection](../modul-b-offensive-ctf/web-exploitation/24-sql-injection.md)
- [ ] **Sudo misconfig** & privilege escalation (LinPEAS/WinPEAS) → [Boot2Root 03 — Privesc](../modul-b-offensive-ctf/boot2root/03-vertical-dan-horizontal-privilege-escalati.md)
- [ ] Enumerasi & eksploitasi layanan → [Boot2Root 01](../modul-b-offensive-ctf/boot2root/01-service-level-enumerations.md) · [02](../modul-b-offensive-ctf/boot2root/02-service-level-exploitation.md)

### Kriteria D — Blue CTF (25%) → **Modul C + Modul A**
- [ ] Patch kerentanan kritis (mis. Heartbleed) → [Linux 02 — Dangerous Services](../modul-a-infrastructure-hardening/linux/02-dangerous-exposed-services.md)
- [ ] IDS rules blokir SQLi/XSS → §3.1 (Snort) + [Network Forensic](../modul-c-defensive-ctf/digital-forensic/02-network-forensic.md)
- [ ] Harden SSH/WinRM (cipher lemah dimatikan) → [Linux 04](../modul-a-infrastructure-hardening/linux/04-network-service-security.md) · [Win 04 — WinRM](../modul-a-infrastructure-hardening/windows/04-network-service-security.md)
- [ ] **Disable LLMNR**, enforce MFA, blokir IP jahat → [Win 04 §LLMNR/NBT-NS](../modul-a-infrastructure-hardening/windows/04-network-service-security.md)
- [ ] Laporan insiden + **IOC** → [Log Forensic](../modul-c-defensive-ctf/digital-forensic/03-log-forensic.md)

---

## 5. Cara Pakai Latihan Ini

1. **Bangun mini-range** versi sederhana (lihat [setup lab](../setup-lab/README.md)): 1 DC (Server 2022), 1 Linux DMZ **RHEL-family (Rocky/AlmaLinux 9)** meniru LINSRV1, 1 firewall (pfSense/OPNsense gratis), 1 client.
2. Kerjakan tugas **§3 berurutan** (Firewall → AD/GPO → Linux), buka halaman modul yang ditautkan saat butuh detail perintah.
3. Untuk tiap tugas, **uji fungsional** (seperti aturan WSA) lalu jalankan **Perintah Audit/Verifikasi** dari modul terkait sebagai bukti (measurement).
4. Lanjut latih Kriteria B/C/D pakai platform di tiap halaman *Referensi & Latihan* (PortSwigger, HTB, CyberDefenders, pwn.college).

---

## 6. Gap & Kandidat Modul Tambahan (dari WSA, belum ada di paket)

- **AD CS / PKI 2-tier** (autoenroll GPO, root offline) — sekaligus serangan ESC1–ESC8.
- **pfSense/OPNsense firewall + OpenVPN + Snort/Suricata IDS** sebagai modul jaringan perimeter (pelengkap Windows Firewall).
- **Executive summary / laporan teknis** (skill judged WSA) — menulis temuan & rekomendasi.

---

> **Etika:** Kredensial contoh di Test Project (`P@ssw0rd`, `pfsense`, dll.) adalah milik environment lomba WSA dan sengaja lemah untuk penilaian — **jangan dipakai di sistem nyata**. Semua latihan hanya di lab pribadi / range berizin.
