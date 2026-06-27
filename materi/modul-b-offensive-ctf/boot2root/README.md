# Boot2Root — Modul B (Offensive / CTF)

> Indeks & **MANIFEST** kategori **Boot2Root** pada Modul B (offensive / Capture The Flag). Di lomba, soal Boot2Root memberi sebuah mesin target (Windows/Linux) yang harus ditembus dari **nol akses** sampai **kepemilikan penuh (root / SYSTEM / Administrator)**. Alurnya rantai utuh: **enumerasi** layanan & permukaan serang → **eksploitasi** untuk mendapat *foothold* (akses awal) → **privilege escalation** untuk naik hak akses sampai menguasai mesin. Yang dinilai bukan satu trik tunggal, tapi **kemampuan menyusun rantai serangan end-to-end**: membaca hasil scan, memilih celah yang benar, masuk, lalu memanfaatkan misconfig/abuse untuk menjadi pemilik sistem. Tujuan akhirnya selalu sama: **dapatkan flag** (umumnya `user.txt` lalu `root.txt`/`proof.txt`).

## Peta ke Kisi-kisi LKSN 2026

Kategori ini adalah bagian dari **Modul B — Offensive / CTF** pada kisi-kisi **LKSN (Lomba Kompetensi Siswa Nasional) bidang Cyber Security 2026**, berdampingan dengan kategori CTF lain di Modul B: **Web Exploitation**, **Binary Exploitation**, dan **Cryptography**. Fokus kategori **Boot2Root**: menembus satu host utuh secara berurutan — dari enumerasi layanan, eksploitasi untuk akses awal, hingga eskalasi hak akses (vertikal & horizontal) — dengan tooling lazim (`nmap`, `enum4linux`/`smbclient`, `gobuster`/`ffuf`, `nikto`, `Metasploit`/`searchsploit`, `netcat`, `winPEAS`/`linPEAS`, `BloodHound`, `GTFOBins`/`LOLBAS`) dalam batas **lingkungan lomba / lab berizin**.

---

## Daftar Topik

Tiga halaman berikut adalah cakupan tetap kategori ini dan mencerminkan **urutan natural sebuah serangan Boot2Root**. Kerjakan **berurutan 01 → 03**: mulai dari memetakan permukaan serang lewat enumerasi layanan, naik ke eksploitasi layanan untuk mendapat akses awal, lalu ditutup dengan eskalasi hak akses (vertikal & horizontal) sampai menguasai mesin sepenuhnya.

| No | Topik | File | Cakupan/Contoh | Status |
|---|---|---|---|---|
| 1 | Service Level Enumerations | [01-service-level-enumerations.md](01-service-level-enumerations.md) | port/service scan (nmap), fingerprinting versi, enum SMB/HTTP/FTP/SSH, brute direktori & vhost | ✅ selesai |
| 2 | Service Level Exploitation | [02-service-level-exploitation.md](02-service-level-exploitation.md) | cari & jalankan exploit layanan, default/weak creds, RCE → reverse shell, foothold awal | ✅ selesai |
| 3 | Vertical & Horizontal Privilege Escalation | [03-vertical-dan-horizontal-privilege-escalati.md](03-vertical-dan-horizontal-privilege-escalati.md) | Abuse atau Living-Off-The-Land (LOLBAS/GTFOBins), SUID/sudo, token/service abuse, pivot antar-user | ✅ selesai |

---

## Mesin Latihan (Practice Boxes)

Untuk melatih rantai Boot2Root end-to-end di lingkungan **legal**, gunakan daftar kurasi berikut:

- **[NetSecFocus Trophy Room](https://docs.google.com/spreadsheets/u/1/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/htmlview?pli=1)** (TJ Null) — daftar mesin **HackTheBox / Proving Grounds / VulnHub** bergaya **OSCP/PNPT**, dikelompokkan per OS (Windows/Linux) & tingkat kesulitan. Rujukan utama untuk memilih box bertahap (Easy → Medium) sambil membangun metodologi *enumerasi → eksploitasi → privilege escalation*.
- Platform: [HackTheBox](https://www.hackthebox.com) · [TryHackMe](https://tryhackme.com) · [VulnHub](https://www.vulnhub.com) (VM lokal) · [OffSec Proving Grounds](https://www.offsec.com/labs/).
- Referensi privesc cepat: [GTFOBins](https://gtfobins.github.io) (Linux) · [LOLBAS](https://lolbas-project.github.io) (Windows).

> Daftar OS lab & hypervisor: lihat [setup-lab](../../setup-lab/README.md).

---

## Catatan Format

Setiap topik di atas adalah **satu halaman** yang ditulis dengan **template seragam** berikut, agar mudah dipakai sebagai referensi cepat saat lomba:

1. **Konsep** — apa fase/teknik ini dan kenapa relevan di rantai Boot2Root.
2. **Cara Kerja** — mekanisme yang dieksploitasi (layanan yang terekspos, misconfig, kepercayaan/privilege yang disalahgunakan).
3. **Indikator / Cara Mengenali** — tanda-tanda yang dicari dari hasil scan/enum dan apa artinya untuk menentukan vektor serangan.
4. **Langkah Eksploitasi** — alur langkah demi langkah, dari mengenali target sampai mendapat akses/hak akses yang diincar.
5. **Tools** — alat yang dipakai (mis. `nmap`, `enum4linux`/`smbclient`, `gobuster`/`ffuf`, `nikto`, `searchsploit`/`Metasploit`, `netcat`, `winPEAS`/`linPEAS`, `BloodHound`, `GTFOBins`/`LOLBAS`).
6. **Contoh/Payload** — perintah / skrip / contoh nyata yang bisa langsung diadaptasi.
7. **Deteksi & Mitigasi** — bagaimana sisi defender mengenali & menutup celah ini (hardening layanan, patch, least-privilege, audit konfigurasi, logging & monitoring).
8. **Mini-Lab** — latihan mandiri untuk menguji pemahaman.
9. **Referensi** — sumber rujukan (writeup, dokumentasi, HTB/THM, GTFOBins/LOLBAS).

> Materi ini **hanya** untuk lab pribadi, lingkungan kompetisi, atau sistem dengan **izin tertulis eksplisit**. Teknik di sini dipakai untuk belajar memecahkan tantangan CTF dan menguji mesin milik sendiri, **bukan** untuk menyerang sistem orang lain.
