# Linux Hardening (Modul A)

> Kategori ini berisi teknik **hardening sistem Linux** yang menjadi inti pertahanan pada lomba CTF/LKS bertipe *defense* dan *attack-defense*. Tujuannya: menutup celah privilege escalation, mematikan layanan berbahaya, memperbaiki misconfiguration umum, mengamankan layanan jaringan, dan memastikan jejak audit (logging) tetap utuh — sehingga skor *service uptime* dan *defense* tetap aman sementara serangan lawan diblokir.
>
> **Referensi latihan (WSA 2025):** skenario hardening **Linux** nyata (LINSRV1 — RHEL-family: `firewalld`/SELinux/SSH) + **VM Module A1** & slide dari **WorldSkills ASEAN 2025**. Lihat [Latihan WSA 2025](../../latihan-wsa-2025/README.md).

## Peta ke Kisi-kisi LKSN 2026

Kategori **Linux Hardening** merupakan bagian dari **Modul A — Infrastructure Hardening**. Fokusnya adalah mengeraskan host Linux (server/endpoint) sesuai best practice keamanan, melengkapi materi hardening Windows pada modul yang sama.

## Daftar Topik

| No | Topik | File | Cakupan/Contoh | Status |
|----|-------|------|----------------|--------|
| 1 | Privileged Access Management (PAM) | [01-privileged-access-management-pam.md](01-privileged-access-management-pam.md) | pam.d, sudo/sudoers, su, polkit, root login | ✅ selesai |
| 2 | Dangerous/Exposed Services | [02-dangerous-exposed-services.md](02-dangerous-exposed-services.md) | service terbuka & berbahaya, banner, default cred | ✅ selesai |
| 3 | Common Linux Misconfigurations | [03-common-linux-misconfigurations.md](03-common-linux-misconfigurations.md) | SUID/SGID, permission, cron, PATH, capabilities | ✅ selesai |
| 4 | Network Service Security | [04-network-service-security.md](04-network-service-security.md) | SSH hardening, firewall (nftables/ufw), service binding | ✅ selesai |
| 5 | Logging | [05-logging.md](05-logging.md) | rsyslog/journald, auditd, logrotate, sentralisasi | ✅ selesai |

## Catatan

Tiap topik ditulis sebagai **satu halaman** dengan template seragam:

- **Konsep & Tujuan** — definisi, model ancaman, dan mengapa topik ini penting untuk hardening.
- **Topik bernomor (APA/KENAPA/CARA)** — bagian teknis bernomor (2, 3, dst.) yang membedah tiap kontrol/celah dengan pola **APA** (definisi mekanisme), **KENAPA** (relevansi dari sudut penyerang), dan **CARA** (langkah hardening + perintah/konfigurasi).
- **Serangan Umum & Mitigasi** — peta teknik serangan (dipetakan ke MITRE ATT&CK) beserta penangkalnya.
- **Hardening Checklist (Modul Ini)** — daftar periksa ringkas untuk verifikasi cepat.
- **Lab Praktik** — latihan praktik singkat untuk menguji pemahaman.
- **Perintah Audit/Verifikasi** — perintah siap-pakai untuk membuktikan hardening benar-benar "menempel".
- **Referensi** — sumber resmi (CIS Benchmark, man page, dokumentasi vendor) dan bacaan lanjutan.
