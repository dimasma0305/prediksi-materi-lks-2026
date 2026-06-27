# Modul A — Infrastructure Hardening

> Modul pertama (Hari-1) pada persiapan lomba **LKS (Lomba Kompetensi Siswa) bidang Cyber Security 2026**. Fokusnya **blue team**: peserta diberi OS untuk dikonfigurasi agar memenuhi objektif soal — mengeraskan (*harden*) infrastruktur **Windows** (Plain dan/atau Active Directory level) dan **Linux Distro** dengan *security best practices* dan *service-based hardening* yang dapat diuji dan diverifikasi.
>
> **Referensi latihan (WSA 2025):** materi **WorldSkills ASEAN 2025** — Test Project, **VM Module A1** (OVF/VMDK), arsip kompetisi (`WSASEAN2025.zip`), dan slide *Network Hardening & Security Implementation* — relevan untuk hardening **Windows & Linux** dan dapat dipakai sebagai lingkungan latihan resmi. Lihat [Latihan WSA 2025](../latihan-wsa-2025/README.md).

| Atribut | Nilai |
|---|---|
| **Hari** | Hari Pertama (H1) |
| **Durasi** | 3 jam |
| **Bobot** | **15%** (skala LKS Nasional 2026; setara 25% bobot internal H1) |
| **Penilaian** | Judgement (J) 10 + Measurement (M) 10 = **20 poin** |
| **Bentuk uji** | Konfigurasi OS sesuai objektif → diuji apakah memenuhi/tidak |
| **Kategori** | **Windows** (6 subbab) + **Linux** (5 subbab) |

---

## Tujuan Modul

Membangun kemampuan **mengamankan sistem dari sisi pertahanan** sebelum sistem itu diserang. Setelah menyelesaikan modul ini, peserta diharapkan mampu:

- Menutup jalur serangan klasik (Pass-the-Hash, LLMNR poisoning, Kerberoasting, privilege escalation Linux, ransomware, log clearing) lewat konfigurasi yang konkret.
- Menerapkan prinsip **least privilege**, **defense-in-depth**, dan **assume breach** pada host Windows maupun Linux.
- Mengankor setiap nilai konfigurasi (panjang password, ukuran log, opsi keamanan) ke sumber otoritatif — **Microsoft Security Baseline**, **CIS Benchmark**, dan *man page* / dokumentasi distro — bukan dikarang.
- Menjalankan kontrol berisiko *lockout* dengan pola aman **audit → verifikasi → enforce**, lalu **membuktikan** setiap kontrol benar-benar aktif lewat perintah audit/verifikasi.

Filosofi ini dipegang konsisten di kedua kategori sehingga skor *defense* dan *service uptime* tetap terjaga sementara serangan lawan diblokir.

---

## Kategori dalam Modul

Modul A dibagi menjadi dua kategori OS yang dinilai berdampingan. Tiap kategori punya README sendiri sebagai indeks dan peta navigasi ke seluruh subbab-nya.

| Kategori | Subbab | Status | Indeks kategori |
|---|---|---|---|
| **Windows** | 6 | ✅ selesai | [windows/README.md](windows/README.md) |
| **Linux** | 5 | ✅ selesai | [linux/README.md](linux/README.md) |

### Windows Hardening — 6 subbab → [windows/README.md](windows/README.md)

Mengeraskan infrastruktur Windows berbasis **Active Directory**. Tiap subbab memakai pola **APA → KENAPA → CARA**, dilengkapi tabel *Serangan Umum & Mitigasi* (dipetakan ke **MITRE ATT&CK**), *Hardening Checklist*, *Lab Praktik*, dan *Perintah Audit/Verifikasi*. Materi ditulis dengan **kepemilikan tegas**: satu topik dimiliki satu subbab, yang lain hanya merujuk.

| # | Subbab | Inti |
|---|---|---|
| 01 | [Privileged Access Management (PAM)](windows/01-privileged-access-management.md) | Tiering / Enterprise Access Model, PAW, Protected Users, Auth Policy Silos, **Windows LAPS**, JIT/JEA, gMSA, **Credential Guard** |
| 02 | [Basic Security Configurations on Active Directory](windows/02-active-directory-security.md) | Password/Lockout/Kerberos policy, PSO, AES/RC4, rotasi **KRBTGT**, NTLM hardening, **LDAP signing & channel binding**, hygiene grup privileged |
| 03 | [GPO — Local/AD Policy](windows/03-gpo-policy.md) | Mekanisme GPO (LSDOU, link/filter, loopback, `gpupdate`/`gpresult`), Central Store ADMX, URA, Security Options & UAC, SCT, **AppLocker & WDAC** |
| 04 | [Network Service Security](windows/04-network-service-security.md) | Defender Firewall, **SMB hardening**, RDP (NLA/TLS), **LLMNR/NBT-NS/mDNS/WPAD**, WinRM, protokol legacy & weak cipher, DNS security |
| 05 | [Antivirus — Microsoft Defender & EDR](windows/05-antivirus-defender.md) | Defender AV (RTP/cloud/BAFS), **ASR rules**, Controlled Folder Access, Network Protection, **Tamper Protection**, AMSI, Defender for Endpoint |
| 06 | [Logging & Auditing](windows/06-logging-auditing.md) | **Advanced Audit Policy**, daftar **Event ID**, command-line auditing (4688), **PowerShell logging**, **Sysmon**, **WEF/WEC**, retensi & integritas log |

> Bonus: [windows/07-hardening-checklist.md](windows/07-hardening-checklist.md) — checklist konsolidasi seluruh kontrol Windows untuk dipakai sebagai *scorecard* saat lomba.

### Linux Hardening — 5 subbab → [linux/README.md](linux/README.md)

Mengeraskan host Linux (server/endpoint): menutup *privilege escalation*, mematikan layanan berbahaya, memperbaiki *misconfiguration* umum, mengamankan layanan jaringan, dan menjaga jejak audit. Tiap subbab memakai template seragam: **Konsep → Cara Kerja → Langkah → Tools → Contoh/Payload → Deteksi & Mitigasi → Mini-Lab → Referensi**.

| # | Subbab | Inti |
|---|---|---|
| 01 | [Privileged Access Management (PAM)](linux/01-privileged-access-management-pam.md) | `pam.d`, `sudo`/`sudoers`, `su`, polkit, kontrol root login |
| 02 | [Dangerous/Exposed Services](linux/02-dangerous-exposed-services.md) | Service terbuka & berbahaya, banner, kredensial default |
| 03 | [Common Linux Misconfigurations](linux/03-common-linux-misconfigurations.md) | SUID/SGID, permission, cron, `PATH`, capabilities |
| 04 | [Network Service Security](linux/04-network-service-security.md) | SSH hardening, firewall (nftables/ufw), service binding |
| 05 | [Logging](linux/05-logging.md) | rsyslog/journald, auditd, logrotate, sentralisasi log |

---

## Relevansi ke Penilaian Lomba

Modul A dikerjakan pada **Hari Pertama selama 3 jam** dan menyumbang **15%** dari total nilai LKS Nasional 2026. Memahami *cara* juri menilai sama pentingnya dengan menguasai materinya.

**Dua metode penilaian (total 20 poin: J 10 + M 10):**

- **Measurement (objektif, biner).** Skor **1 bila konfigurasi sesuai kriteria, 0 bila tidak** — tidak ada nilai parsial. Setiap kontrol harus benar-benar **menyala dan terverifikasi**, bukan sekadar "sudah dicoba". Inilah alasan tiap subbab Windows menutup dengan blok **Perintah Audit/Verifikasi**: jadikan itu *checklist pembuktian* bahwa setiap setting aktif sebelum dianggap selesai.
- **Judgement (kualitas, skor 0–3).** Juri menilai kualitas kerja terhadap standar industri (0 = di bawah standar/tidak dikerjakan, 1 = memenuhi, 2 = melampaui, 3 = luar biasa). Kerapian, kelengkapan, dan kejelasan langkah/dokumentasi ikut dihitung.

**Bentuk proyek uji.** Peserta **diberi OS untuk dikonfigurasi** sesuai objektif soal; pengujian dilakukan dari **hasil konfigurasi** yang memenuhi objektif atau tidak. Cakupan eksplisit kisi-kisi: *security best practices* pada **Windows (Plain dan/atau AD level)** dan **Linux Distro**, plus *service-based hardening* pada keduanya.

**Implikasi praktis saat lomba:**

1. **Snapshot dulu** sebelum mengubah apa pun — banyak setting berisiko *lockout* atau memutus layanan yang juga dinilai (*service uptime*).
2. **Audit → verifikasi → enforce** untuk kontrol yang bisa mematahkan akses (ASR, AppLocker, NTLM/LDAP, Auth Silo di Windows; SSH/firewall di Linux). Jangan langsung *enforce* di sistem lomba.
3. **Pakai checklist & perintah verifikasi sebagai scorecard** — karena Measurement bersifat biner, kontrol yang "hampir benar" tetap bernilai 0.
4. **Jaga akun darurat (breakglass)** dan jangan kunci diri sendiri saat memperketat akses; pertahanan yang membuat layanan mati justru menurunkan skor.
5. **Hardening, bukan sabotase.** Jangan menonaktifkan kontrol yang dinilai juri demi "kemenangan" yang melemahkan postur keamanan.

---

## Saran Urutan Belajar

Modul ini menggabungkan dua OS; tidak harus menyelesaikan satu kategori penuh baru pindah, tetapi urutan berikut membangun pemahaman secara berlapis.

1. **Mulai dari kerangka berpikir.** Baca bagian *Tujuan & Konteks* di [windows/README.md](windows/README.md): *assume breach*, tiering/Tier 0, dan pola *audit → enforce* berlaku untuk Windows maupun Linux.
2. **Windows 01 → 06 secara berurutan.** Subbab memang ditulis untuk dibaca runtut — identitas (01–02) lalu bergerak keluar ke mekanisme kebijakan (03), jaringan (04), endpoint (05), dan visibilitas (06).
   - **Kuasai Modul 03 (GPO) lebih awal** sebagai referensi: subbab Windows lain merujuk ke sana ("terapkan via GPO → lihat Modul 03"). Buka ia tetap terbuka saat mengerjakan lab.
3. **Linux 01 → 05 secara berurutan.** Topik Linux memetakan pola yang sama: identitas/privilege (01), permukaan layanan (02–04), lalu logging (05) terakhir karena dipakai untuk **memverifikasi** kontrol sebelumnya.
4. **Selaraskan topik lintas-OS.** Banyak konsep paralel — manfaatkan untuk memperkuat ingatan:
   - PAM/akses berhak istimewa → Windows 01 ↔ Linux 01
   - Network service security → Windows 04 ↔ Linux 04
   - Logging & audit → Windows 06 ↔ Linux 05
5. **Tutup dengan checklist.** Pakai [windows/07-hardening-checklist.md](windows/07-hardening-checklist.md) dan blok verifikasi tiap subbab Linux sebagai latihan *scorecard* — simulasikan penilaian Measurement sebelum hari-H.

> **Catatan:** Materi ini hanya untuk lab pribadi, lingkungan kompetisi, atau sistem dengan **izin tertulis eksplisit**. Tool ofensif yang muncul di Lab Praktik dipakai untuk **menguji pertahanan sendiri**, bukan menyerang sistem lain.
