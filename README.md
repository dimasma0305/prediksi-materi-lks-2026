# Persiapan LKSN 2026 — Cyber Security (Windows & Linux Hardening + CTF)

> Paket materi **+ prediksi soal** untuk **Lomba Kompetensi Siswa Nasional (LKSN) XXXIV 2026 — bidang Teknologi Keamanan Siber (Cyber Security)**. Berisi **82 topik** (Hardening Windows/Linux, Offensive CTF, Defensive CTF) yang dipetakan ke kisi-kisi resmi, plus **analisis prediksi** materi yang kemungkinan keluar — berbasis perbandingan dengan **WorldSkills ASEAN (WSA) 2025**.

## Struktur Repository

```
windows-hardening-lks/
├── README.md                  ← (file ini) ringkasan + PREDIKSI soal
├── reference/                 ← dokumen acuan (sumber kebenaran)
│   ├── lksn-2026-technical-description.pdf        (format & penilaian resmi LKSN 2026)
│   ├── lksn-2026-kisi-kisi.pdf                    (silabus resmi LKSN 2026)
│   └── WSA2025_TP54_MA2_actual_en_final_v1.pdf    (Test Project WSA 2025 — acuan prediksi hardening)
└── materi/                    ← seluruh bahan belajar (82 topik)
    ├── README.md              ← indeks induk + peta kisi-kisi & bobot
    ├── modul-a-infrastructure-hardening/   (Windows 6 + Linux 5)
    ├── modul-b-offensive-ctf/              (Crypto 7, Web 37, Binary 9, Boot2Root 3)
    ├── modul-c-defensive-ctf/              (RE 9, Forensic 6)
    ├── latihan-wsa-2025/      ← studi kasus WSA 2025 + VM & materi resmi
    └── setup-lab/             ← link unduh OS lab
```

→ Mulai belajar dari **[materi/README.md](materi/README.md)**.

## Ringkasan Format Lomba (resmi — dari `reference/`)

| Modul | Hari | Durasi | Bobot 2026 | Isi |
|---|---|:--:|:--:|---|
| **A — Infrastructure Hardening** | H1 | 3 jam | **15%** | Hardening **Windows** (Plain/AD) + **Linux** |
| **B — Offensive Red-Team CTF** | H2 | 5 jam | **20%** | Web, Cryptography, Binary, Boot2Root |
| **C — Defensive Blue-Team CTF** | H3 | 5 jam | **40%** | Reverse Engineering, Digital Forensic (termasuk SIEM/Log) |

Penilaian: **Judgement** (juri 0–3) + **Measurement** (objektif); skala 0–100 → dikonversi ke skala WSC 700.

---

## 🔮 Prediksi Materi LKSN 2026

> **STATUS: PREDIKSI / ARGUMEN — BUKAN bocoran resmi.** Soal LKSN bersifat rahasia. Analisis ini disusun dari: (a) **kisi-kisi resmi 2026** (`reference/`), (b) **WorldSkills ASEAN 2025** sebagai materi primer (Test Project **LINSRV1** + **WINSRV1**, lihat [`materi/latihan-wsa-2025/`](materi/latihan-wsa-2025/README.md)), dan (c) bobot + level peserta. Kisi-kisi 2026 sendiri menyatakan acuannya **ASC/WSC standards** — sehingga **WSA adalah prediktor terkuat**.

### Dasar argumen

1. Bobot 2026: **Defensive 40% > Offensive 20% > Hardening 15%** → pusat nilai ada di **CTF (Blue + Red = 60%)**, bukan hardening.
2. WSA 2025 (regional, peserta lebih senior) = **Infra 25% + Forensik 25% + Red 25% + Blue 25%** dalam **satu skenario terintegrasi** (pfSense, AD, PKI 2-tier, LINSRV/WINSRV).
3. LKSN = tingkat **SMK nasional**; Hari-1 hardening hanya **3 jam**.
4. **Format CTF (terkonfirmasi kisi-kisi):** **Red Team & Blue Team keduanya *Jeopardy Style Challenge Skills-Based*** — tantangan **flag independen** per kategori (Red juga + **Boot2Root Style**). Artinya CTF **bukan satu skenario terintegrasi** seperti WSA, melainkan **kumpulan soal terpisah** → memungkinkan **kedalaman teknik lebih tinggi & jumlah soal lebih banyak**, dan memperkuat prediksi **tanya-jawab Judgement** (flag jeopardy mudah di-*submit* tanpa paham, jadi juri memvalidasi proses).

### Argumen A — Hardening kemungkinan **LEBIH MUDAH** dari WSA

- **Bobot 15% & waktu 3 jam** → ruang lingkup lebih sempit dari infra WSA (25%, lebih lama).
- **Level SMK nasional** → tugas lebih *guided* (daftar tugas eksplisit, pola WSA yang **disederhanakan**).
- Bagian WSA paling kompleks — **PKI 2-tier (offline Root + Issuing CA), OpenVPN, custom Snort rule** — kemungkinan **dipangkas/disederhanakan** karena menuntut waktu & keahlian tinggi.

➡️ **Implikasi:** fokus ke **tugas hardening inti yang terdokumentasi baik**, bukan PKI/IDS lanjutan.

### Argumen B — Red Team (Offensive) kemungkinan **LEBIH SUSAH** dari WSA

- Kisi-kisi 2026 mengenumerasi teknik **tingkat lanjut** yang melampaui skenario *applied* WSA: Web **37 vektor** (SSTI, Insecure Deserialization, Request Smuggling, Prototype Pollution), Binary **Heap Exploitation/ROP** (mengarah ke UAF/SROP/FSOP), Crypto **ECC Smart's attack / lattice / AES-GCM**.
- Format **jeopardy + boot2root murni** menggali **lebih dalam** ke satu teknik dibanding skenario WSA yang luas-tapi-aplikatif.

➡️ **Implikasi:** siapkan **solver/payload yang BISA DIJALANKAN** untuk teknik tersulit (lihat [Modul B](materi/modul-b-offensive-ctf/README.md)).

### Argumen C — Blue Team (Defensive) kemungkinan **LEBIH SUSAH** dari WSA

- Bobot **40% — tertinggi**; ini *center of gravity* lomba.
- Kisi-kisi menuntut **Reverse Engineering** (anti-debug, obfuscation, **Mobile RE**, arch **ARM/MIPS**), **Digital Forensic** (Memory/Volatility3, Malware Analysis, Network), dan **SIEM threat hunting / anomaly detection** — cakupan lebih dalam dari forensik WSA.

➡️ **Implikasi:** **Blue/DFIR + RE = prioritas latihan tertinggi** (ROI nilai terbesar).

### 🎯 Prediksi konkret materi yang akan keluar

#### Modul A — Hardening (prediksi **diambil dari WSA 2025 LINSRV1 + WINSRV1**)

Pola tugas WSA hampir pasti jadi tulang punggung Hari-1 (disederhanakan). Sumber: [Test Project WSA 2025](materi/latihan-wsa-2025/README.md).

**WINSRV (Windows Server / Active Directory)** — prediksi tugas:

| Tugas prediksi (pola WSA) | Materi |
|---|---|
| Password policy domain (mis. panjang min + ganti berkala) | [windows/02](materi/modul-a-infrastructure-hardening/windows/02-active-directory-security.md) |
| Fine-Grained Password Policy untuk grup tertentu (mis. *executive*) | [windows/02](materi/modul-a-infrastructure-hardening/windows/02-active-directory-security.md) |
| GPO: batasi Control Panel / blokir `regedit` / set homepage via ADMX | [windows/03](materi/modul-a-infrastructure-hardening/windows/03-gpo-policy.md) |
| Login banner (`legalnotice` caption + text) | [windows/03](materi/modul-a-infrastructure-hardening/windows/03-gpo-policy.md) |
| Share + NTFS permission least-privilege per grup | [windows/02](materi/modul-a-infrastructure-hardening/windows/02-active-directory-security.md) |
| File auditing via **SACL** (Object Access, Event 4663) | [windows/06](materi/modul-a-infrastructure-hardening/windows/06-logging-auditing.md) |
| *(mungkin)* autoenroll certificate via GPO | [windows/03](materi/modul-a-infrastructure-hardening/windows/03-gpo-policy.md) |

**LINSRV (Linux Server, RHEL-family)** — prediksi tugas:

| Tugas prediksi (pola WSA) | Materi |
|---|---|
| SSH hardening: ganti port, `PermitRootLogin no`, `AllowUsers` | [linux/04](materi/modul-a-infrastructure-hardening/linux/04-network-service-security.md) |
| `sudo` untuk user tertentu (sudoers) | [linux/01](materi/modul-a-infrastructure-hardening/linux/01-privileged-access-management-pam.md) |
| Password policy: `pam_pwquality` + aging (`chage`) | [linux/01](materi/modul-a-infrastructure-hardening/linux/01-privileged-access-management-pam.md) |
| `firewalld`: izinkan layanan yang perlu, persisten | [linux/04](materi/modul-a-infrastructure-hardening/linux/04-network-service-security.md) |
| **SELinux** enforcing + context `httpd_sys_content_t` (`/var/www`) | [linux/03](materi/modul-a-infrastructure-hardening/linux/03-common-linux-misconfigurations.md) |
| HTTPS pada `httpd` (sertifikat) | [linux/04](materi/modul-a-infrastructure-hardening/linux/04-network-service-security.md) |

> ⚠️ **LINSRV1 WSA = RHEL-family** (`firewalld`/SELinux/`httpd`, bukan Ubuntu). Latih versi **Rocky/AlmaLinux 9** + terjemahan perintah — lihat [latihan-wsa-2025](materi/latihan-wsa-2025/README.md).

#### Modul B — Offensive (prediksi)
Web injection family (SQLi/SSTI/XSS/Upload), Crypto (classical + RSA + AES mode), Binary (BOF → ROP → Heap), Boot2Root (enum layanan → eksploitasi → privesc **PwnKit/SUID/sudo**).

#### Modul C — Defensive (prediksi)
**Memory forensic** (Volatility3), Network forensic (PCAP/Zeek), Disk/OS artifact, **Malware Analysis**, **RE** (static+dynamic, anti-debug, mobile), **SIEM hunting** (korelasi `4625→4624`).

### Prediksi mekanisme Judgement (penilaian proses)

> **Status: prediksi.** TD resmi menyebut penilaian **Judgement** = *pengamatan proses maupun hasil* (skor juri **0–3**, komponen ~30% nilai) dan dokumen menandai pelaksanaan **daring** (`Daring_Versi 0`) dengan *onsite monitoring*. Kemungkinan besar mekanismenya:

- **Meeting / video conference:** semua peserta **join** satu room dan **share screen** selama mengerjakan — terutama saat **hands-on lab**.
- **Monitoring live:** juri mengamati **proses**, bukan hanya hasil/flag — cara enumerasi, urutan langkah, kerapian & justifikasi konfigurasi.
- **Tanya-jawab *mid-competition*:** juri **menanyakan** alasan/metodologi di tengah lomba — **kemungkinan besar untuk Offensive & Defensive** karena memakai **format CTF**: flag mudah di-*submit* tanpa paham, sehingga juri memvalidasi **pemahaman & orisinalitas** (mencegah *copy-paste* / joki).

➡️ **Implikasi:**
- **Bisa menjelaskan = bagian dari nilai.** Latih **verbalisasi**: "kenapa pakai payload ini", "bagaimana flag didapat", "apa mitigasinya".
- Susun **POC/writeup sambil berjalan** (screenshot + langkah), bukan di akhir.
- Jaga **koneksi & screen-share stabil**; pastikan layar kerja (terminal / Burp / Volatility / GPMC) terlihat jelas oleh juri.
- Untuk **hardening**, juri bisa minta **buktikan setting aktif secara live** → kuasai blok **Perintah Audit/Verifikasi** di tiap modul.

### Strategi berbasis prediksi

1. **Kunci hardening dulu (15%, paling *predictable*)** — tugas WSA LINSRV/WINSRV ≈ "nilai gratis" jika dikuasai.
2. **Investasi terbesar di Defensive (40%)** — RE + Forensik + SIEM.
3. **Offensive (20%)** — kuasai **Web + Boot2Root** dulu (poin cepat & sering), lalu Binary/Crypto.

> **Caveat:** prediksi ≠ jaminan. Bila berbeda, **dokumen resmi di [`reference/`](reference/) yang menang.**

---

## Cara Pakai

- 📚 Peta lengkap & urutan belajar → [materi/README.md](materi/README.md)
- 🧪 Bangun lab (unduh OS) → [materi/setup-lab/README.md](materi/setup-lab/README.md)
- 🎯 Latihan terintegrasi WSA 2025 → [materi/latihan-wsa-2025/README.md](materi/latihan-wsa-2025/README.md)

## Etika

Seluruh materi & teknik (termasuk ofensif) **hanya** untuk **lab pribadi, lingkungan kompetisi, atau sistem dengan izin tertulis**. Bukan untuk menyerang sistem tanpa izin.
