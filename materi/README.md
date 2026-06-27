# Paket Materi LKSN 2026 — Cyber Security

> Kurikulum latihan **lengkap** untuk **Lomba Kompetensi Siswa Nasional (LKSN) 2026 bidang Cyber Security**. Paket ini mencakup **ketiga modul lomba** — bukan hanya Windows hardening — yaitu **Infrastructure Hardening (A)**, **Offensive Red-Team CTF (B)**, dan **Defensive Blue-Team CTF (C)**. Tujuannya: menyiapkan peserta agar mampu **mengeraskan (harden)** infrastruktur, **mengeksploitasi** kerentanan secara terkendali, dan **mempertahankan + menganalisis (forensik & reverse engineering)** sistem dengan keterampilan yang dapat diuji dan diverifikasi.

Setiap topik ditulis dalam Bahasa Indonesia dengan pola **APA → KENAPA → CARA**, dilengkapi lab praktik, perintah verifikasi, dan pemetaan ke kerangka standar (MITRE ATT&CK untuk pertahanan, OWASP untuk web). Materi hanya untuk **lab / lingkungan kompetisi / sistem dengan izin eksplisit** — lihat [Catatan Etika](#catatan-etika).

---

## Konteks LKSN 2026

| Aspek | Keterangan |
|---|---|
| **Lomba** | LKSN (Lomba Kompetensi Siswa Nasional) 2026 — bidang **Cyber Security** |
| **Format** | **Luring** (on-site), terstruktur per hari |
| **Durasi total** | **± 14 jam** dibagi **3 hari** |
| **Struktur penilaian** | Mengikuti standar **WorldSkills** (WSC) — kombinasi *Judgement* + *Measurement* |
| **Dokumen acuan resmi** | Lihat folder [`../reference/`](../reference/) |

Dua dokumen resmi yang menjadi sumber kebenaran kisi-kisi, bobot, dan aturan teknis ada di folder `../reference/`:

- [`../reference/lksn-2026-technical-description.pdf`](../reference/lksn-2026-technical-description.pdf) — *Technical Description*: ruang lingkup, format modul, infrastruktur, dan skema penilaian.
- [`../reference/lksn-2026-kisi-kisi.pdf`](../reference/lksn-2026-kisi-kisi.pdf) — *Kisi-kisi*: rincian kompetensi dan bobot per modul.

> **Selalu utamakan dokumen resmi di `../reference/`.** Bila ada selisih antara paket materi ini dan dokumen resmi (bobot, durasi, atau ruang lingkup), **dokumen resmi yang menang**.

---

## Peta Kisi-kisi & Bobot

Tiga modul lomba dipetakan ke hari, alokasi waktu, dan bobot nilai berikut:

| Modul | Nama | Hari | Alokasi Waktu | Bobot |
|---|---|---|---|---|
| **A** | **Infrastructure Hardening** (Linux + Windows) | **Hari-1** | **± 3 jam** | **15%** |
| **B** | **Offensive Red-Team CTF** (Crypto, Web, Binary, Boot2Root) | **Hari-2** | **± 5 jam** | **20%** |
| **C** | **Defensive Blue-Team CTF** (Reverse Engineering, Digital Forensic) | **Hari-3** | **± 5 jam** | **40%** |

**Pembacaan cepat:**

- **Defensive (Modul C) berbobot tertinggi (40%)** — investasi belajar terbesar harus ke sini, meski porsinya berada di hari terakhir.
- **Offensive (Modul B) 20%** menempati durasi terpanjang bersama C, dengan cakupan topik terbanyak (terutama Web Exploitation).
- **Infrastructure Hardening (Modul A) 15%** adalah pembuka di Hari-1 dan menjadi fondasi pola pikir *assume breach* yang berguna untuk modul defensif.
- Total bobot ketiga modul di atas = **75%**. Sisa bobot (mis. komponen lain / penilaian umum) mengikuti rincian pada [`../reference/lksn-2026-kisi-kisi.pdf`](../reference/lksn-2026-kisi-kisi.pdf) — **verifikasi ke dokumen resmi**, jangan diasumsikan.

---

## Pohon Navigasi

Struktur paket: **Modul → Kategori → Topik**. Klik tautan untuk membuka README tiap kategori.

```
materi/
├── modul-a-infrastructure-hardening/   ← Modul A · Hari-1 · 15%
│   ├── linux/      → Linux Hardening      (5 topik)
│   └── windows/    → Windows Hardening    (6 modul · SELESAI)
│
├── modul-b-offensive-ctf/              ← Modul B · Hari-2 · 20%
│   ├── cryptography/        → Cryptography        (7 topik)
│   ├── web-exploitation/    → Web Exploitation    (37 topik)
│   ├── binary-exploitation/ → Binary Exploitation (9 topik)
│   └── boot2root/           → Boot2Root           (3 topik)
│
└── modul-c-defensive-ctf/              ← Modul C · Hari-3 · 40%
    ├── reverse-engineering/ → Reverse Engineering (9 topik)
    └── digital-forensic/    → Digital Forensic    (6 topik)
```

### Tautan README per Modul & Kategori

**Modul A — Infrastructure Hardening**

- [Linux Hardening](modul-a-infrastructure-hardening/linux/README.md) — 5 topik
- [Windows Hardening](modul-a-infrastructure-hardening/windows/README.md) — 6 modul (PAM, AD Security, GPO, Network, Defender, Logging) · **selesai**

**Modul B — Offensive Red-Team CTF**

- [Cryptography](modul-b-offensive-ctf/cryptography/README.md) — 7 topik
- [Web Exploitation](modul-b-offensive-ctf/web-exploitation/README.md) — 37 topik
- [Binary Exploitation](modul-b-offensive-ctf/binary-exploitation/README.md) — 9 topik
- [Boot2Root](modul-b-offensive-ctf/boot2root/README.md) — 3 topik

**Modul C — Defensive Blue-Team CTF**

- [Reverse Engineering](modul-c-defensive-ctf/reverse-engineering/README.md) — 9 topik
- [Digital Forensic](modul-c-defensive-ctf/digital-forensic/README.md) — 6 topik

**Latihan & Studi Kasus**

- [WorldSkills ASEAN 2025 — Cyber Security](latihan-wsa-2025/README.md) — skenario hardening nyata (pfSense firewall, AD/GPO, PKI 2-tier, Linux/SELinux/SSH) + checklist 4 kriteria, **dipetakan ke tiap modul** sebagai latihan terintegrasi.
- [Setup Lab — Download OS](setup-lab/README.md) — link unduh **resmi** semua OS lab: Windows (eval), Rocky/AlmaLinux, Ubuntu, Kali, + pfSense/OPNsense & hypervisor.

---

## Status & Cakupan

Status pembangunan tiap kategori. **Seluruh 82 topik kisi-kisi sudah ditulis** (Windows Hardening + Linux Hardening + seluruh kategori Offensive & Defensive). Setiap halaman topik sudah melewati *count gate* (jumlah file = jumlah bullet kisi-kisi) dan pass verifikasi.

| Modul | Kategori | Jumlah Topik | Status |
|---|---|:---:|---|
| A | Linux Hardening | 5 | ✅ Selesai |
| A | **Windows Hardening** | 6 | ✅ Selesai |
| B | Cryptography | 7 | ✅ Selesai |
| B | Web Exploitation | 37 | ✅ Selesai |
| B | Binary Exploitation | 9 | ✅ Selesai |
| B | Boot2Root | 3 | ✅ Selesai |
| C | Reverse Engineering | 9 | ✅ Selesai |
| C | Digital Forensic | 6 | ✅ Selesai |
| | **Total** | **82** | **✅ Lengkap** |

> **Catatan status:** Beberapa identifier teknis yang tidak dapat dipastikan saat verifikasi otomatis ditandai inline dengan "(perlu diverifikasi di lab)" — konfirmasi sendiri di lingkungan latihan sebelum dipakai saat lomba. Modul Windows Hardening dipakai sebagai **acuan format** untuk seluruh kategori lain.
>
> **Catatan cakupan (scope-out):** beberapa area yang diuji di WorldSkills ASEAN — **AD CS / PKI 2-tier (ESC1–8)**, **perimeter firewall + IDS (pfSense/Snort)**, dan keterampilan **penulisan POC/laporan teknis** — berada **di luar kisi-kisi LKSN 2026** dan **belum** dijadikan modul penuh di paket ini. Ini kandidat pengembangan, bukan klaim kelengkapan 100% terhadap semua varian lomba.

---

## Saran Urutan Belajar (berbasis bobot)

Prioritas belajar **mengikuti bobot nilai**, bukan urutan hari. Karena **Defensive (40%) jauh lebih besar** dari Offensive (20%) dan Hardening (15%), alokasikan jam latihan terbanyak ke Modul C.

### Prioritas global

1. **Modul C — Defensive (40%)** → porsi latihan terbesar. Reverse Engineering & Digital Forensic adalah pembeda peringkat. Dahulukan ketika menyusun jadwal latihan jangka panjang.
2. **Modul B — Offensive (20%)** → cakupan terluas (Web Exploitation 37 topik). Bangun kecepatan & cakupan teknik; banyak skill menyilang ke RE/forensik.
3. **Modul A — Hardening (15%)** → bobot terkecil, tetapi melatih pola pikir *assume breach* dan pemahaman sistem yang mempercepat modul B & C. Bisa diselesaikan lebih dahulu karena paling terstruktur.

### Alur per hari (saat lomba)

- **Hari-1 — Infrastructure Hardening (3 jam).** Kerjakan terstruktur dan cepat: ikuti checklist, **audit → verifikasi → enforce**, snapshot dulu. Lihat Windows Hardening untuk pola APA→KENAPA→CARA dan blok perintah verifikasi. Linux hardening melengkapi sisi non-Windows.
- **Hari-2 — Offensive Red-Team CTF (5 jam).** Triase semua tantangan dulu (Crypto, Web, Binary, Boot2Root), kerjakan yang *bobot-per-waktu* tertinggi lebih dahulu. Web Exploitation paling luas — kuasai pondasinya. Catat flag rapi.
- **Hari-3 — Defensive Blue-Team CTF (5 jam).** Bobot terbesar. Reverse Engineering dan Digital Forensic menuntut ketelitian artefak; alokasikan waktu paling banyak dan jaga rantai bukti analisis.

> **Strategi waktu:** dalam tiap modul CTF, lakukan *time-boxing* — bila satu tantangan macet melewati alokasi, pindah ke yang lain dan kembali nanti. Kumpulkan poin "mudah" lebih dulu sebelum mengejar yang "sulit".

---

## Penilaian & Skoring

Penilaian mengikuti standar **WorldSkills (WSC)**, menggabungkan dua jenis penilaian:

| Jenis | Cara nilai | Contoh penerapan |
|---|---|---|
| **Judgement** | Skala **0–3** oleh juri (0 = di bawah standar industri, 1 = memenuhi, 2 = di atas, 3 = unggul). Beberapa juri menilai independen lalu diagregasi. | Kualitas hardening, kelengkapan laporan/analisis, ketepatan metode forensik & RE |
| **Measurement** | **Objektif/biner** — benar/salah, flag cocok/tidak, kontrol aktif/tidak. | Flag CTF, hasil cek konfigurasi (`gpresult`/audit), artefak yang berhasil diekstrak |

**Konversi skala:**

- Nilai mentah tiap aspek diakumulasi dan **dinormalisasi ke skala 0–100**.
- Skala 0–100 lalu dipetakan ke **standar WSC 700** (total 700 poin kompetisi) sesuai pembobotan modul (A 15% · B 20% · C 40%, plus komponen lain per dokumen resmi).

> Rujuk [`../reference/lksn-2026-technical-description.pdf`](../reference/lksn-2026-technical-description.pdf) untuk rumus agregasi resmi dan distribusi *Marks* per aspek. Angka bobot di sini adalah ringkasan; **dokumen resmi adalah acuan final**.

---

## Catatan Etika

- Seluruh materi ditujukan **hanya** untuk **lab pribadi, lingkungan kompetisi, atau sistem dengan izin tertulis eksplisit**.
- Konten **ofensif** (eksploitasi web, binary, kriptografi, boot2root) disediakan **untuk latihan CTF dan untuk memahami sisi penyerang agar bisa bertahan lebih baik** — bukan untuk menyerang sistem yang bukan milik Anda atau tanpa izin.
- Konten **hardening & defensif** dirancang untuk **memperkuat dan menganalisis sistem sendiri**. Tool ofensif yang muncul di lab (mis. scanner, fuzzer, atau exploit) dipakai **menguji pertahanan sendiri**.
- Perintah destruktif/berisiko (menghapus log, menonaktifkan kontrol, mengubah konfigurasi domain) **wajib** dijalankan dengan snapshot dan hanya pada lab. **Jangan** dijalankan di production tanpa izin.
- Hormati aturan lomba dan hukum yang berlaku: **harden, exploit, dan defend dalam batas yang sah**. Penyalahgunaan keterampilan ini di luar lingkup berizin adalah ilegal.

---

## Sumber Rujukan Utama

- **Dokumen resmi LKSN 2026** di [`../reference/`](../reference/): *Technical Description* & *Kisi-kisi* — acuan kebenaran untuk bobot, durasi, dan ruang lingkup.
- **MITRE ATT&CK** — pemetaan teknik penyerang ↔ mitigasi (dipakai di Modul A & C).
- **OWASP** (Top 10, WSTG) — acuan kategori dan metodologi untuk Web Exploitation (Modul B).
- **Microsoft Security Baseline** & **CIS Benchmarks** — anchor numerik untuk Windows Hardening.
- **WorldSkills Standards (WSC)** — kerangka penilaian *Judgement* + *Measurement* dan skema 700 poin.

> Paket materi ini adalah **bahan latihan**, bukan pengganti dokumen resmi. Sebelum lomba, baca ulang kedua PDF di `../reference/` dan sesuaikan strategi dengan aturan terbaru panitia.
