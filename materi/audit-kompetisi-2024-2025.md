# Audit Materi vs Kompetisi (2024 · 2025 · 2026)

> Audit cakupan paket materi ini terhadap kompetisi Cyber Security tahun **2024, 2025, dan 2026**. **Penting soal keyakinan:** audit ini **kuat** untuk **LKSN 2026 (nasional)** dan **WorldSkills ASEAN 2025** karena keduanya berbasis **dokumen primer**, tetapi **lemah** untuk **LKSN 2024/2025 nasional** karena dokumen resminya **tidak dapat diambil** (lihat §1). Klaim apa pun yang bersumber sekunder ditandai **(perlu verifikasi dokumen resmi)**.

---

## 1. Sumber & Tingkat Keyakinan

| Sumber | Tahun | Tipe | Keyakinan |
|---|---|---|---|
| LKSN Kisi-kisi + Deskripsi Teknis (`../reference/lksn-2026-*.pdf`) | 2026 | **Primer (resmi)** | 🟢 Tinggi |
| WorldSkills ASEAN — Test Project TP54 MA2 + marking (Notion) → [latihan-wsa-2025](latihan-wsa-2025/README.md) | 2025 | **Primer (resmi)** | 🟢 Tinggi |
| LKSN XXXII — struktur 4 modul + kategori | 2024 | Sekunder (ringkasan web/Scribd) | 🔴 Rendah |
| LKSN nasional — silabus | 2025 | Sekunder (ringkasan web) | 🔴 Rendah |
| Writeup LKS SMK 28 Tingkat Nasional (21 Okt 2020) | 2020 | Primer tapi **lama** | 🟡 Konteks evolusi |

**Kenapa 2024/2025 nasional lemah:** portal resmi (`smk-pusatprestasinasional.kemendikdasmen.go.id`) **hanya meng-host siklus 2026** (dokumen ber-label "2025" pun berada di `/storage/2026/`); repo resmi LKSN XXXII 2024 (`lksnasional32lpg.id`) **sudah mati**; arsip GitHub 2024/2025 mayoritas **tingkat provinsi/kota** (Jaktim, Jateng, Samarinda) yang ruang lingkupnya berbeda dari **nasional** — sengaja **tidak** dipakai untuk klaim nasional.

---

## 2. Evolusi Struktur Lomba (re-presentation, bukan perubahan konten)

| Tahun / Event | Struktur | Catatan |
|---|---|---|
| **2020** LKS SMK 28 (nasional) | Jeopardy CTF dasar (RCE/command injection, web source hunting) | Format lama, satu sesi, jauh lebih sederhana |
| **2024** LKSN XXXII *(sekunder)* | **4 modul**: Infra Hardening · IR/Forensics · CTF Attack · CTF Defense | (perlu verifikasi dokumen resmi) |
| **2025** WSA ASEAN *(primer)* | **4 kriteria × 25%**: Infrastructure · Forensics · Red CTF · Blue CTF | Dokumen lengkap, terverifikasi |
| **2026** LKSN XXXIV *(primer)* | **3 modul**: A Hardening 15% · B Offensive 20% · C Defensive 40% | Acuan paket materi ini |

> **Kesimpulan §2:** beda "4 modul (2024/WSA)" vs "3 modul (2026)" adalah **cara menyajikan** pemisahan CTF *attack/defense* (WSA memisah jadi 4×25%; 2026 menggabung jadi Offensive + Defensive dengan bobot Defensive 40%) — **bukan** perubahan isi. *Universe* skill konsisten lintas tahun: **infrastructure hardening + web/binary/crypto/RE/forensics + privilege escalation**. Tren jangka panjang: makin selaras dengan standar **WSC/ASC** (dari jeopardy 2020 → format profesional 2026).

---

## 3. Audit Cakupan — Materi Kita vs Kategori yang Diuji

Kategori yang konsisten muncul di kisi-kisi 2024–2026 dan dipetakan ke modul kita:

| Kategori historis (2024–2026) | Tercakup di paket ini? | Lokasi |
|---|---|---|
| Infrastructure Hardening (Windows + Linux) | ✅ Penuh | [Modul A](modul-a-infrastructure-hardening/README.md) (6 Windows + 5 Linux) |
| Web Exploitation | ✅ Penuh | [37 topik](modul-b-offensive-ctf/web-exploitation/README.md) |
| Binary Exploitation | ✅ Penuh | [9 topik](modul-b-offensive-ctf/binary-exploitation/README.md) |
| Cryptography | ✅ Penuh | [7 topik](modul-b-offensive-ctf/cryptography/README.md) |
| Reverse Engineering | ✅ Penuh | [9 topik](modul-c-defensive-ctf/reverse-engineering/README.md) |
| Digital Forensics | ✅ Penuh | [6 topik](modul-c-defensive-ctf/digital-forensic/README.md) |
| Boot2Root / Privilege Escalation | ✅ Penuh | [3 topik](modul-b-offensive-ctf/boot2root/README.md) |
| "System Security" (istilah 2024) | ✅ Tercakup | tersebar di Hardening + Boot2Root |

> **Kesimpulan §3:** **tidak ada kategori utama yang hilang.** Seluruh kategori yang dites historis tercakup oleh 82 topik paket ini.

---

## 4. Gap & Rekomendasi

### 4a. Gap **terverifikasi** (dari primer WSA 2025) — 🟢 prioritaskan
1. **AD CS / PKI 2-tier** (Root CA offline + Issuing CA, autoenroll GPO) — diuji WSA, **belum ada modul**. Sekaligus relevan serangan **ESC1–ESC8** (Red) & deteksinya (Blue).
2. **Perimeter: pfSense/OPNsense + OpenVPN + Snort/Suricata IDS** — diuji WSA; paket kita baru mengajarkan Windows Firewall.
3. **Executive summary / laporan teknis** (skill *judged* WSA) — belum ada panduan menulis temuan & rekomendasi.
4. **Linux RHEL-family** (firewalld/SELinux/httpd) — LINSRV1 WSA berbasis RHEL; modul Linux kita Ubuntu-primary. *(Sudah diberi catatan terjemahan di [latihan-wsa-2025](latihan-wsa-2025/README.md), tapi bisa dijadikan modul penuh.)*

### 4b. Gap **perlu verifikasi** (sekunder) — 🔴 jangan dijadikan final tanpa dokumen resmi
5. **Source code review multi-bahasa** (PHP/Python/Go/Java/C/Ruby/NodeJS/ASP.NET) — muncul di pedoman LKS lama. Sebagian tersinggung di Web Exploitation (deserialization, injection, SSTI) tapi **bukan** sebagai modul SAST/code-review tersendiri. **(perlu verifikasi ke kisi-kisi nasional 2024/2025)**
6. Apakah ada komponen **"System Security"** terpisah yang lebih luas dari yang kita asumsikan. **(perlu verifikasi)**

---

## 5. Self-Audit Materi (integritas internal)

| Aspek | Hasil |
|---|---|
| *Count gate* (jumlah file = bullet kisi-kisi 2026) | ✅ 82 topik tepat |
| Link `.md` antar-modul | ✅ tidak ada yang putus |
| Penanda status sisa (🚧/"sedang dibangun") | ✅ bersih |
| Verifikasi akurasi | ✅ Modul A (ASR GUID, Event ID, cmdlet, Windows LAPS) + kategori CTF fact-dense (crypto/binary/RE/forensic) dicek web |
| Asimetri kedalaman | ⚠️ Windows 500–760 baris vs CTF 150–260 baris — **disengaja & disetujui**, bukan cacat |

---

## 6. Tindakan Disarankan (prioritas)

1. 🟢 **Bangun modul AD CS / PKI + ESC1–8** — gap terverifikasi bernilai tertinggi (lintas Red & Blue).
2. 🟢 **Modul perimeter** pfSense/OPNsense + IDS (Snort/Suricata).
3. 🟡 **Dapatkan dokumen resmi LKSN 2024/2025 nasional** dari panitia/pembimbing untuk mengonfirmasi gap §4b — saat ini **tidak tersedia publik**. Begitu ada, simpan di `../reference/` (mirror cara `lksn-2026-*.pdf`) dan audit ulang.
4. 🟡 (Opsional) Modul **source-code review / SAST** bila §4b terkonfirmasi.

---

> **Keterbatasan (jujur):** audit ini **valid** untuk membandingkan paket materi dengan **LKSN 2026 (primer)** dan **WSA 2025 (primer)**. Untuk **LKSN 2024/2025 nasional**, temuan berbasis **sumber sekunder** dan **belum final** — perlakukan §2 (2024) dan §4b sebagai hipotesis sampai dokumen resmi diperoleh. Tidak ada klaim "drift" yang dibuat tanpa dasar dokumen primer.
