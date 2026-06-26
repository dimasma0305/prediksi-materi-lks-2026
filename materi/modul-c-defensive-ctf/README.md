# Modul C — Defensive / Blue Team Based CTF

> Indeks dan peta navigasi untuk **Modul C** pada persiapan lomba **LKS (Lomba Kompetensi Siswa) bidang Cyber Security 2026**. Modul ini bertipe **Jeopardy Style — Skills-Based**: peserta menyelesaikan kumpulan tantangan independen di dua kategori, **Reverse Engineering** dan **Digital Forensic**, dan mengumpulkan *flag* serta bukti pengerjaan (POC) untuk dinilai.

## Tujuan Modul

Modul C menguji kemampuan **defensif / blue team** dalam membongkar dan menganalisis artefak, bukan menyerang sistem hidup. Fokusnya: memahami *bagaimana* sebuah program bekerja (atau berperilaku jahat) dan *apa* yang terjadi pada sebuah sistem dari jejak yang ditinggalkannya. Kemampuan inti yang dibangun:

- **Membaca kode pada level rendah** — merekonstruksi algoritma dari disassembly/decompile, melacak alur eksekusi secara statis maupun dinamis, dan menembus teknik anti-analisis.
- **Menggali bukti dari artefak** — memulihkan file, membaca lalu lintas jaringan, menelusuri log, dan merekonstruksi aktivitas dari memori serta artefak OS.
- **Bekerja di bawah tekanan waktu** — modul dikerjakan dalam **satu sesi ~5 jam** (lihat [Relevansi ke Penilaian](#relevansi-ke-penilaian-lomba)), sehingga triase dan manajemen waktu antar-tantangan sama pentingnya dengan kemampuan teknis.

Filosofi yang dipegang: **bukti dulu, klaim kemudian**. Setiap *flag* harus bisa dijelaskan ulang lewat POC yang jelas — juri menilai bukan hanya hasil, tapi juga kejernihan langkah.

> Materi ini ditulis untuk **lingkungan lab / kompetisi dengan izin eksplisit**. Sampel malware dan binari yang dianalisis hanya boleh dijalankan di VM terisolasi (snapshot dulu, jaringan host-only/terputus). Lihat [Catatan Etika](#catatan-etika).

---

## Kategori dalam Modul Ini

| # | Kategori | Ringkas | Jumlah topik kisi-kisi | README kategori |
|---|---|---|---|---|
| 1 | **Reverse Engineering** | Bongkar logika program dari binari: rekonstruksi algoritma, tracing dinamis, lawan anti-RE, lalu *patch*/pecahkan. | 9 | [`./reverse-engineering/README.md`](./reverse-engineering/README.md) |
| 2 | **Digital Forensic** | Rekonstruksi kejadian dari artefak: carving file, jaringan, log, OS, memori, hingga analisis malware. | 6 | [`./digital-forensic/README.md`](./digital-forensic/README.md) |

### 1. Reverse Engineering → [`./reverse-engineering/`](./reverse-engineering/README.md)

Membongkar program untuk memahami atau memulihkan logikanya (mis. validasi *flag*, rutin enkripsi, atau perilaku malware). Sembilan topik kisi-kisi:

1. **Static Analysis** — rekonstruksi algoritma dari disassembly/decompile, penyelesaian kendala dengan **z3**.
2. **Dynamic Analysis** — *tracing* dan debugging dengan **GDB**.
3. **Low Level File Formats** — pembacaan Assembly & terjemahan *bytecode*.
4. **Anti-RE** — Anti-Debug (**PTRACE**), Simple Anti-Disassembly, Simple Anti-Decompiler.
5. **Format bahasa terkompilasi dalam executable** — pola khas **C, C++, Golang, Rust**, dll.
6. **Arsitektur** — **x86_64, x64, ARM, MIPS**.
7. **Framework khusus** — **Flutter, Kotlin, Desktop Apps (Qt)**, dsb.
8. **Obfuscation & Binary Patching** — enkripsi *known/custom* dan menambal binari.
9. **Mobile Reverse Engineering** — pembongkaran aplikasi mobile.

### 2. Digital Forensic → [`./digital-forensic/`](./digital-forensic/README.md)

Menggali dan merekonstruksi bukti dari artefak digital yang tertinggal. Enam topik kisi-kisi:

1. **File Carving** — pemulihan file dengan **binwalk, foremost, photorec**.
2. **Network Forensic** — analisis **PCAP/PCAPNG**.
3. **Log Forensic** — **SIEM** dan *standalone logs*.
4. **OS Forensic** — Browser, AppData, aplikasi pihak ketiga, dan *Digital Artifact Discovery* (Windows/Linux).
5. **Memory Forensic** — analisis memori dengan **Volatility**.
6. **Malware Analysis** — analisis perilaku dan karakteristik sampel berbahaya.

---

## Relevansi ke Penilaian Lomba

Modul C dijadwalkan pada **Hari Ketiga (H3)** dengan total waktu pengerjaan **~5 jam** (sesi 09.15–12.00 = 2j45m, lalu 13.00–15.15 = 2j15m).

**Bobot: 40%** dari total nilai lomba, dipecah menjadi **Judgement 10** dan **Measurement 30** (tabel komposisi penilaian §3.2.3 — sama persis dengan Modul B Offensive CTF).

> **Catatan dua sumber.** Tabel komposisi (§3.2.3) memberi Modul C **40/100 (40%)**. Namun tabel *prosedur penilaian* (§3.6) mencantumkan **bobot 50%** untuk H3 (Modul A & B masing-masing 25%). Sesuai kaidah materi ("bila dua sumber berbeda, tampilkan keduanya"), gunakan **40%** sebagai angka utama (selaras dengan rincian J:10 + M:30) dan catat bahwa §3.6 menyebut 50% — konfirmasi ke juri/panitia bila menentukan strategi alokasi nilai.

Apa artinya bagi strategi pengerjaan:

| Komponen | Porsi | Cara dinilai | Implikasi |
|---|---|---|---|
| **Measurement (M)** | 30 (mayoritas) | Biner: **1 bila benar, 0 bila tidak** (mis. *flag* tertangkap, objektif tercapai). | Sumber poin terbesar. Prioritaskan **menangkap flag** — tidak ada nilai parsial untuk usaha tanpa hasil. |
| **Judgement (J)** | 10 | Skor juri **0–3** atas kualitas POC/penjelasan (kejelasan langkah, screenshot, bukti). | Tulis **writeup/POC yang jernih dan berbukti** untuk tiap tantangan yang diselesaikan; ini menambah nilai di atas flag mentah. |

Karena formatnya **Jeopardy** (tantangan independen, masing-masing bernilai sendiri), tidak ada keterkaitan *blocker* antar-soal — setiap *flag* yang masuk langsung menambah skor.

---

## Saran Urutan Pengerjaan

Urutan di bawah dioptimalkan untuk **format jeopardy + measurement-dominan + waktu tetap 5 jam**. Inti strateginya: **maksimalkan jumlah flag**, hindari terjebak satu soal.

1. **Sapu cepat semua soal lebih dulu (10–15 menit).** Baca seluruh tantangan di **kedua** kategori, catat poin/estimasi kesulitan. Jangan langsung menukik ke satu binari.
2. **Petik yang mudah lintas kategori.** Ambil *low-hanging fruit* di RE **dan** Forensic (mis. *strings*/carving sederhana, PCAP ringan, *static* trivial). Flag biner-bernilai-penuh dari soal mudah sama harganya dengan dari soal sulit.
3. **Masuk ke kelas menengah sesuai kekuatanmu.** Kerjakan kategori yang paling kamu kuasai untuk mengamankan *measurement*, sambil mulai mencatat bukti untuk POC.
4. **Kotak-waktu (time-box) soal sulit.** Tetapkan batas (mis. 30–40 menit) per tantangan berat; bila buntu, **tinggalkan dan putar** ke soal lain, kembali jika ada sisa waktu. Rabbit-hole pada satu RE ber-obfuscation adalah jebakan skor terbesar di modul ini.
5. **Sisihkan ~30 menit terakhir untuk POC.** Rapikan **Judgement (J:10)**: pastikan tiap flag yang didapat punya langkah + screenshot yang bisa diverifikasi juri. Flag tanpa POC kehilangan nilai judgement.

> **Manajemen waktu sesi.** Ada jeda istirahat 12.00–13.00 di tengah. Gunakan blok pagi (2j45m) untuk sapu + petik mudah + amankan menengah, dan blok siang (2j15m) untuk soal sulit ter-timebox + penulisan POC. Catat di mana kamu berhenti sebelum istirahat.

---

## Catatan Etika

- Sampel yang dianalisis di modul ini (binari, malware, *image* memori, PCAP) hanya untuk **lab kompetisi / sistem dengan izin tertulis**.
- **Jalankan malware hanya di VM terisolasi** — snapshot dulu, jaringan host-only atau terputus, dan jangan eksekusi di host kerja. Detonasi tak sengaja bisa merusak data nyata.
- Tooling reverse engineering & forensik dipakai untuk **memahami dan mempertahankan**, bukan untuk mendistribusikan ulang malware atau menyerang sistem lain.
- Hormati aturan lomba: kumpulkan flag lewat analisis yang sah, bukan dengan menyerang infrastruktur scoring atau peserta lain.

---

## Sumber Rujukan

- **Kisi-kisi LKS Nasional 2026** (`reference/lksn-2026-kisi-kisi.pdf`) — daftar topik per kategori (Reverse Engineering & Digital Forensic).
- **Technical Description LKS Nasional 2026** (`reference/lksn-2026-technical-description.pdf`) — format jeopardy, jadwal H3, dan komposisi penilaian (§3.2.3 J:10/M:30; §3.6 bobot H3).
- README per kategori (subfolder) untuk materi teknis mendalam tiap topik.
