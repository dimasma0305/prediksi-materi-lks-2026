# Digital Forensic (Modul C)

> Kategori **Digital Forensic** berfokus pada penyelidikan barang bukti digital: memulihkan data yang terhapus, merekonstruksi aktivitas dari jejak yang tertinggal, dan membuktikan apa yang terjadi pada sebuah sistem. Dalam konteks CTF/lomba, peran kategori ini adalah **menemukan flag yang tersembunyi di dalam artefak** — file, paket jaringan, log, image disk, dump memori, atau sampel malware — dengan pendekatan analitis, metodis, dan dapat dipertanggungjawabkan secara teknis.

## Peta ke Kisi-kisi LKSN 2026

Kategori ini merupakan bagian dari **Modul C — Defensive CTF**. Digital Forensic menuntut peserta menguasai siklus investigasi *defensive*: identifikasi, akuisisi, analisis, dan pelaporan terhadap bukti digital. Kemampuan ini bersifat reaktif (pasca-insiden) dan menjadi penyeimbang dari keahlian *offensive*, sehingga peserta mampu memahami serangan dari sisi jejak yang ditinggalkannya.

## Daftar Topik

| No | Topik | File | Cakupan/Contoh | Status |
|----|-------|------|----------------|--------|
| 1 | File Carving | [01-file-carving.md](01-file-carving.md) | binwalk, foremost, photorec | ✅ selesai |
| 2 | Network Forensic | [02-network-forensic.md](02-network-forensic.md) | PCAP/PCAPNG | ✅ selesai |
| 3 | Log Forensic | [03-log-forensic.md](03-log-forensic.md) | SIEM, Standalone Logs | ✅ selesai |
| 4 | OS Forensic | [04-os-forensic.md](04-os-forensic.md) | Browser, AppData, Third Party App, Artifact Discovery (Windows/Linux) | ✅ selesai |
| 5 | Memory Forensic | [05-memory-forensic.md](05-memory-forensic.md) | Volatility | ✅ selesai |
| 6 | Malware Analysis | [06-malware-analysis.md](06-malware-analysis.md) | static+dynamic, sandbox, IOC, YARA | ✅ selesai |

## Catatan

Setiap topik di atas merupakan **satu halaman tersendiri** yang ditulis dengan **template seragam**, mencakup bagian-bagian berikut:

- **Konsep** — definisi dan latar belakang topik.
- **Cara Kerja** — mekanisme teknis di balik artefak/teknik.
- **Indikator / Cara Mengenali** — tanda-tanda di artefak yang patut dicurigai.
- **Langkah Analisis/Investigasi** — alur investigasi tahap demi tahap.
- **Tools** — perkakas yang relevan beserta kegunaannya.
- **Contoh/Payload** — contoh kasus, perintah, atau sampel nyata.
- **Anti-Forensik & Pitfall** — teknik anti-forensik attacker dan kesalahan analis yang membuat flag terlewat.
- **Mini-Lab** — latihan praktik singkat untuk menguji pemahaman.
- **Referensi** — bahan bacaan dan sumber lanjutan.
