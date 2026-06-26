# 1. File Carving

> File carving adalah teknik memulihkan file langsung dari raw data (image disk, blob memori, atau sebuah file kontainer) **tanpa bergantung pada metadata filesystem** — murni dengan mengenali struktur internal file itu sendiri. Di CTF LKSN 2026 (Modul C — Digital Forensic), soal kategori ini biasanya memberi sebuah disk image (`.dd`, `.raw`, `.img`), sebuah file "tak berdosa" (PNG/PDF/ZIP) yang ternyata menyembunyikan data lain, atau unallocated space berisi sisa file terhapus. Tuntutannya: angkat flag yang dikubur di dalamnya menggunakan tool seperti **binwalk**, **foremost**, dan **photorec**.

## Konsep

Sebuah filesystem (NTFS, ext4, FAT) menyimpan *metadata* — tabel inode/MFT yang mencatat di blok mana sebuah file berada beserta nama dan ukurannya. Ketika file dihapus, isinya sering **masih utuh di disk**; yang hilang hanya entri metadata-nya. File carving mengabaikan metadata itu dan bekerja pada **konten mentah**: ia memindai byte stream mencari **magic bytes** (signature header) dan **footer** yang menandai awal-akhir sebuah tipe file, lalu "mengukir" (carve) rentang byte di antaranya menjadi file utuh.

Carving relevan di CTF dalam beberapa skenario klasik:

- **Recovery** — file dihapus / partisi diformat, isi harus diangkat dari unallocated space.
- **Embedded / appended data** — flag ditempel **setelah footer** sebuah PNG, atau file ZIP disisipkan di tengah gambar (lihat trik polyglot & steg).
- **Firmware / blob** — sebuah image firmware atau dump berisi banyak file ter-embed (filesystem, kernel, sertifikat) yang harus dipisah.

Dua pendekatan utama: **header-footer carving** (cari signature awal & akhir, ambil semua di antaranya) dan **header + max-size carving** (jika tidak ada footer pasti, ambil sejumlah byte tetap). Tantangan terbesar adalah **fragmentasi**: file yang tidak tersimpan kontigu sulit di-carve utuh, dan inilah batas teoretis semua tool carving.

## Cara Kerja

Setiap format file punya **magic number** di awal (dan sering penanda akhir). Carver memindai seluruh stream byte demi byte mencari pola ini, mencatat offset, lalu menyalin rentang `[header .. footer]` keluar sebagai file baru. Beberapa signature kunci yang wajib dihafal:

| Tipe | Header (hex) | Footer / penanda akhir |
|---|---|---|
| JPEG | `FF D8 FF` | `FF D9` |
| PNG | `89 50 4E 47 0D 0A 1A 0A` | `49 45 4E 44 AE 42 60 82` (`IEND`) |
| GIF | `47 49 46 38` (`GIF8`) | `00 3B` |
| PDF | `25 50 44 46` (`%PDF`) | `25 25 45 4F 46` (`%%EOF`) |
| ZIP / Office / APK | `50 4B 03 04` (`PK..`) | `50 4B 05 06` (EOCD) |
| GZIP | `1F 8B 08` | — (stream) |
| ELF | `7F 45 4C 46` (`.ELF`) | — |

Perbedaan filosofi tiga tool inti pada kisi-kisi:

- **binwalk** — dirancang untuk **firmware/blob analysis**. Versi modern (**binwalk 3.x**, ditulis ulang dalam **Rust** oleh ReFirmLabs) memindai *semua* signature yang dikenalnya di setiap offset, lalu memanggil **extractor eksternal** (mis. `unsquashfs`, `jefferson`, `7z`) untuk membongkar tiap blob. Kuncinya: **recursive extraction** (matryoshka) dan **entropy analysis** untuk menemukan region terkompresi/terenkripsi.
- **foremost** — carver **header-footer klasik** berbasis konfigurasi (`/etc/foremost.conf`). Cepat, deterministik, cocok untuk image disk; output rapi per tipe + `audit.txt`. (**scalpel** adalah turunan foremost yang lebih cepat tapi mengharuskan meng-*uncomment* tipe file di config-nya.)
- **photorec** — bagian dari paket **TestDisk** (Christophe Grenier / CGSecurity), **signature-based recovery** untuk **>480 tipe file**. Ia sengaja **mengabaikan filesystem** sehingga tetap bekerja pada media yang rusak/diformat, dengan trade-off: **nama file asli hilang** (hasil dinamai `f0000001.jpg`, dst.).

## Indikator / Cara Mengenali

Tanda bahwa sebuah artefak menyimpan file tersembunyi atau layak di-carve:

- **`file` salah / generik** — ekstensi `.png` tapi `file` bilang "data", atau ukuran jauh lebih besar dari yang masuk akal untuk dimensinya.
- **Signature ganda** — `binwalk` menampilkan lebih dari satu signature dalam satu file (mis. PNG di offset 0 **dan** `Zip archive` di offset belakang) → ada appended/embedded data.
- **Byte setelah footer** — pada hexdump masih ada data **setelah** `IEND` (PNG) atau `%%EOF` (PDF) → kandidat kuat penyembunyian flag.
- **Lonjakan entropy** — region ber-entropy tinggi (≈8 bit/byte) di tengah file berstruktur rendah → blob terkompresi/terenkripsi.
- **String mencurigakan** — `strings` mengungkap `PK`, `flag{`, header base64, atau nama path di tempat yang tidak semestinya.
- **Unallocated space tidak kosong** — pada image disk, area "kosong" berisi sisa header file → bukti penghapusan.

## Langkah Analisis/Investigasi

1. **Identifikasi kontainer** — `file target`, lalu `xxd target | head` untuk membaca magic bytes awal dan memastikan tipe sebenarnya, bukan sekadar ekstensi.
2. **Pindai signature** — `binwalk target` untuk memetakan semua struktur ter-embed beserta offset-nya. Ini peta jalan sebelum mengukir apa pun.
3. **Periksa entropy** — `binwalk -E target` untuk menemukan region terkompresi/terenkripsi yang menandai blob tersembunyi.
4. **Cek ekor file** — bandingkan ukuran nyata dengan posisi footer; bila ada data setelah footer, itu prioritas pertama.
5. **Ekstrak ter-embed** — `binwalk -e` (dan `-M` untuk rekursif) membongkar blob; untuk image disk, gunakan `foremost`/`photorec` mengangkat banyak file sekaligus.
6. **Validasi hasil** — jalankan `file`/buka tiap hasil carve; carver sering menghasilkan file korup atau over-carved (terlalu panjang). Sortir yang valid.
7. **Telusuri lanjutan** — `strings`, `exiftool`, atau unzip pada hasil; flag sering ada di metadata, di dalam ZIP terkarvel, atau butuh decode base64/hex.
8. **Dokumentasi** — catat offset, tool, dan rantai ekstraksi sebagai bukti POC yang reprodusibel.

## Tools

| Tool | Fungsi singkat |
|---|---|
| `file` | Identifikasi tipe via magic bytes (langkah nol) |
| `xxd` / `hexdump` | Inspeksi byte mentah, baca header/footer manual |
| `strings` | Tarik teks tercetak (flag, base64, path) dari binary |
| **binwalk** | Pindai & ekstrak file ter-embed di firmware/blob; entropy + recursive (`-e`,`-M`,`-E`) |
| **foremost** | Header-footer carving berbasis `/etc/foremost.conf`; output per tipe + `audit.txt` |
| **scalpel** | Turunan foremost yang lebih cepat; tipe diaktifkan via config |
| **photorec** | Signature recovery >480 tipe, abaikan filesystem (paket TestDisk) |
| **testdisk** | Pulihkan partisi & undelete dengan **nama file** masih utuh |
| `bulk_extractor` | Pindai fitur (email, URL, kartu, ZIP) + carve tanpa parsing FS |
| `exiftool` | Baca/ekstrak metadata & thumbnail tertanam |
| `dd` | Carve manual presisi byte berdasarkan offset hasil binwalk |
| `zsteg` / `steghide` | Lanjutan bila penyembunyian bersifat steganografi, bukan sekadar append |

## Contoh / Payload

**Triase sebuah file "gambar" yang mencurigakan:**

```bash
# 0) Apa ini sebenarnya?
file suspicious.png            # PNG image data ... tapi 5 MB?
xxd suspicious.png | head      # konfirmasi magic 89 50 4E 47 (PNG)

# 1) Petakan isi — adakah file lain di dalam?
binwalk suspicious.png
# DECIMAL    HEXADECIMAL   DESCRIPTION
# 0          0x0           PNG image, 800 x 600
# 137216     0x21800       Zip archive data, "secret.txt"
#                          ^-- ZIP ditempel SETELAH gambar (appended data)

# 2) Ekstrak otomatis (rekursif) ke folder _suspicious.png.extracted/
binwalk -e -M suspicious.png
unzip -o _suspicious.png.extracted/*.zip
cat secret.txt | grep -i 'flag{'

# 2b) Atau carve manual presisi pakai offset di atas
dd if=suspicious.png of=hidden.zip bs=1 skip=$((0x21800))
unzip -o hidden.zip
```

**Recovery dari disk image (banyak file terhapus) dengan foremost:**

```bash
# Carve tipe tertentu (atau 'all') dari image ke folder out/
foremost -t jpg,png,pdf,zip -i evidence.dd -o out/
# Hasil tersortir per tipe + ringkasan di out/audit.txt:
cat out/audit.txt
ls out/zip/ out/pdf/
strings -a out/**/* | grep -iE 'LKSN\{|flag\{'
```

**Recovery agresif lintas-tipe dengan photorec (non-interaktif):**

```bash
# Abaikan filesystem, carve SEMUA tipe yang dikenal ke recup_dir.*
photorec /d recup_dir /cmd evidence.dd search
# Nama asli hilang -> hasil bernama f0000001.jpg dst.
find recup_dir.* -type f -exec file {} \;       # validasi tiap hasil
```

**Periksa entropy untuk menemukan blob terenkripsi/terkompresi:**

```bash
binwalk -E firmware.bin        # plot entropy; lonjakan ~8 bit/byte = blob
# (binwalk 3.x menyimpan grafik entropy sebagai PNG secara default; pakai --png untuk nama output kustom)
```

## Anti-Forensik & Pitfall

**Teknik anti-forensik attacker** (mempersulit carving):

- **Spoofed / false magic bytes** — header dipalsukan (mis. payload diberi header `FF D8 FF` agar dikira JPEG, atau file ZIP diberi prefix `%PDF`). Carver akan salah mengukir atau menghasilkan file korup. Lawan dengan validasi konten, bukan sekadar header.
- **Polyglot files** — satu file valid sebagai dua format sekaligus (mis. **PDF + ZIP**, atau gambar yang juga arsip). Footer satu format menjadi awal data format lain; carver naif berhenti terlalu cepat.
- **Appended data di slack/setelah footer** — flag ditempel setelah `IEND`/`%%EOF`; tool yang hanya membaca file "sampai footer" akan melewatkannya. Selalu cek byte setelah penanda akhir.
- **Fragmentasi sengaja & bifragment gap** — file dipecah ke blok non-kontigu; header-footer carving menyatukan potongan yang salah. Ini batas fundamental carving.
- **Enkripsi / kompresi** — payload dienkripsi (entropy tinggi, tanpa signature) sehingga **tidak ada yang bisa di-carve** sampai dekripsi; carving hanya melihat blob acak.
- **Wiping** — `shred`/zero-fill menimpa unallocated space sehingga sisa file hilang permanen.

**Pitfall analis** (kesalahan yang membuat flag terlewat):

- **Percaya ekstensi.** `.png` bisa apa saja; selalu mulai dengan `file` + `xxd`/`binwalk`, bukan asumsi.
- **Tidak rekursif.** Lupa `-M` (matryoshka) pada binwalk → blob di dalam blob tak terbongkar. ZIP-dalam-PNG-dalam-firmware sering bertingkat.
- **Berhenti di footer pertama.** Mengabaikan data setelah `IEND`/`%%EOF` adalah penyebab nomor satu flag CTF terlewat.
- **Over-carving & file korup.** foremost/photorec sering menghasilkan file yang **terpotong atau kepanjangan** (terbawa data blok berikutnya). Jangan percaya hasil mentah — validasi tiap file dengan `file`/buka.
- **Batas ukuran config.** foremost memotong di ukuran maksimum per tipe pada `foremost.conf`; file besar bisa ter-truncate. Sesuaikan config bila hasil tampak terpotong.
- **photorec menghapus nama.** Hasil dinamai generik (`f0000001.*`); konteks nama asli hilang — korelasikan via isi/`exiftool`, bukan nama.
- **Mengabaikan entropy.** Region "acak" bukan berarti kosong — bisa data terenkripsi/terkompresi yang justru menyimpan flag.
- **Hanya carve area teralokasi.** Carve dari **seluruh image** (termasuk unallocated/slack), bukan hanya partisi yang ter-mount.

## Mini-Lab

**Skenario:** Diberikan `case01.dd` (image FAT32) dan sebuah file `holiday.png` yang "terlihat normal" tapi berukuran janggal. Flag tersembunyi sebagai data yang ditempel di balik gambar dan sebagai file PDF yang sudah dihapus pada image.

1. **Lakukan:** `file holiday.png` lalu `binwalk holiday.png` → **dapatkan** daftar signature; identifikasi `Zip archive` yang muncul setelah blok PNG.
2. **Lakukan:** `binwalk -e -M holiday.png` (atau `dd ... skip=<offset>`), lalu `unzip` hasilnya → **dapatkan** file teks berisi bagian pertama **`flag{...}`**.
3. **Lakukan:** `foremost -t pdf,all -i case01.dd -o out/` dan periksa `out/audit.txt` → **dapatkan** PDF terkarvel; buka/`strings` untuk bagian kedua flag.
4. **Lakukan (silang-cek):** `photorec /d recup /cmd case01.dd search`, lalu `file recup.*/*` untuk memvalidasi hasil → **dapatkan** konfirmasi file yang sama dan tulis timeline kontainer → offset → tool → flag sebagai POC (Judgement).

## Referensi & Latihan

- **ReFirmLabs/binwalk** — repo & dokumentasi binwalk 3.x (Rust), daftar signature dan extractor.
- **CGSecurity (TestDisk & PhotoRec) Wiki** — panduan resmi PhotoRec data carving dan recovery TestDisk.
- **Foremost / Scalpel man pages** — opsi `-t/-i/-o/-c` dan struktur `foremost.conf`.
- **DFIR / NIST** — referensi konsep carving, fragmentasi, dan bifragment gap carving.
- **TryHackMe — "File Carving"** dan **picoCTF Forensics** — latihan carving & embedded-data bertahap.
- **CyberDefenders** & **BlueTeam Labs Online (BTLO)** — challenge blue-team berbasis disk/file image nyata.
- **HackTheBox Sherlocks** — investigasi DFIR yang kerap memuat tahap carving.
- **SANS DFIR (FOR500 / FOR508)** poster & cheat sheet — referensi cepat signature & alur recovery saat lomba.

---

> **Catatan etika.** Teknik di halaman ini hanya untuk **lingkungan lab, sistem milik sendiri, atau dengan izin tertulis**, serta untuk keperluan **CTF/latihan resmi LKSN 2026**. File carving dapat mengangkat data sensitif/pribadi; memulihkan atau mengakses data dari media milik orang lain tanpa otorisasi adalah pelanggaran hukum dan etika. Carve hanya pada bukti yang sah dan dalam ruang lingkup yang diizinkan.
