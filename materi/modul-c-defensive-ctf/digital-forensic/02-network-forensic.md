# 2. Network Forensic

> Network forensic adalah analisis lalu lintas jaringan yang telah ditangkap (capture) untuk merekonstruksi komunikasi yang terjadi: siapa berbicara dengan siapa, lewat protokol apa, dan data apa yang dipindahkan. Di CTF LKSN 2026 (Modul C — Digital Forensic), soal kategori ini umumnya memberi sebuah file **PCAP/PCAPNG** dan menuntut peserta mengangkat flag dari isi paket — mengekstrak file dari transfer HTTP, memulihkan kredensial plaintext, mengikuti sebuah TCP stream, membongkar DNS tunneling/exfiltrasi, atau mendekode keystroke USB. Inti pekerjaannya: membuka *wire data* mentah lalu menyusunnya kembali menjadi cerita yang bisa dibuktikan.

## Konsep

Tidak seperti memory atau disk forensic yang melihat satu host, network forensic melihat **interaksi antar-host**. Lalu lintas yang sudah lewat tidak bisa diulang, jadi bukti utamanya adalah *capture* yang direkam saat insiden berlangsung. Ada dua tingkat sumber bukti:

- **Full Packet Capture (FPC)** — seluruh byte tiap paket disimpan ke file **PCAP** (format libpcap klasik) atau **PCAPNG** (PCAP Next Generation). Ini yang paling sering muncul di CTF karena flag sering ada di *payload* aplikasi.
- **Flow / metadata** — ringkasan koneksi tanpa payload penuh, mis. **NetFlow/IPFIX** atau log **Zeek**. Berguna untuk triase volume besar.

Network forensic muncul di CTF ketika: flag dikirim mentah lewat protokol tak terenkripsi (FTP, HTTP, Telnet), file dipindahkan via HTTP/SMB/TFTP, kredensial bocor di HTTP Basic auth atau `USER`/`PASS` FTP, attacker membangun C2 dengan beacon periodik, data diselundupkan lewat DNS/ICMP, atau sebuah pcap berisi capture USB yang harus didekode menjadi keystroke.

## Cara Kerja

Capture dilakukan di *link layer* oleh library **libpcap** (Linux/Unix) atau **Npcap** (Windows, penerus WinPcap), lalu disimpan ke file. Memahami dua format file adalah kunci membaca soal:

- **PCAP (libpcap)** — sederhana dan linear: satu *global header* (magic `0xa1b2c3d4` untuk resolusi mikrodetik, atau `0xa1b23c4d` untuk nanodetik) yang menyimpan **link-type** dan **snaplen**, diikuti deretan record: tiap paket punya *record header* (timestamp, `caplen`, `len`) lalu data paket. `caplen < len` berarti paket **terpotong** karena snaplen — sumber klasik file ekstraksi yang rusak.
- **PCAPNG (PCAP Next Generation)** — berbasis *block*, lebih kaya. Blok-blok intinya: **SHB** (Section Header Block, wajib, byte-order magic `0x1a2b3c4d`), **IDB** (Interface Description Block — mendefinisikan tiap interface: link-type, snaplen, dan resolusi waktu lewat opsi `if_tsresol`, mis. `0x09` = nanodetik), **EPB** (Enhanced Packet Block — satu paket beserta *interface id* dan timestamp 64-bit), serta **SPB**, **ISB** (Interface Statistics), dan **NRB** (Name Resolution). Keunggulan PCAPNG: mendukung **banyak interface dalam satu file**, timestamp nanodetik, dan **komentar/anotasi** per-paket (sering jadi tempat hint atau bahkan flag tersembunyi — periksa kolom *packet comments*).

Setelah file dibuka, **dissector engine** (Wireshark/tshark) menumpuk layer secara berurutan: `Ethernet → IP → TCP → HTTP`. Yang membuat payload aplikasi bisa dibaca utuh adalah **TCP reassembly** — engine menyusun ulang segmen TCP (yang terpecah, *out-of-order*, atau ter-retransmit) menjadi satu aliran byte (*stream*), barulah dissector lapisan atas (HTTP, TLS, SMB) bisa memparsernya. **Link-type** pada header menentukan cara dekoding lapisan terbawah — Ethernet, 802.11, atau **USB** (`LinkType USBPcap`/`Linux mmapped`) untuk capture perangkat.

## Indikator / Cara Mengenali

Hal yang patut dicurigai/diburu saat membuka sebuah capture:

- **Kredensial plaintext** pada protokol tak terenkripsi: `USER`/`PASS` (FTP), `Authorization: Basic <base64>` (HTTP), login Telnet, `AUTH`/`USER` POP3/IMAP/SMTP.
- **Transfer file** lewat HTTP (`Content-Type`, `Content-Disposition: attachment`), SMB, atau TFTP → kandidat **Export Objects**.
- **Beaconing**: koneksi keluar berinterval konstan ke satu IP/domain → pola C2.
- **DNS anomali**: query bertubi ke satu domain dengan subdomain panjang/acak atau record `TXT`/`NULL` besar → **DNS tunneling/exfiltrasi** (iodine, dnscat2).
- **ICMP** dengan payload besar atau berpola → **ICMP tunneling** (ptunnel).
- **Protokol di port tak lazim** (TLS di 8443, SSH di 443) atau handshake TLS dengan **sertifikat self-signed** / **SNI** janggal.
- **Capture USB** (link-type USB) berisi `URB_INTERRUPT in` 8-byte → keystroke HID keyboard.

Sebagai baseline cepat, hafalkan filter tampilan (*display filter*) Wireshark/tshark yang paling sering membuka soal:

| Tujuan | Display filter |
|---|---|
| Hanya request HTTP | `http.request` |
| Lalu lintas satu host | `ip.addr == 10.0.0.5` |
| Satu sesi TCP utuh | `tcp.stream eq 3` |
| Query DNS | `dns.qry.name` |
| SNI pada TLS | `tls.handshake.extensions_server_name` |
| Kredensial FTP | `ftp.request.command == "PASS"` |
| Cari string di payload | `frame contains "flag"` |
| Keystroke USB | `usb.transfer_type == 0x01 && usb.data_len == 8` |

## Langkah Analisis/Investigasi

**Prasyarat (mulai dari sini):** capture (`.pcap`/`.pcapng`) **sudah disediakan panitia** — akuisisi tidak perlu di lomba. Untuk langkah GUI, buka file lebih dulu: jalankan **Wireshark → menu File > Open → pilih `file.pcapng` → klik Open** sampai daftar paket tampil. Untuk langkah CLI, pastikan `tshark`, `capinfos`, dan `editcap` terpasang (verifikasi `tshark -v`).

1. **Validasi capture** — jalankan `capinfos file.pcapng` untuk melihat jumlah paket, durasi, link-type, dan apakah paket **terpotong** (snaplen) → hasilnya ringkasan capture; bila `caplen < len` muncul, paket truncated. Tahu medannya sebelum menggali.
2. **Petakan protokol** — di Wireshark klik menu **Statistics > Protocol Hierarchy** untuk melihat protokol dominan, lalu **Statistics > Conversations** (pindah ke tab **TCP**/**UDP**) dan **Statistics > Endpoints** untuk host & port paling aktif → hasilnya daftar protokol + pasangan IP/port teratas.
3. **Filter & fokus** — ketik display filter di bar atas Wireshark (mis. `http.request`, `dns`, `ftp`, `tls.handshake`) lalu tekan Enter → tampilan menyusut ke protokol yang relevan dengan pertanyaan soal.
4. **Follow stream** — klik kanan salah satu paket sesi target → **Follow > TCP Stream** (atau **UDP Stream**/**HTTP Stream**) → jendela stream menampilkan percakapan utuh (request+response) tempat flag/kredensial biasanya berada; ubah dropdown **Show data as** ke *Raw*/*Hex Dump* bila isinya biner.
5. **Ekstrak objek/file** — klik **File > Export Objects > HTTP** (atau SMB/TFTP/IMF/DICOM) → pilih objek → **Save All** ke sebuah folder; alternatif CLI `tshark -r file.pcapng --export-objects http,./loot`, atau buka capture di **NetworkMiner** lalu lihat tab *Files* → hasilnya file-file yang ditransfer tersimpan di disk.
6. **Decode artefak** — decode konten hasil ekstraksi sesuai bentuknya: `base64 -d` untuk base64, `gunzip`/dissector untuk `Content-Encoding: gzip`, `xxd -r -p` untuk hex, atau parser keystroke untuk capture USB → hingga menjadi data bersih yang terbaca.
7. **Dekripsi TLS** — bila tersedia **key log** (`SSLKEYLOGFILE`) atau **private key RSA**, muat lewat **Edit > Preferences > Protocols > TLS → (Pre)-Master-Secret log filename** (untuk key log) atau **RSA keys list** (untuk private key) → trafik HTTPS ter-dekripsi dan muncul sebagai HTTP biasa di daftar paket.
8. **Korelasi & timeline** — satukan urutan (koneksi → transfer → decode → flag) → hasilnya timeline reprodusibel sebagai bukti POC.

## Tools

| Tool | Fungsi singkat |
|---|---|
| **Wireshark** | GUI analisis paket; dissector ratusan protokol, Follow Stream, Export Objects |
| **tshark** | Versi CLI Wireshark; display filter, ekstraksi field (`-T fields`), export objects |
| **tcpdump** | Capture & filter cepat berbasis **BPF** di host Unix |
| **capinfos** | Metadata & validasi capture (count, durasi, link-type, truncated) |
| **editcap** / **mergecap** | Potong/filter & gabung capture; konversi PCAP↔PCAPNG |
| **NetworkMiner** | Ekstraksi otomatis file, kredensial, host, dan sesi berbasis konten |
| **Zeek** (formerly Bro) | Hasilkan log koneksi/protokol terstruktur dari pcap untuk triase |
| **Suricata** | IDS/IPS; deteksi signature & ekstraksi file dari trafik |
| **Arkime** (formerly Moloch) | Indexing & pencarian sesi pada capture skala besar |
| **Zui** (formerly Brim) / **Brimcap** | Triase pcap cepat lewat log Zeek+Suricata, pivot ke Wireshark |
| **Scapy** | Manipulasi/parsing paket programatik (Python) |
| **foremost** / **binwalk** | Carve file dari payload yang sudah diekstrak |
| **CTF-Usb_Keyboard_Parser** | Dekode keystroke HID keyboard dari pcap/pcapng |

## Contoh / Payload

**Akuisisi & validasi** (langkah nol — di lomba pcap sudah disediakan, tapi pahami caranya):

```bash
# Capture ke file (BPF filter: hanya host & port tertentu)
sudo tcpdump -i eth0 -s 0 -w capture.pcap 'host 10.0.0.5 and port 80'

# Validasi capture: link-type, jumlah paket, durasi, truncated?
capinfos capture.pcapng

# Konversi PCAPNG -> PCAP klasik bila tool lawas butuh format itu
editcap -F libpcap capture.pcapng capture.pcap
```

**Analisis** — menambang flag dari sebuah capture:

```bash
# 0) Peta protokol (apa yang dominan di capture ini?)
tshark -r capture.pcapng -q -z io,phs

# 1) Daftar request HTTP + host + URI
tshark -r capture.pcapng -Y http.request -T fields -e ip.src -e http.host -e http.request.uri

# 2) Rekonstruksi satu sesi TCP utuh (stream index 3) sebagai teks
tshark -r capture.pcapng -q -z follow,tcp,ascii,3

# 3) Ekstrak semua objek HTTP (file terunduh) ke folder ./loot
tshark -r capture.pcapng --export-objects http,./loot
strings ./loot/* | grep -iE 'LKSN\{|flag\{'

# 4) Kredensial FTP yang dikirim plaintext
tshark -r capture.pcapng -Y 'ftp.request.command in {"USER","PASS"}' \
       -T fields -e ftp.request.command -e ftp.request.arg

# 5) HTTP Basic auth -> ambil header mentah lalu decode base64 jadi user:pass
tshark -r capture.pcapng -Y http.authorization -T fields -e http.authorization
#   -> Basic YWRtaW46czNjcmV0
echo 'YWRtaW46czNjcmV0' | base64 -d        # -> admin:s3cret

# 6) Indikasi DNS exfiltrasi: subdomain panjang/acak ke satu domain
tshark -r capture.pcapng -Y dns.qry.name -T fields -e dns.qry.name | sort -u | head

# 7) Dekripsi TLS bila disediakan key log (SSLKEYLOGFILE)
tshark -r https.pcapng -o tls.keylog_file:sslkeys.log -Y http -T fields -e http.file_data

# 8) Capture USB keyboard -> ambil 8-byte HID report (keycode di byte ke-3)
tshark -r usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata
#   lalu petakan keycode ke karakter (mis. CTF-Usb_Keyboard_Parser)
python3 main.py keystrokes.txt        # -> rekonstruksi teks yang diketik
```

## Anti-Forensik & Pitfall

**Teknik anti-forensik attacker** (mempersulit analisis trafik):

- **Enkripsi (TLS/HTTPS, SSH)** — payload tak terbaca tanpa kunci. Tetap eksploitasi **metadata** yang bocor: **SNI**, isi sertifikat, fingerprint **JA3/JA3S**, serta ukuran & timing paket untuk inferensi.
- **Tunneling / covert channel** — data dibungkus dalam protokol yang tampak sah: **DNS tunneling** (iodine, dnscat2), **ICMP tunneling** (ptunnel), atau HTTP/HTTPS. Cari volume/ pola query yang tidak wajar untuk protokolnya.
- **Port non-standar, port hopping, domain fronting, fast-flux DNS** — membuat penyaringan berbasis port/IP gagal; andalkan analisis berbasis *konten/protokol*, bukan nomor port.
- **Fragmentasi IP & TCP segmentation/overlap** — memecah payload agar lolos IDS atau mengelabui dissector yang tidak melakukan reassembly.
- **Timing/padding covert channel & steganografi** dalam field protokol (mis. ID/TTL/sequence) — flag disisipkan di tempat yang tidak diparser otomatis.

**Pitfall analis** (kesalahan yang membuat flag terlewat):

- **Lupa TCP reassembly.** Tanpa "Allow subdissector to reassemble TCP streams", payload aplikasi terpotong dan file hasil ekstraksi rusak. Selalu Follow Stream / aktifkan reassembly.
- **Snaplen truncation.** Jika capture direkam dengan snaplen kecil (`caplen < len`), byte hilang dan **Export Objects** gagal diam-diam — cek dulu lewat `capinfos`.
- **TCP checksum errors palsu.** Banyak paket bertanda *checksum error* hampir selalu akibat **checksum offload** NIC pada mesin perekam, **bukan** tanda serangan — matikan validasi checksum agar tidak salah baca.
- **Tidak mendekompresi `Content-Encoding: gzip`/chunked.** String flag sering tersembunyi di response terkompresi; pastikan dissector men-dekode body.
- **Salah indeks `tcp.stream` pada PCAPNG multi-interface** — penomoran stream bisa membingungkan; perhatikan *interface id* tiap paket.
- **Menebak protokol dari port.** Layanan di port tak lazim akan salah-parse; gunakan **Decode As** untuk memaksa dissector yang benar.

## Mini-Lab

**Skenario:** Diberikan `case02.pcapng` (capture campuran HTTP + FTP). Attacker mengunduh sebuah tool lewat HTTP, lalu mengeksfiltrasi sebuah arsip via FTP. Flag tertanam di dalam file yang ditransfer.

**Prasyarat:** dari shell analis dengan `tshark`/`capinfos` terpasang dan Wireshark tersedia; file `case02.pcapng` (disediakan panitia) ada di direktori kerja. Akuisisi tidak perlu.

1. **Lakukan:** `capinfos case02.pcapng` → catat link-type, jumlah paket, dan apakah ada truncation (`caplen < len`).
2. **Lakukan:** buka file di Wireshark (**File > Open > `case02.pcapng`**) lalu klik **Statistics > Protocol Hierarchy** (atau jalankan `tshark -r case02.pcapng -q -z io,phs`) → identifikasi protokol pembawa data (terlihat HTTP **dan** FTP/FTP-DATA).
3. **Lakukan:** ekstrak unduhan HTTP via `tshark -r case02.pcapng --export-objects http,./loot` (atau **File > Export Objects > HTTP > Save All**). Untuk arsip FTP: di Wireshark ketik display filter `ftp-data` lalu Enter → klik kanan paket FTP-DATA → **Follow > TCP Stream** → set **Show data as** ke *Raw* → **Save as...** `exfil.bin` → angkat file yang ditransfer.
4. **Dapatkan:** jalankan `strings exfil.bin ./loot/*` / decode (atau carve dengan `binwalk -e exfil.bin`) untuk memperoleh **`flag{...}`**, lalu susun timeline koneksi→transfer→flag sebagai POC (Judgement).

## Referensi & Latihan

- **Wireshark User's Guide** & **Display Filter Reference** (`wireshark.org/docs`) — rujukan kanonik filter dan fitur Follow Stream/Export Objects.
- **PCAP/PCAPNG spec** — draft IETF *opsawg pcapng* dan dokumentasi **libpcap** untuk struktur file.
- **NetworkMiner** & **Zeek** documentation — ekstraksi konten dan log triase.
- **malware-traffic-analysis.net** (Brad Duncan) — latihan PCAP serangan nyata dengan kunci jawaban.
- **CyberDefenders** & **BlueTeam Labs Online (BTLO)** — challenge blue-team berbasis pcap nyata.
- **HackTheBox Sherlocks** — investigasi DFIR termasuk analisis trafik.
- **SANS** — **FOR572** (Advanced Network Forensics) & **SEC503** poster/cheat sheet untuk referensi cepat saat lomba.

---

> **Catatan etika.** Teknik capture, dekripsi, dan ekstraksi di atas hanya untuk **lab pribadi, sistem yang Anda miliki, atau lingkungan CTF/penilaian resmi dengan izin eksplisit**. Menyadap atau menganalisis lalu lintas jaringan pihak lain tanpa otorisasi melanggar hukum dan etika. Gunakan pengetahuan ini untuk **bertahan dan memahami**, bukan menyerang.
