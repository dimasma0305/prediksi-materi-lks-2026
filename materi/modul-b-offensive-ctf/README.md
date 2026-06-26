# Modul B — Offensive / Red-Team Based CTF

> Indeks dan peta navigasi untuk **Modul B** pada persiapan **LKS (Lomba Kompetensi Siswa) bidang Cyber Security — LKSN 2026**. Modul ini adalah sesi **ofensif / red-team** yang dikerjakan pada **Hari Kedua (H2)** selama **5 jam**. Tujuannya: melatih kemampuan **menyerang** sistem secara terkontrol — memecahkan soal eksploitasi pada level **web, kriptografi, dan binary**, lalu melakukan **penyusupan server** Windows/Linux hingga mencapai **akses level tertinggi (Administrator/root)**.
>
> Berbeda dari **Modul A** (hardening, sudut pandang blue team) dan **Modul C** (defensif/forensik), Modul B adalah satu-satunya modul di mana peserta **menyerang**. Semua materi di sini ditujukan **hanya** untuk lab pribadi, lingkungan kompetisi, atau sistem dengan **izin tertulis eksplisit**.

---

## Tujuan Modul

Setelah menuntaskan modul ini, peserta mampu:

1. **Menyelesaikan objektif soal eksploitasi** bertipe **web, kriptografi, dan binary** dalam format **Jeopardy CTF** — menemukan kerentanan, menulis exploit/skrip, dan **menangkap flag**.
2. **Melakukan red teaming end-to-end** pada soal **Boot2Root**: enumerasi layanan → eksploitasi → **privilege escalation** (vertikal & horizontal) hingga menguasai akun `Administrator`/`root`.
3. **Mendokumentasikan jalur eksploitasi** dalam bentuk **writeup / POC** yang jelas dan dapat diverifikasi juri — bagian yang sering diabaikan pemain CTF, padahal **bernilai poin besar** (lihat [Relevansi ke Penilaian](#relevansi-ke-penilaian-lomba)).

Modul B mencakup **empat kategori** dengan total **56 soal-acuan/topik** sesuai kisi-kisi LKSN 2026:

| Kategori | Jumlah topik | Lingkungan | README kategori |
|---|---:|---|---|
| **Cryptography** | 7 | Jeopardy (CTFd) | [`cryptography/README.md`](cryptography/README.md) |
| **Web Exploitation** | 37 | Jeopardy (CTFd) | [`web-exploitation/README.md`](web-exploitation/README.md) |
| **Binary Exploitation** | 9 | Jeopardy (CTFd) | [`binary-exploitation/README.md`](binary-exploitation/README.md) |
| **Boot2Root** | 3 | VM lokal / VPN ke remote VM | [`boot2root/README.md`](boot2root/README.md) |

> Angka di kolom **Jumlah topik** adalah banyaknya butir keterampilan pada kisi-kisi per kategori, bukan jumlah soal yang akan muncul saat lomba. Jumlah soal aktual ditentukan panitia dan poin tiap soal **dinamis** (lihat catatan hari-H).

---

## Ringkasan Tiap Kategori

### 1. Cryptography — 7 topik · Jeopardy
Serangan terhadap primitif & protokol kriptografi, umumnya diselesaikan dengan **skrip** (Python + `pycryptodome`/`sympy`/SageMath). Cakupan kisi-kisi:

- **Classical ciphers** — Vigenere, Caesar, Atbash, Affine, Substitution, XOR
- **Attack on RSA** — Håstad broadcast, common modulus, twin prime, multiprime
- **Attack on PRNG** — Mersenne Twister, LCG, LFSR
- **Attack on AES** — kelemahan mode ECB/CBC/OFB/CFB/CTR/GCM (mis. byte-at-a-time ECB, bit-flipping CBC, nonce reuse)
- **Attack on ECC** — Smart's attack (kurva anomali)
- **Attack on DSA** — serangan ECDSA & tanda tangan RSA (mis. nonce reuse `k`)
- **Hashing** — length extension attack

Detail teknik, tooling, dan pola soal: **[`cryptography/README.md`](cryptography/README.md)**.

### 2. Web Exploitation — 37 topik · Jeopardy
Kategori **terbesar** dan dengan **yield poin tertinggi** karena jumlah soalnya banyak. Rentang sangat luas, dari injeksi klasik hingga kelas serangan modern:

- **Injeksi & deserialisasi:** SQL/NoSQL/LDAP/XPATH/XSLT/XXE Injection, SSTI, SSI, Command Injection, Insecure Deserialization, LaTeX Injection
- **Logika & autentikasi:** Account Takeover, Business Logic Errors, OAuth Misconfiguration, JWT, SAML Injection, Type Juggling, Race Condition, IDOR, CSRF
- **Request & protokol:** SSRF, HTTP Parameter Pollution, Request Smuggling, Web Cache Deception, Web Sockets, GraphQL Injection, Java RMI
- **Lain-lain:** XSS, Prototype Pollution, Dependency Confusion, Directory Traversal & File Inclusion, Upload Insecure Files, Insecure Randomness, Insecure Management Interface, CVE Exploits, **Prompt Injection**, **OWASP API Security Top 10**

Detail per kelas serangan, payload, dan tooling (Burp Suite, dll.): **[`web-exploitation/README.md`](web-exploitation/README.md)**.

### 3. Binary Exploitation — 9 topik · Jeopardy
Eksploitasi memori pada binary (umumnya Linux ELF), diselesaikan dengan `pwntools` + analisis (Ghidra/IDA/GDB-pwndbg). Cakupan:

- **Stack:** Buffer overflow, Format String, ROP chain (ret2win, ret2libc, dst.)
- **Integer & tipe:** Integer overflow/underflow, Type Confusion, Uninitialized Memory Use
- **Shellcode** dan **bypass proteksi** — PIE, Stack Canary, NX, RELRO
- **Heap:** Heap overflow, Use-After-Free (UAF), Double Free

Detail mitigasi, primitif, dan template exploit: **[`binary-exploitation/README.md`](binary-exploitation/README.md)**.

### 4. Boot2Root — 3 topik · Lingkungan tersendiri
Bukan Jeopardy. Peserta menyerang **VM utuh** (di-*import* ke laptop dari cloud storage **dan/atau** diakses lewat **VPN privat ke remote cloud VM**) dan menembusnya sampai akar:

- **Service Level Enumeration** — pemetaan layanan & permukaan serang
- **Service Level Exploitation** — menembus layanan rentan untuk pijakan awal (foothold)
- **Privilege Escalation vertikal & horizontal** — abuse konfigurasi / **Living-Off-The-Land** hingga `Administrator`/`root`

Penilaian Boot2Root menekankan **audit perlakuan penyerangan** (urutan langkah) + **dokumentasi writeup**, bukan sekadar flag. Detail metodologi red teaming: **[`boot2root/README.md`](boot2root/README.md)**.

---

## Relevansi ke Penilaian Lomba

### Bobot & komposisi nilai

Dokumen LKSN 2026 menyebut beberapa angka pada konteks berbeda — semuanya dicantumkan agar tidak membingungkan:

| Acuan | Nilai untuk Modul B | Sumber |
|---|---|---|
| **Bobot kompetensi (kolom "LKS 2026")** | **20%** | Tabel Perbandingan Bobot Kompetensi (WSC/LKS) |
| **Bobot modul pada jadwal penilaian** | **25%** (H2; A 25% · B 25% · C 50%) | Deskripsi Teknis §3.6 & tabel Modul Lomba |
| **Komposisi poin modul** | **40 poin = 10 Judgement + 30 Measurement** | Deskripsi Teknis §3.2.3 |

Intinya: **30 dari 40 poin (Measurement)** berasal dari **flag yang benar**, dan **10 poin (Judgement)** dari **kualitas writeup/POC**.

### Yang menentukan poin Anda

1. **Measurement = flag & objektif tercapai.** Biner: 1 bila flag/objektif sesuai, 0 bila tidak. Untuk soal seperti Web Exploitation, contoh aspek terukur adalah *Client-Side Exploit Success*, *Server-Side Exploit Success*; untuk Binary, *Variable Successfully Overflowed* dan *Gain flag.txt*. **Submit flag ke portal CTFd** untuk soal Jeopardy.
2. **Judgement = POC/writeup, dinilai skala 0–3.** Ini **seperempat** nilai modul dan justru bagian yang paling sering diabaikan. Rubrik POC:
   - **0** — tidak ada POC
   - **1** — POC ada tapi kurang jelas, **tanpa screenshot**
   - **2** — POC dengan screenshot tapi bukti masih kurang
   - **3** — POC jelas, ringkas, langkah lengkap
   **Tangkap screenshot dan catat jalur exploit sambil mengerjakan**, bukan setelah selesai — flag yang benar tanpa POC yang rapi membuang sampai 25% potensi nilai modul.
3. **Dua lingkungan, dua cara nilai.** Crypto/Web/Binary = **Jeopardy di CTFd** (kredensial dikirim ke email ketua tim; unduh soal, kirim flag). **Boot2Root** = lingkungan tersendiri (VM lokal atau VPN ke remote VM) yang dinilai dari **audit langkah penyerangan + writeup**.
4. **Poin dinamis.** Semakin banyak tim menyelesaikan suatu soal, **poinnya turun**; poin rata bagi semua tim yang menyelesaikan. Soal mudah yang diselesaikan lebih awal bernilai lebih besar.
5. **Larangan AI interaktif.** Peserta **dilarang** memakai AI interaktif apa pun selama lomba (ChatGPT, Claude, MCP, Codex, dan sejenisnya). Latih keterampilan sampai **otomatis dan manual** — siapkan template skrip/exploit sendiri sebelum lomba.

---

## Saran Urutan Belajar & Kerja

Materi disusun agar dibaca dari yang **paling mandiri** ke yang **menggabungkan semua keterampilan** (Boot2Root sebagai capstone).

1. **Cryptography** — paling *self-contained* dan paling banyak berbasis skrip. Cocok sebagai pemanasan: bangun pustaka skrip serangan RSA/PRNG/AES Anda sendiri.
2. **Web Exploitation** — **prioritaskan** karena jumlah soal terbanyak (yield poin tertinggi). Kuasai alur kerja Burp Suite dan kelas serangan injeksi/logika.
3. **Binary Exploitation** — paling menuntut waktu per soal; kuasai pola `pwntools` + bypass proteksi (Canary/NX/PIE/RELRO) dan template ROP/ret2libc.
4. **Boot2Root** — terakhir, karena memerlukan gabungan enumerasi + eksploitasi layanan + privilege escalation. Latih metodologi end-to-end sampai akses `Administrator`/`root`.

> **Catatan hari-H (strategi):** karena poin **dinamis**, **kumpulkan kemenangan cepat lebih dulu** — sapu soal yang Anda yakin bisa diselesaikan, baru masuk ke soal sulit. **Hindari *rabbit hole*:** beri batas waktu per soal, dan jika buntu, pindah lalu kembali. **Tulis POC sambil jalan** agar 10 poin Judgement tidak hangus saat waktu habis.

---

## Cara Pakai & Etika

- Materi dan tooling ofensif di modul ini **hanya** untuk **lingkungan lomba, lab pribadi, atau sistem dengan izin tertulis**. Jangan menyerang sistem yang bukan milik Anda atau di luar scope yang ditentukan panitia.
- **Snapshot** VM lab sebelum bereksperimen; soal Boot2Root yang di-*import* lokal aman untuk diulang dari snapshot.
- Patuhi **aturan lomba**: kerjakan hanya target dalam scope, lewat akses (CTFd / VPN) yang disediakan. Jangan menyerang infrastruktur peserta lain atau panitia.
- Ingat **larangan AI interaktif** — pelanggaran berisiko diskualifikasi.

---

## Struktur Folder

```
modul-b-offensive-ctf/
├── README.md                  ← berkas ini (indeks modul)
├── cryptography/              → Jeopardy: serangan kripto (7 topik)
├── web-exploitation/          → Jeopardy: eksploitasi web (37 topik)
├── binary-exploitation/       → Jeopardy: eksploitasi binary (9 topik)
└── boot2root/                 → Red teaming VM end-to-end (3 topik)
```

Buka README di tiap subfolder untuk materi mendalam, tooling, dan pola soal per kategori.
