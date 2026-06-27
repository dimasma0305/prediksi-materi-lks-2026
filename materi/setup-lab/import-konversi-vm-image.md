# Import & Konversi VM Image ke VMware Workstation

> Cara memakai **image VM / disk yang sudah jadi** di VMware Workstation untuk lab LKSN — termasuk **install `qemu-img`** dan konversi **`.vhdx`/`.vhd`/`.qcow2` → `.vmdk`**. Berguna saat kamu dapat VM siap-pakai (mis. **VM Module A1 WSA 2025** di [latihan-wsa-2025](../latihan-wsa-2025/README.md), image Rocky/AlmaLinux dari OSBoxes, atau VM rentan dari VulnHub) dan tak mau install dari ISO.

---

## 1. Kenali jenis file → cara cepat

| Ekstensi | Artinya | Cara |
|---|---|---|
| `.ova` / `.ovf` (+`.vmdk`,`.mf`) | Paket VM lengkap | **Import langsung** → §2A |
| `.vmdk` (sendiri) | Disk VMware | **Pasang ke VM baru** → §2B |
| `.vhdx` / `.vhd` | Disk **Hyper-V** | **Konversi → `.vmdk`** → §3 |
| `.qcow2` | Disk **QEMU/KVM** | **Konversi → `.vmdk`** → §3 |
| `.img` / `.raw` / `.dd` | Disk mentah | **Konversi → `.vmdk`** → §3 |

> VMware Workstation **tidak** bisa boot langsung dari `.vhdx`/`.qcow2`/`.img` — wajib dikonversi ke `.vmdk` dulu.

---

## 2. Import langsung (tanpa konversi)

### 2A. Paket OVF/OVA
1. **File → Open** → pilih file **`.ovf`** atau **`.ova`** (untuk OVF, taruh `.ovf`+`.mf`+`.vmdk` di **satu folder**).
2. Beri nama & lokasi → **Import**.
3. Bila muncul *"failed to import / did not pass OVF specification"* → klik **Retry** (Workstation melonggarkan validasi; hampir selalu berhasil untuk OVF hasil export ESXi).

### 2B. Hanya file `.vmdk`
1. **File → New Virtual Machine → Custom** → **"I will install the OS later"** → set Guest OS yang sesuai.
2. Di langkah **Select a Disk** → **"Use an existing virtual disk"** → **Browse** ke `.vmdk`-mu.
3. Bila ditanya konversi format → pilih **Keep Existing Format**. Finish → power on.

---

## 3. Konversi `.vhdx`/`.vhd`/`.qcow2`/`.img` → `.vmdk`

### 3.1 Install `qemu-img`

`qemu-img` adalah bagian dari **QEMU** — install QEMU, otomatis dapat `qemu-img`.

**Windows** (pilih salah satu):

```powershell
winget install --id=SoftwareFreedomConservancy.QEMU   # termudah (Win10/11)
choco install qemu                                     # Chocolatey
scoop install qemu                                     # Scoop
```
- Atau installer manual: **https://qemu.weilnetz.de/w64/** → `qemu-w64-setup-xxxx.exe`.
- ⚠️ QEMU terpasang di **`C:\Program Files\qemu`** dan `qemu-img` **sering belum masuk PATH**. Solusi: tambahkan folder itu ke **PATH** (Settings → *Edit environment variables* → Path → New), **atau** jalankan langsung: `cd "C:\Program Files\qemu"` lalu `.\qemu-img.exe ...`.

**Linux / macOS:**

| OS | Perintah |
|---|---|
| Ubuntu/Debian/Kali | `sudo apt install qemu-utils` |
| Fedora/RHEL/Rocky/Alma | `sudo dnf install qemu-img` |
| Arch | `sudo pacman -S qemu-img` |
| macOS (Homebrew) | `brew install qemu` |

**Cek berhasil:**
```bash
qemu-img --version
```

### 3.2 Perintah konversi

```bash
# VHDX (Hyper-V) -> VMDK
qemu-img convert -p -f vhdx -O vmdk source.vhdx output.vmdk

# VHD -> VMDK
qemu-img convert -p -f vpc  -O vmdk source.vhd  output.vmdk

# qcow2 (QEMU/KVM) -> VMDK
qemu-img convert -p -f qcow2 -O vmdk source.qcow2 output.vmdk

# raw/img -> VMDK
qemu-img convert -p -f raw  -O vmdk disk.img    output.vmdk
```
- `-p` = progress bar.
- Bila VMware menolak hasilnya, ulangi dengan subformat eksplisit: tambahkan `-o subformat=monolithicSparse`.

### 3.3 Alternatif tanpa qemu-img
- **StarWind V2V Converter** (GUI, gratis, anti-PATH): https://www.starwindsoftware.com/v2v-converter → pilih sumber → output **"VMware Workstation/ESX VMDK (growable)"**.
- **VirtualBox** (kalau sudah terpasang): `VBoxManage clonemedium disk source.vhdx output.vmdk --format VMDK`.

---

## 4. Pasang disk hasil konversi ke VM

1. **File → New VM → Custom** → **"I will install the OS later"** → pilih Guest OS yang sesuai (Windows Server / Linux).
2. ⚠️ **Firmware = UEFI** bila disk asalnya **Hyper-V Gen 2** (umum untuk `.vhdx`) — boot UEFI/GPT; kalau diset BIOS **tidak akan boot**.
3. Langkah disk → **"Use an existing virtual disk"** → pilih `output.vmdk` → **Keep Existing Format** → Finish.
4. **Network → Host-only / LAN Segment** untuk lab terisolasi. Ambil **Snapshot** sebelum hardening.

---

## 5. Troubleshooting boot

| Gejala | Penyebab umum | Solusi |
|---|---|---|
| Layar hitam / *No bootable device* | Firmware salah | Ganti **BIOS ↔ UEFI** (VHDX Gen 2 = UEFI) |
| *INACCESSIBLE_BOOT_DEVICE* (Windows) | Driver storage beda | Ganti tipe controller disk: **NVMe / SATA** (Hyper-V Gen 2 pakai SCSI) |
| VMware tolak `.vmdk` | Subformat tak cocok | Konversi ulang `-o subformat=monolithicSparse` atau pakai StarWind |
| Resolusi/mouse kaku | VMware Tools belum ada | **VM → Install VMware Tools** |

---

## 6. Di mana mengunduh image VM

- **VM resmi WSA 2025 (Module A1)** → [latihan-wsa-2025](../latihan-wsa-2025/README.md) (folder Google Drive: `.ovf`+`.vmdk`).
- **Windows Server / Win11 (eval ISO/VHD)**, **Rocky/AlmaLinux/Ubuntu/Kali**, **pfSense/OPNsense** → [README setup-lab §1–§3](README.md).
- **Linux siap-import (VMDK)** → **OSBoxes**: https://www.osboxes.org (Rocky/AlmaLinux/Ubuntu).
- **VM rentan untuk Boot2Root** → **VulnHub**: https://www.vulnhub.com (`.ova`/`.vmdk`).

> **Etika:** jalankan image pihak ketiga **hanya di jaringan lab terisolasi** (host-only/internal) dan verifikasi sumbernya.
