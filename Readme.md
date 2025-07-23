# 🛰️ Nascar — Advanced WAN/LAN Network Scanner

**Nascar** is a lightweight, fast, and intelligent network scanner written in Python.  
It detects live hosts on both **LAN (via ARP)** and **WAN (via ICMP)**, with optional **lateral movement port scanning**, OS fingerprinting via TTL, and even **domain resolution** support.

> ⚡ Simple syntax. Fast results. Smart scanning.

---

## 🚀 Features

- ✅ Scans LAN using **ARP** and WAN using **ICMP**
- ✅ Detects host **OS type** using TTL values
- 🌐 Supports **CIDR, IP, and domain names** as input
- 🔁 **Multi-threaded** scanning for fast execution
- 🔍 Optional **common port scanning** for lateral movement
- 🧠 Uses Scapy, standard Python libs (no bloat)
- 🧰 Modular design for extension

---

## 📦 Installation

### 🔹 With `setup.sh` (Linux/macOS)

```bash
chmod +x setup.sh
./setup.sh
```

### 🔹 Manually (Windows or virtualenv users)

```bash
pip install -r requirements.txt
```

> Make sure `scapy` is installed and you run the script with appropriate privileges.

---

## ⚙️ Usage

```bash
python main.py --network <target> [options]
```

### 🔧 Arguments

| Flag                     | Description |
|--------------------------|-------------|
| `-n`, `--network`        | Required. Target IP, CIDR, or domain |
| `-t`, `--threads`        | Number of threads (default: 10) |
| `-v`, `--verbose`        | Enable verbose output |
| `-s`, `--silent`         | Silent mode (minimal output) |
| `-lm`, `--lateral`       | Enable lateral movement port scan |

---

## 🧪 Example Usage

### 🔹 Scan local subnet
```bash
python main.py -n 192.168.1.0/24 -t 30 -v
```

### 🔹 Scan a domain
```bash
python main.py -n example.com
```

### 🔹 Scan external IP range + ports
```bash
python main.py -n 10.10.10.0/24 -lm -t 20
```

---

##  Output

Scanned hosts are printed in a table like:

```
Scan complete. Alive hosts:
IP Address       MAC Address        Hostname             OS           Open Ports
-------------------------------------------------------------------------------------
192.168.1.1      00:11:22:33:44:55  router.local         Linux/Unix   80,443
192.168.1.5      aa:bb:cc:dd:ee:ff  desktop.local        Windows      3389
```

---

##  OS Fingerprinting

Uses simple TTL-based fingerprinting:
- TTL ≥ 120 → Windows
- TTL ≥ 60  → Linux/Unix
- TTL <  60 → Unknown/Filtered

---

## Disclaimer

This tool is provided for:
- Educational purposes
- Internal testing in authorized environments

> Do not scan networks you do not own or have permission to audit.

---

##  Author

**err0rgod**  
> _"If it's on the network, it’s on the radar."_
