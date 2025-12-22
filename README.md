# Spectrum Hawk 🦅

**Advanced WiFi Network & Device Enumeration Tool**

Spectrum Hawk is a powerful Python-based wireless network scanner designed for security professionals, network administrators, and ethical hackers. It identifies WiFi networks, enumerates connected devices, and provides detailed device fingerprinting—perfect for locating specific IoT/CCTV cameras and understanding network topology.

## Use Cases
  - **Security Auditing** – Identify all devices on a network
  - **IoT Device Discovery** – Find CCTV cameras, smart devices
  - **Network Mapping** – Understand network topology
  - **Targeted Attacks** – Focus on specific networks/devices instead of wasting time by attacking all networks
## 📋 Requirements

### System
- Linux (Kali Linux recommended)
- Wireless adapter supporting **monitor mode**
- Root privileges

### Tools
```bash
sudo apt update
sudo apt install -y aircrack-ng iw net-tools
```

---

## 🚀 Installation

### Clone Repository
```bash
git clone https://github.com/yourusername/spectrum-hawk.git
cd spectrum-hawk
```

### Create Virtual Environment
```bash
python3 -m venv wifi-env
source wifi-env/bin/activate
```

### Install Python Dependencies
```bash
pip install -r requirements.txt
```

### requirements.txt
```txt
mac-vendor-lookup
rich
jinja2
requests
```

## ▶️ Usage

Run as root:
```bash
sudo python3 spectrum_hawk.py
```

## 🎯 Key Features

- 📡 **Three Scanning Modes**
  - **Quick Scan** – High signal networks only
  - **Normal Scan** – Balanced coverage
  - **Intense Scan** – Full spectrum analysis

- 🔍 **Smart MAC Vendor Lookup**
  - Offline OUI database (fast)
  - Optional online lookup (macaddress.io)
  - Automatic fallback handling

- 📊 **Multi-Format Reports**
  - JSON (automation-friendly)
  - TXT (terminal readable)
  - HTML (visual report with auto-open)

### Interactive Setup
- Select MAC lookup mode
- Choose scan intensity
- Pick wireless interface
- Monitor mode enabled automatically


## 📁 Output

All reports are saved to:
```bash
wifi_enum_output/
```

Formats:
- `.json`
- `.txt`
- `.html` (opens automatically)
---

## ⚠️ Legal Disclaimer

This tool is for **AUTHORIZED SECURITY TESTING ONLY**.

You must have explicit permission to scan any network.  
The author is not responsible for misuse.


## 🧪 Tested On
- Kali Linux
- Ubuntu 22.04
- Parrot OS


## 🤝 Contributing

Pull requests welcome:
- Vendor fingerprint additions
- UI improvements
- Performance tuning
- Export formats (PDF/CSV)


## ⭐ Support

If you find this project useful:
- ⭐ Star the repository
- 🐞 Report bugs
- 💡 Suggest features


## 🦅 Author

**Spectrum Hawk**  
Advanced WiFi Enumeration & Device Fingerprinting Tool
Built for red teamers, blue teamers, and security researchers
