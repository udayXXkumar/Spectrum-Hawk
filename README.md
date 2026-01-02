# Spectrum Hawk 🦅

**Advanced WiFi Network & Device Enumeration Tool**

Spectrum Hawk is a powerful Python-based wireless network scanner designed for security professionals, network administrators, and ethical hackers. It identifies WiFi networks, finds connected devices, and provides names of the connected devices of each network without authetication/connecting to network. It is useful when locating specific IoT/CCTV cameras from multiple wifi's so we can focus on attacking that specific wifi instead of wasting time on recon, scanning and attacking other wifi's

## Use Cases
  - **Security Auditing** – Identify all devices on a network
  - **IoT Device Discovery** – Find CCTV cameras, smart devices
  - **Network Mapping** – Understand network topology
  - **Targeted Attacks** – Focus on specific networks/devices instead of wasting time by attacking all networks
## 📋 Requirements
  - **Wi-Fi Adapter** - Use Wi-Fi adapter for scanning long range and better results
<p align="center">
  <a href="https://www.amazon.in/TP-Link-Wireless-Network-Supports-T2U/dp/B07P681N66?source=ps-sl-shoppingads-lpcontext&ref_=fplfs&smid=AJ6SIZC8YQDZX&th=1">
    <img src="https://m.media-amazon.com/images/I/51ii8SWvsPL._SL1500_.jpg" width="300">
  </a>
  <a href="https://www.amazon.in/Long-Range-Dual-Band-Wireless-External-Antennas/dp/B00VEEBOPG?source=ps-sl-shoppingads-lpcontext&ref_=fplfs&psc=1&smid=A7TY3KN2D336C">
    <img src="https://m.media-amazon.com/images/I/41Qo0EGG4TL._SL1000_.jpg" width="300">
  </a>
</p>

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
git clone https://github.com/udayXXkumar/Spectrum-Hawk.git
cd spectrum-hawk
```

### Create Virtual Environment
```bash
python3 -m venv shawk-venv
source shawk-venv/bin/activate
```

### Install Python Dependencies
```bash
pip install -r requirements.txt
```

## ▶️ Usage

Run as root: Make sure to use virtual environment(venv) and SuperUserDo(sudo)
```bash
 sudo ./shawk-venv/bin/python spectrum_hawk.py
```
---

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
---

## 🦅 Author

**Spectrum Hawk**  
Advanced WiFi Enumeration & Device Fingerprinting Tool
Built for red teamers, blue teamers, and security researchers
