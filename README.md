<img width="2172" height="724" alt="ChatGPT Image Aug 17, 2026, 01_47_52 PM" src="https://github.com/user-attachments/assets/6064c8db-b803-411c-b6de-74911b9a5670" />


<div align="center">
# M I R A G E | MITM Interception, Routing & Analytical Graph Engine

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-Web%20UI-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![License](https://img.shields.io/badge/License-MIT-red.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Tested%20On-Android%2013%20%7C%20Win%2011%20%7C%20Linux-darkgreen)]()

**A powerful, stealth-first Man-in-the-Middle (MITM) framework with a built-in Wireshark-style packet inspector.**

*Invisible to the victim. Zero internet drops. Pure interceptive power.*
</div>

---

## ⚠️ Disclaimer

**MIRAGE** is designed for authorized security auditing, educational purposes, and network analysis.
Attacking networks without explicit permission from the owner is illegal. The developer assumes no liability and is not responsible for any misuse or damage caused by this program.

---

## 🚀 Overview

Most MITM tools disrupt the victim's connection, triggering OS-level warnings (like the infamous Android `!` icon). **MIRAGE** is built differently.

By implementing a **Transparent Bridge Architecture** (using kernel-level IP forwarding and custom `iptables`/`rp_filter` tuning), MIRAGE slips into the traffic stream completely unnoticed. It doesn't NAT the traffic; it silently passes it through while analyzing every byte with zero latency.

Tested extensively and confirmed **invisible** on:
- 📱 **Android 13** (No captive portal triggers, no connection drops)
- 💻 **Windows 11** (No network warnings)
- 🐧 **Linux** (Seamless routing)

## ✨ Features

### 🕵️ 1. Stealth-First Interception
- **Transparent Bridge Mode:** Bypasses OS security checks without altering packet headers.
- **ARP Spoofing Engine:** High-speed, dual-direction spoofing that keeps the victim's ARP cache poisoned without flooding the network.

### 📊 2. Live Analytical Dashboard
- **Real-time Traffic Graph:** Smooth, 60FPS Canvas-based graph showing Download/Upload speeds in KB/s.
- **Target History:** Live extraction of visited URLs (DNS queries) for quick profiling.

### 🔬 3. Integrated Packet Inspector
- **Wireshark-Style Analysis:** Click on any packet in the live stream to open a detailed modal.
- **Deep Dive:** View Source/Destination IPs, Ports, TCP Flags, and Payloads in both **ASCII** and **HEX** formats.
- **Smart Filtering:** Instantly filter packets by protocol (TCP, UDP, ICMP, URL) or search through payloads with a live search bar.

### 🧠 4. Credential Harvesting
- Automatically extracts plaintext HTTP credentials (usernames, passwords) from POST requests.
- Saves all captured credentials to an isolated file inside the `logs/` directory.

---

## 📸 Screenshots

<img width="1920" height="1080" alt="Screenshot_2026-08-12_21_13_27" src="https://github.com/user-attachments/assets/11437684-7ed5-4512-bca0-483ca656eedd" />
<img width="1920" height="1080" alt="Screenshot_2026-08-12_21_00_15" src="https://github.com/user-attachments/assets/76f151f0-3928-49b2-b94a-4066c4471519" />
<img width="1920" height="1080" alt="Screenshot_2026-08-12_21_13_58" src="https://github.com/user-attachments/assets/68f758ab-5a10-4300-941f-4b0de4fb8287" />


---

## 🛠️ Architecture

MIRAGE uses a decoupled architecture (FastAPI Backend + HTML/JS Frontend). It relies on `tcpdump` for kernel-level PCAP capture (zero latency) and `Scapy` for real-time payload analysis.

```text
mirage/
├── main.py # FastAPI Web Server & WebSocket Manager
├── requirements.txt
├── static/
│   └── index.html # Cyberpunk Web UI (Tailwind CSS + Vanilla JS)
└── core/ # Backend Engine
    ├── network.py # Nmap Network Scanner logic
    ├── mitm.py # Stealth ARP Spoofer
    └── sniffer.py # Packet Analyzer & Traffic Calculator
```

---

## 📦 Installation & Requirements

### Prerequisites
- Linux environment (Kali, Parrot, or Arch recommended)
- Wireless/Wired card supporting **Promiscuous Mode**
- Root privileges

### System Dependencies
You must have the underlying CLI tools installed:

```bash
sudo apt update
sudo apt install nmap tcpdump iptables iproute2
```

### Python Setup

```bash
git clone https://github.com/YOUR_GITHUB_USERNAME/mirage.git
cd mirage
pip install -r requirements.txt
```

---

## 💻 Usage

Run MIRAGE with root privileges:

```bash
sudo python3 main.py
```

Once running, open your browser and navigate to:
`http://localhost:9000`

1. Select your network interface.
2. Click **START SCAN** to discover hosts on the LAN.
3. Click **INTERCEPT** on your target.
4. Watch the traffic graph move and analyze packets in real-time!

---

## What's New in v2.0? (Major Update)
### 🔒 WebSocket Authentication: Server connection now requires a security token to prevent unauthorized access within the local network.

### 🛡️ Crash & Race Condition Fix:
Implemented asyncio.Lock to eliminate concurrent command interference, achieving 100% server stability.

### ⚡ Zero UI Freezing:
Stopping operations (Scan/MITM) is now handled in separate threads, ensuring the Web UI remains completely responsive at all times.

### 🧵 Thread Safety Improvements:
Replaced unsafe boolean flags with threading.Event for immediate and secure termination of network engines.

### 🧹 Automatic Network Cleanup:
If the WebSocket connection drops unexpectedly, the tool automatically stops all operations and restores network settings (iptables/sysctl).

### 🐛 Transparent Error Handling:
Removed silent except: blocks. All exceptions are now clearly logged in the dashboard for easier debugging.

### 🚀 Processing Speed Boost:
Removed unnecessary terminal logging for individual packets, significantly reducing CPU usage and improving performance under heavy traffic.

### 📊 Accurate Traffic Calculation:
Added threading.Lock to byte counters, ensuring 100% precise RX/TX speed calculations without data races.

### 🐍 Modern FastAPI Standards:
Migrated from the deprecated @app.on_event to the modern lifespan context manager for future-proof compatibility.

---

## 🤝 Acknowledgements

I want to be completely transparent about the development process of MIRAGE. A significant portion of this tool's architecture, backend Python logic, and the cyberpunk-themed frontend were designed and written with the assistance of an AI language model. It acted as an incredible co-pilot, helping to debug complex threading issues, optimize the transparent bridge routing, and design the UI.

Thank you to the AI for making this project come to life so rapidly.

---

<div align="center">
<sub>Stay invisible. Happy Hacking.</sub>
</div>
