<img width="100%" alt="MIRAGE Banner" src="[https://github.com/user-attachments/assets/e91d309f-12b6-4db4-a821-bd6d407dcd9b](https://github.com/user-attachments/assets/e91d309f-12b6-4db4-a821-bd6d407dcd9b)" />

<div align="center">

# M I R A G E

### MITM Interception, Routing & Analytical Graph Engine

<p>   <strong>A modular network security framework for authorized MITM testing, traffic analysis, and real-time packet inspection.</strong> </p>

<p>   <a href="[https://www.python.org/](https://www.python.org/)">     <img src="[https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)">   </a>   <a href="[https://fastapi.tiangolo.com/](https://fastapi.tiangolo.com/)">     <img src="[https://img.shields.io/badge/FastAPI-Web%20UI-009688?style=for-the-badge&logo=fastapi&logoColor=white](https://img.shields.io/badge/FastAPI-Web%20UI-009688?style=for-the-badge&logo=fastapi&logoColor=white)">   </a>   <a href="[https://scapy.net/](https://scapy.net/)">     <img src="[https://img.shields.io/badge/Scapy-Packet%20Analysis-111827?style=for-the-badge](https://img.shields.io/badge/Scapy-Packet%20Analysis-111827?style=for-the-badge)">   </a>   <a href="[https://nmap.org/](https://nmap.org/)">     <img src="[https://img.shields.io/badge/Nmap-Recon-4CAF50?style=for-the-badge](https://img.shields.io/badge/Nmap-Recon-4CAF50?style=for-the-badge)">   </a>   <a href="[https://www.tcpdump.org/](https://www.tcpdump.org/)">     <img src="[https://img.shields.io/badge/tcpdump-PCAP%20Capture-374151?style=for-the-badge](https://img.shields.io/badge/tcpdump-PCAP%20Capture-374151?style=for-the-badge)">   </a>   <a href="LICENSE">     <img src="[https://img.shields.io/badge/License-MIT-FF003C?style=for-the-badge](https://img.shields.io/badge/License-MIT-FF003C?style=for-the-badge)">   </a> </p>

<p>   <code>Recon → Target → Interception → Capture → Analysis → Recovery</code> </p>

</div>

---

## ⚠️ Disclaimer

**MIRAGE is intended exclusively for authorized security testing, laboratory environments, education, and network analysis.**

Only use MIRAGE on systems and networks you own or have explicit permission to test.

Unauthorized interception, traffic manipulation, credential collection, or monitoring may be illegal. The developer assumes no responsibility for misuse, unauthorized activity, data loss, service disruption, or damage resulting from this software.

---

# 🧠 Overview

MIRAGE is a modular **Man-in-the-Middle (MITM) security testing framework** built around a real-time web dashboard.

Instead of being a single-purpose ARP spoofing script, MIRAGE combines several components into one controlled workflow:

```text
Network Reconnaissance
        │
        ▼
Target Discovery
        │
        ▼
MITM Session
        │
        ├── ARP Interception
        ├── IP Forwarding
        ├── Traffic Capture
        └── Packet Analysis
                │
                ▼
          WebSocket Stream
                │
                ▼
        Real-Time Dashboard
                │
                ▼
        Session Cleanup
        & Network Restore
```

The project is designed around **explicit state ownership, transactional network changes, failure-aware cleanup, and real-time analysis**.

---

# ✨ Features

## 🕵️ MITM Interception

### Transparent forwarding

MIRAGE uses Linux IP forwarding and controlled firewall/sysctl configuration to allow intercepted traffic to continue through the host while traffic is analyzed.

The framework creates a **transaction-owned firewall scope** instead of flushing the host firewall configuration.

### ARP interception

The ARP engine performs bidirectional poisoning between:

```text
Target
  ↕
MIRAGE
  ↕
Gateway
```

The engine also attempts to restore the ARP state when the session ends.

---

## 🔎 Network Reconnaissance

MIRAGE integrates Nmap for LAN discovery.

The scanner provides:

* IPv4 address
* MAC address
* Vendor information
* Hostname
* Live host discovery

Nmap XML output is parsed directly rather than relying on fragile human-readable output parsing.

---

## 📡 Real-Time Packet Analysis

MIRAGE combines:

```text
tcpdump
   +
Scapy
```

for packet collection and live analysis.

The dashboard can display:

* Source IP
* Destination IP
* Source port
* Destination port
* Protocol
* TCP flags
* Packet length
* ASCII payload
* HEX payload

Packets are processed through a bounded queue and delivered to the frontend in batches to reduce WebSocket and browser overhead.

---

## 📊 Live Traffic Monitoring

The dashboard provides a real-time traffic graph showing:

```text
Download
Upload
```

with rolling traffic statistics calculated from observed packets.

Byte counters are protected using thread synchronization to avoid inconsistent statistics under concurrent packet processing.

---

## 🌐 Plaintext DNS Observation

MIRAGE can observe plaintext DNS queries visible on the monitored traffic path.

Example:

```text
example.com
api.example.com
cdn.example.net
```

Encrypted DNS mechanisms such as DoH and DoT are outside the visibility of a normal plaintext DNS packet monitor.

---

## 🔬 Packet Inspector

Every captured packet can be opened in the built-in inspector.

The interface provides:

```text
┌───────────────────────────────┐
│ PACKET INSPECTOR              │
├───────────────────────────────┤
│ Source                        │
│ Destination                   │
│ Protocol                      │
│ Ports                         │
│ TCP Flags                     │
│ Length                        │
├───────────────────────────────┤
│ Payload ASCII                 │
├───────────────────────────────┤
│ Payload HEX                   │
└───────────────────────────────┘
```

Packet filtering and search are available directly from the dashboard.

---

## 🔐 Plaintext Credential Detection

MIRAGE includes basic detection for credential-like fields visible inside plaintext HTTP POST traffic.

Detected data can be written to the session log directory for authorized lab analysis.

This capability is intentionally limited to traffic that is actually visible to the analyzer and does **not** bypass TLS encryption.

---

# 🏗️ Architecture

MIRAGE uses a decoupled backend/frontend architecture.

```text
                           MIRAGE
                              │
              ┌───────────────┴───────────────┐
              │                               │
        FastAPI Backend                 Web Dashboard
              │                               │
              └───────────────┬───────────────┘
                              │
                      MirageController
                              │
          ┌───────────────────┼───────────────────┐
          │                   │                   │
       Scanner              Sniffer            ARP Engine
          │                   │                   │
         Nmap              Scapy               Scapy
                              │
                      Packet Processing
                              │
                       Bounded Queue
                              │
                           Batching
                              │
                         WebSocket
                              │
                              ▼
                             UI
```

### Project structure

```text
MIRAGE/
├── main.py
├── requirements.txt
├── .env
│
├── core/
│   ├── mitm.py
│   ├── network.py
│   └── sniffer.py
│
├── static/
│   ├── index.html
│   └── tailwind.js
│
└── logs/
```

### Component responsibilities

| Component           | Responsibility                                                            |
| ------------------- | ------------------------------------------------------------------------- |
| `main.py`           | FastAPI server, controller, WebSocket lifecycle, network state management |
| `core/network.py`   | Nmap-based host discovery                                                 |
| `core/mitm.py`      | ARP interception and ARP restoration                                      |
| `core/sniffer.py`   | Packet capture, processing, traffic statistics, packet batching           |
| `static/index.html` | Real-time dashboard and packet inspector                                  |

---

# 🔒 Network State Management

One of the main engineering goals of MIRAGE is to avoid leaving the host in a modified network state after a failed or interrupted session.

Before modifying networking configuration, MIRAGE creates a session-specific snapshot containing relevant:

```text
iptables
sysctl values
```

The workflow is:

```text
Capture Snapshot
       │
       ▼
Mark Transaction Active
       │
       ▼
Apply Network Changes
       │
       ▼
Start Engines
       │
       ▼
MITM Session
       │
       ├──────────────┐
       │              │
      STOP         FAILURE
       │              │
       └──────┬───────┘
              ▼
       Restore Snapshot
              │
              ▼
       Remove MIRAGE State
              │
              ▼
             IDLE
```

The firewall configuration created by MIRAGE is transaction-owned and uses a unique chain name for each session.

---

# 🛡️ Reliability & Safety Engineering

MIRAGE is built with several defensive mechanisms:

### Transaction-aware network changes

Network configuration is only mutated after a valid snapshot has been captured.

### Fail-fast system commands

System-level operations validate command exit codes and surface failures rather than silently continuing.

### Failure-tolerant cleanup

Scanner, sniffer, ARP engine, firewall state, and temporary session resources are cleaned independently so a failure in one component does not automatically prevent cleanup of another.

### Controlled shutdown

Long-running subprocesses such as Nmap and tcpdump have bounded shutdown paths with escalation when graceful termination fails.

### Single-operator control

Only one authenticated WebSocket operator can control a MIRAGE instance at a time.

### Bounded packet buffering

Packet queues are bounded to prevent unlimited in-memory growth during high traffic conditions.

---

# 🔑 Configuration

MIRAGE supports an environment-based access token.

Create a `.env` file in the project root:

```env
MIRAGE_ACCESS_TOKEN=your-secret-token
```

Generate a strong token with:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

---

# 📦 Installation

## Requirements

Recommended environment:

* Linux
* Python 3.10+
* Root privileges
* Nmap
* tcpdump
* iptables
* iproute2
* Network interface capable of the required packet operations

Kali Linux, Parrot OS, Debian, Ubuntu, and Arch-based environments are suitable starting points.

### System dependencies

```bash
sudo apt update
sudo apt install nmap tcpdump iptables iproute2
```

### Clone

```bash
git clone https://github.com/itsBONSAW/MIRAGE.git
cd MIRAGE
```

### Python environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Install dependencies

```bash
pip install -r requirements.txt
```

If `.env` loading is handled by the application:

```bash
pip install python-dotenv
```

---

# 🚀 Usage

Start MIRAGE with the required privileges:

```bash
sudo python3 main.py
```

Then open:

```text
http://127.0.0.1:9000
```

For the initial authenticated browser session, provide the operator token through the interface/session mechanism configured by your deployment.

### Typical workflow

```text
1. Start MIRAGE
2. Select a network interface
3. Start reconnaissance
4. Review discovered hosts
5. Select an authorized test target
6. Start interception
7. Inspect live traffic
8. Stop the session
9. Verify network restoration
```

---

# 🧪 Recommended Lab Setup

For safe experimentation, use an isolated test environment such as:

```text
                  ┌──────────────┐
                  │ Test Router  │
                  └──────┬───────┘
                         │
              ┌──────────┴──────────┐
              │                     │
        MIRAGE Host             Test Device
        Linux/Kali             Android/Windows
```

Keep the environment isolated from networks and systems you do not own or have explicit authorization to test.

---

# 🆕 What's New in v2.0

## 🔐 WebSocket Authentication

Control traffic now requires an authenticated operator token.

---

## 🧠 Centralized Controller

Engine state has moved into a centralized `MirageController` rather than being owned independently by every WebSocket session.

This reduces lifecycle conflicts and makes cleanup deterministic.

---

## 🔒 Transactional Network State

Network configuration is now treated as a transaction:

```text
Snapshot
→ Apply
→ Run
→ Restore
```

Failures during initialization trigger rollback paths instead of leaving the host in an assumed default state.

---

## 🛡️ Transaction-Owned Firewall

MIRAGE no longer flushes the system firewall.

Instead, every session receives its own uniquely named firewall chain.

This isolates MIRAGE-managed rules from unrelated firewall configuration.

---

## 🧵 Concurrency Improvements

Critical control operations are serialized using asyncio synchronization primitives.

The application also uses thread synchronization for packet counters and packet buffering.

---

## ⚡ Improved Shutdown

Nmap, tcpdump, Scapy capture, and background worker threads now have explicit shutdown paths and bounded termination behavior.

---

## 📦 Packet Batching

Packets are queued and transmitted to the browser in batches instead of generating a WebSocket message for every packet.

This significantly reduces frontend message overhead during busy captures.

---

## 🧹 Unified Cleanup

Stopping a session, disconnecting the operator, changing interfaces, or shutting down the server all enter the same cleanup architecture.

The goal is to restore the host's previous network configuration rather than assuming default values.

---

## 🐛 Better Error Handling

Important system operations validate return codes and report failures instead of silently ignoring them.

---

# 🧭 Roadmap

The current release focuses on reliable MITM lifecycle management and live packet analysis.

Planned areas include:

```text
[ ] Automated regression tests
[ ] Fault-injection test suite
[ ] CI pipeline
[ ] More protocol-aware analyzers
[ ] Improved session/flow tracking
[ ] IPv6-aware network handling
[ ] Advanced BPF filtering
[ ] Better packet stream backpressure
[ ] Richer PCAP workflows
[ ] Extended observability
```

---

# 🧪 Testing Philosophy

A core design goal of MIRAGE is that failure should be safe and observable.

Important scenarios to test include:

```text
iptables-save failure
sysctl snapshot failure
firewall creation failure
sysctl mutation failure
tcpdump startup failure
Nmap failure
ARP engine failure
WebSocket disconnect
operator race
interface change
iptables restore failure
process termination
application shutdown
```

The key invariant is:

```text
Network State Before MIRAGE
            =
Network State After Cleanup
```

whenever rollback is able to complete successfully.

---

# 📸 Screenshots

<div align="center">

<img width="1920" height="1080" alt="Screenshot_2026-08-12_21_00_15" src="https://github.com/user-attachments/assets/a80c4c7b-d58d-47eb-aeac-ba38bc8797c0" />

<img width="1920" height="1080" alt="Screenshot_2026-08-12_21_13_27" src="https://github.com/user-attachments/assets/ca9de018-62a1-4f8c-a63f-6784446b8810" />


</div>

---

# 📄 License

MIRAGE is released under the MIT License.

---

<div align="center">

### M I R A G E

**Observe. Intercept. Analyze. Recover.**

<sub>Built for authorized security research and network analysis.</sub>

</div>
