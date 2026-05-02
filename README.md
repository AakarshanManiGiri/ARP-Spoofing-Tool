# ARP Security Monitor

A PyQt6 + Scapy desktop application for defensive ARP monitoring and anomaly detection.

## What It Does

- Captures ARP request/reply traffic in real time.
- Tracks IP-to-MAC and MAC-to-IP mappings.
- Detects suspicious mapping changes that can indicate ARP spoofing.
- Shows live telemetry counters:
  - packets seen
  - new mapping pairs
  - IP conflicts
  - MAC conflicts
- Supports optional focus mode for one host IP.

## Why This Refactor

The app has been refactored into a defensive network visibility tool instead of an active poisoning utility.

## Requirements

- Python 3.10+
- PyQt6
- Scapy
- Packet capture privileges (Administrator on Windows or root on Linux/macOS)
- Npcap on Windows for reliable packet capture

Install dependencies:

```bash
pip install pyqt6 scapy
```

## Run

```bash
python ARP-Poison.py
```

## Usage

1. Enter a network interface name (for example: `Ethernet`, `Wi-Fi`, `eth0`).
2. Optionally enter a Watch IP to filter analysis focus.
3. Choose an analysis profile.
4. Click Start Monitoring.
5. Watch the live stream and conflict alerts.

## Notes

- ARP spoofing indicators are heuristic-based. Confirm with switch/router logs when available.
- If packet capture fails, relaunch with elevated privileges and confirm interface name.
