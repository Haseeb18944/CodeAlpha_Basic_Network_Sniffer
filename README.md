# CodeAlpha Basic Network Sniffer

A Python-based network traffic analysis tool developed as part of the CodeAlpha Cyber Security Internship.

The project uses Scapy to capture authorized network traffic and analyze useful packet metadata such as source and destination IP addresses, protocols, ports, packet length, payload size, and a limited hexadecimal payload preview.

> **Ethical Use:** This project is intended for educational and defensive security purposes. Only capture traffic on systems and networks that you own or have explicit authorization to monitor.

---

## Features

- Capture network packets using Scapy
- Display source and destination IP addresses
- Identify TCP, UDP, ICMP, IP, and other traffic
- Display source and destination ports when available
- Display packet length
- Calculate payload size
- Display a limited hexadecimal payload preview
- Timestamp captured packets
- Number captured packets
- Protocol statistics
- Capture a specific number of packets
- Capture traffic for a specific duration
- Apply optional packet filters
- Select a specific network interface
- Export packet metadata to CSV
- Graceful handling of `Ctrl+C`
- Basic permission and error handling

---

## Project Structure

```text
CodeAlpha_Basic_Network_Sniffer/
├── .gitignore
├── README.md
├── requirements.txt
├── src/
│   └── network_sniffer.py
├── docs/
│   └── capture_report.csv
└── screenshots/
