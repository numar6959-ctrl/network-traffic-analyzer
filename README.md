# Python Network Traffic Analyzer

A Python-based network traffic analyzer built using Scapy.

This project analyzes PCAP files to provide insights into
network protocols, IP addresses, ports, and DNS activity.

## Features

- Analyze PCAP files
- Count TCP, UDP, ICMP, and other packets
- Identify source and destination IPv4 addresses
- Display the top 10 destination ports
- Analyze DNS queries
- Calculate total traffic size and average packet size
- Detect initial TCP SYN packets

## Technologies Used

- Python 3
- Scapy
- Ubuntu Linux
- tcpdump
- Git

## Installation

Create a virtual environment:

```bash
python3 -m venv .venv
```

Activate it:

```bash
source .venv/bin/activate
```

Install Scapy:

```bash
python -m pip install scapy
```

## Usage

Run the analyzer with a PCAP file:

```bash
python analyzer.py capture.pcap
```

Replace `capture.pcap` with your own packet capture file.

## Privacy and Security

Only analyze traffic you own or have permission to inspect.

PCAP files are excluded from this repository to protect
potentially sensitive network information.

## Limitations

- IP address analysis currently supports IPv4.
- Encrypted DNS queries may not be visible.
- SYN packet counts may include retransmissions.
- The analyzer processes saved captures rather than live traffic.

## Future Improvements

- IPv6 support
- CSV and JSON export
- Network traffic visualization
- Basic suspicious traffic detection
