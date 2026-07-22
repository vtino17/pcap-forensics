# PCAP Forensics

[![License](https://img.shields.io/badge/License-MIT-22AA55?style=flat-square)](LICENSE)
[![Stars](https://img.shields.io/github/stars/vtino17/pcap-forensics?style=flat-square)](https://github.com/vtino17/pcap-forensics/stargazers)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square)](https://python.org)
[![Last Commit](https://img.shields.io/github/last-commit/vtino17/pcap-forensics?style=flat-square)](https://github.com/vtino17/pcap-forensics/commits)

Command-line forensic analysis tool for network packet captures. Designed for incident responders and security analysts who need to quickly extract indicators from PCAP files without a full SIEM pipeline.

## Features

DNS query extraction with source/destination attribution

HTTP request reconstruction including method, URI, and Host header

TLS handshake detection with Server Name Indication (SNI) extraction

Beaconing detection based on outbound traffic volume and port diversity

Multi-format reporting (JSON, CSV)

## Installation

```bash
pip install scapy
git clone https://github.com/vtino17/pcap-forensics.git
cd pcap-forensics
pip install .
```

## Usage

```bash
# Basic analysis
pcap-forensics capture.pcap

# JSON report with verbose output
pcap-forensics capture.pcap --report json --output report.json --verbose

# CSV report
pcap-forensics capture.pcap --report csv --output report.csv
```

## Output

JSON report structure:

```json
{
  "summary": {
    "total_packets": 15000,
    "protocols": { "TCP": 12000, "UDP": 2500, "OTHER": 500 },
    "dns_queries": 340,
    "http_requests": 89,
    "tls_handshakes": 45,
    "beacon_candidates": 2
  },
  "dns_queries": [
    { "query": "evil.example.com", "type": 1, "src": "10.0.0.5", "dst": "8.8.8.8" }
  ],
  "http_requests": [
    { "request": "GET /admin", "host": "target.com", "src": "10.0.0.5", "dst": "203.0.113.10" }
  ],
  "beacon_candidates": [
    { "ip": "10.0.0.5", "total_tx_bytes": 450000, "unique_ports": [80, 443, 8080], "reason": "High outbound volume on multiple ports" }
  ]
}
```

## Testing

```bash
pip install pytest
pytest tests/
```

## License

MIT
