# Network Sniffer

A Python-based network packet sniffer that captures and analyzes network traffic

## Installation

```bash
pip install scapy
```

## Usage

Basic usage:

```bash
# Run with default settings (capture on default interface)
python network_sniffer.py

# List available network interfaces
python network_sniffer.py -l

# Capture on a specific interface
python network_sniffer.py -i eth0

# Capture 100 packets and stop
python network_sniffer.py -c 100

# Capture for 60 seconds and stop
python network_sniffer.py -t 60

# Save packet data to a file
python network_sniffer.py -o captured_packets.txt
```

### Command Line Arguments

- `-i, --interface`: Network interface to use for capturing
- `-c, --count`: Number of packets to capture (0 for unlimited)
- `-t, --timeout`: Stop sniffing after specified seconds
- `-o, --output`: Write packet data to file
- `-l, --list-interfaces`: List available network interfaces

