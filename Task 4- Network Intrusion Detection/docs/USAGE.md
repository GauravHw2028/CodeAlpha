# Network Intrusion Detection System: Usage Guide

This document provides detailed instructions on how to use the Network Intrusion Detection System after installation.

## Basic Workflow

1. **Start Suricata** for network monitoring
2. **Monitor alerts** using alert_manager.py
3. **Analyze PCAP files** (optional) using pcap_analyzer.py
4. **Visualize results** using visualize_alerts.py

## Running Suricata

### Starting Suricata in IDS Mode

```bash
# Linux (running as a service)
sudo systemctl start suricata

# Linux (manual mode for specific interface)
sudo suricata -c /etc/suricata/suricata.yaml -i eth0 --init-errors-fatal

# Windows
& 'C:\Program Files\Suricata\bin\suricata.exe' -c 'C:\Program Files\Suricata\conf\suricata.yaml' -i INTERFACE_NAME
```

### Checking Suricata Status

```bash
# Linux
sudo systemctl status suricata

# Or check logs
sudo tail -f /var/log/suricata/suricata.log
```

## Monitoring Alerts in Real-Time

The `alert_manager.py` script monitors Suricata's alert logs and provides real-time notifications:

```bash
# Basic usage
python scripts/alert_manager.py /var/log/suricata/eve.json

# With email notifications
python scripts/alert_manager.py /var/log/suricata/eve.json --email your.email@example.com

# Set a custom threshold for notifications
python scripts/alert_manager.py /var/log/suricata/eve.json --threshold 5
```

### Alert Manager Output

The alert manager will display alerts in real-time with the following information:
- Timestamp
- Severity level (color-coded: RED=Critical, YELLOW=Medium, GREEN=Low)
- Source and destination IP addresses
- Alert signature
- Category

Example output:
```
2023-06-12T15:34:23 | CRITICAL | 192.168.1.100 -> 192.168.1.5 | SQL Injection Attempt | Web Application Attack
2023-06-12T15:35:17 | LOW | 8.8.8.8 -> 192.168.1.5 | ICMP Ping Detected | Network Scanning
```

## Analyzing PCAP Files

If you have packet capture files from Wireshark or other tools, you can analyze them for suspicious activity:

```bash
# Basic usage
python scripts/pcap_analyzer.py /path/to/capture.pcap

# Specify output directory for analysis results
python scripts/pcap_analyzer.py /path/to/capture.pcap --output /path/to/output
```

The PCAP analyzer detects:
- Port scanning activity
- SYN flood attacks
- SQL injection attempts in HTTP traffic
- XSS attempts in HTTP traffic
- Directory traversal attempts
- DNS tunneling
- Large ICMP packets (potential covert channels)

## Visualizing Alert Data

After collecting alert data, visualize it with the visualization tool:

```bash
# Basic usage (looks for logs in ../stats directory relative to script)
python scripts/visualize_alerts.py

# Specify custom log directory
python scripts/visualize_alerts.py --log-dir /path/to/logs

# Specify custom output directory for visualizations
python scripts/visualize_alerts.py --log-dir /path/to/logs --output /path/to/output
```

The visualization tool generates:
1. Alert timeline chart
2. Alert categories pie chart
3. Severity distribution bar chart
4. Top attackers (source IPs) chart
5. Hourly distribution histogram
6. Protocol distribution chart
7. An HTML report containing all visualizations

## Custom Rules

You can add your own custom rules to `/etc/suricata/rules/custom.rules` (Linux) or the equivalent Windows path.

### Rule Syntax Example:

```
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Custom Rule - Suspicious User-Agent"; \
    flow:established,to_server; \
    content:"User-Agent|3A| Suspicious"; http_header; \
    classtype:web-application-attack; sid:1000001; rev:1;)
```

After adding custom rules, reload Suricata:

```bash
# Linux
sudo systemctl reload suricata

# Or manually
sudo kill -USR2 $(pidof suricata)
```

## Scheduled Analysis

For automated monitoring, you can set up cron jobs (Linux) or Task Scheduler (Windows):

### Example Cron Job (Linux)

```bash
# Edit crontab
crontab -e

# Add this line to run visualization daily at 1 AM
0 1 * * * cd /path/to/project && python scripts/visualize_alerts.py --log-dir /var/log/suricata/stats >> /var/log/nids_reports.log 2>&1
```

### Scheduled Task (Windows)

Use Task Scheduler to run the scripts at regular intervals.

## Troubleshooting

1. **No alerts showing in alert_manager:**
   - Check if Suricata is running and properly configured
   - Verify the path to eve.json is correct
   - Ensure you have proper permissions to read the log files

2. **Missing visualizations:**
   - Ensure you have matplotlib, pandas, and seaborn installed
   - Check if the log directory contains valid log files
   - Verify you have write permissions to the output directory

3. **PCAP analysis fails:**
   - Confirm Scapy is properly installed
   - Verify the PCAP file is valid and not corrupted
   - Check for sufficient disk space for analysis results