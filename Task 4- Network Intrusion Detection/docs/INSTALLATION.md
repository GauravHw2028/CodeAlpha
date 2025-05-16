# Installation Guide: Network Intrusion Detection System

This document provides step-by-step instructions for installing and configuring the Network Intrusion Detection System.

## Prerequisites

- Operating System: Linux (Ubuntu/Debian recommended), Windows 10/11, or macOS
- Python 3.7 or higher
- Network interface in promiscuous mode (for live traffic monitoring)
- Administrative privileges

## Installing Suricata

### Ubuntu/Debian
```bash
# Install Suricata from the Ubuntu repository
sudo apt-get update
sudo apt-get install suricata

# Alternative: Install from PPA for latest version
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt-get update
sudo apt-get install suricata
```

### CentOS/RHEL
```bash
# Enable EPEL repository
sudo yum install epel-release
sudo yum install suricata
```

### Windows
1. Download the latest Windows installer from [Suricata's official website](https://suricata.io/download/)
2. Run the installer and follow the on-screen instructions
3. Add Suricata to your system PATH

### macOS
```bash
# Using Homebrew
brew install suricata
```

## Installing Required Python Packages

The Python scripts in this project require several dependencies:

```bash
# Create a virtual environment (recommended)
python -m venv nids-env
source nids-env/bin/activate  # On Windows: nids-env\Scripts\activate

# Install required packages
pip install scapy dpkt colorama matplotlib pandas seaborn tabulate requests geoip2
```

## Configuring Suricata

1. Locate the Suricata configuration file:
   - Ubuntu/Debian: `/etc/suricata/suricata.yaml`
   - Windows: Usually in `C:\Program Files\Suricata\conf\suricata.yaml`

2. Set your home network range in the configuration:
   ```yaml
   vars:
     address-groups:
       HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"  # Adjust to your network
   ```

3. Configure your network interface:
   ```yaml
   af-packet:
     - interface: eth0  # Change this to your network interface
       cluster-id: 99
       cluster-type: cluster_flow
       defrag: yes
   ```

4. Copy the custom rules file:
   ```bash
   # For Linux
   sudo cp rules/custom.rules /etc/suricata/rules/
   
   # For Windows
   copy rules\custom.rules "C:\Program Files\Suricata\rules\"
   ```

5. Update the rules configuration to include your custom rules:
   ```yaml
   rule-files:
     - suricata.rules
     - custom.rules
   ```

## Setting Up the Python Scripts

1. Create a stats directory for storing alert logs:
   ```bash
   mkdir -p stats
   ```

2. Ensure script permissions are set correctly (Linux/macOS):
   ```bash
   chmod +x scripts/*.py
   ```

## Starting Suricata

### Linux
```bash
# Start Suricata service
sudo systemctl start suricata

# Or run in IDS mode on a specific interface
sudo suricata -c /etc/suricata/suricata.yaml -i eth0 --init-errors-fatal
```

### Windows
```powershell
# Run Suricata from the installation directory
& 'C:\Program Files\Suricata\bin\suricata.exe' -c 'C:\Program Files\Suricata\conf\suricata.yaml' -i INTERFACE_NAME
```

## Using the Alert Monitoring Script

Once Suricata is running and generating alerts, you can monitor them in real-time:

```bash
# Navigate to the scripts directory
cd scripts

# Run the alert manager
python alert_manager.py /var/log/suricata/eve.json  # Linux path
# or 
python alert_manager.py "C:\Program Files\Suricata\log\eve.json"  # Windows path
```

## Analyzing PCAP Files

To analyze existing packet capture files:

```bash
cd scripts
python pcap_analyzer.py /path/to/capture.pcap
```

## Visualizing Alert Data

After collecting some alert data:

```bash
cd scripts
python visualize_alerts.py --log-dir ../stats
```

## Troubleshooting

1. **No alerts are being generated:**
   - Verify Suricata is running: `systemctl status suricata`
   - Check interface configuration: `ip link show`
   - Ensure network interface is in promiscuous mode
   - Verify log files have correct permissions

2. **Performance issues:**
   - Adjust the threading and CPU affinity settings in suricata.yaml
   - Enable runmode=autofp if available in your version
   - Reduce the number of rules if CPU usage is high

3. **Script errors:**
   - Verify all Python dependencies are installed
   - Check paths to log files and configuration files
   - Ensure correct permissions for accessing log files 