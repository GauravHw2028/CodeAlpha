# Network Intrusion Detection System (NIDS)

This project is a simple network intrusion detection system using Suricata. It monitors network traffic, detects suspicious activity, and provides basic analysis and visualization of alerts.

## How It Works

- **Suricata** runs on your machine and watches network traffic for threats.
- Alerts are saved in a file called `eve.json`.
- Python scripts in the `scripts` folder process these alerts and generate visualizations.

## Getting Started

1. **Install Suricata**

   - On Linux (Ubuntu/Debian):
     ```
     sudo apt-get update
     sudo apt-get install suricata
     ```
   - On Windows:  
     Download and install from [suricata.io/download](https://suricata.io/download/)

2. **Configure Suricata**

   - Make sure Suricata is set to log alerts in `eve.json` format.
   - You can find and edit the config file (usually `suricata.yaml`) to set the log directory and filename.

3. **Run Suricata**

   - Start Suricata on your network interface:
     ```
     sudo suricata -i <your-interface>
     ```
   - Or analyze a PCAP file:
     ```
     sudo suricata -r path/to/file.pcap
     ```

4. **Copy the `eve.json` File**

   - After running Suricata, copy the generated `eve.json` file into this project folder.

5. **Analyze and Visualize Alerts**

   - Make sure you have Python installed.
   - Run the main script:
     ```
     python run_nids.py
     ```
   - This will analyze the alerts and show you a visualization of detected attacks.

## Files

- `run_nids.py` — Main script to analyze and visualize alerts.
- `scripts/alert_manager.py` — Processes Suricata alerts.
- `scripts/visualize_alerts.py` — Creates simple visualizations from the alerts.

## Notes

- You can add your own Suricata rules in the `local.rules` file (see Suricata docs).
- For more advanced dashboards, consider using the ELK stack (Elasticsearch, Logstash, Kibana), but this project keeps things simple and uses Python.

## Configuration

- Default configuration file: `/etc/suricata/suricata.yaml`
- Rules directory: `/etc/suricata/rules/`
- Custom rules can be added to: `/etc/suricata/rules/local.rules`

## Custom Scripts

- `scripts/alert_manager.py`: Processes Suricata alerts and sends notifications
- `scripts/pcap_analyzer.py`: Analyzes captured packets for deeper inspection

## Visualization (Optional)

For visualization, you can:
1. Install ELK Stack locally
2. Use Suricata with built-in logging to syslog
3. Use simple Python-based visualization of the logs

## Monitoring Logs

View Suricata alerts:
```
sudo tail -f /var/log/suricata/fast.log
```

For detailed event logs:
```
sudo tail -f /var/log/suricata/eve.json | jq 