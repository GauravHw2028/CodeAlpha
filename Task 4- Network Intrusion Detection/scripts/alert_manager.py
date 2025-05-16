#!/usr/bin/env python3
"""
Suricata Alert Manager
----------------------
This script monitors Suricata's eve.json file for new alerts and can:
1. Display alerts in real-time
2. Send notifications (email, SMS, etc.)
3. Log alerts to a database
4. Generate reports

Usage:
    python alert_manager.py /path/to/eve.json

Dependencies:
    pip install requests colorama tabulate
"""

import json
import sys
import os
import time
import datetime
import argparse
from collections import defaultdict
import socket
import smtplib
from email.message import EmailMessage
from colorama import Fore, Style, init

# Initialize colorama
init()

# Alert severity levels
SEVERITY = {
    "CRITICAL": Fore.RED + Style.BRIGHT,
    "HIGH": Fore.RED,
    "MEDIUM": Fore.YELLOW,
    "LOW": Fore.GREEN,
    "INFO": Fore.BLUE
}

class SuricataAlertManager:
    def __init__(self, eve_log_path, notify_email=None, threshold=10):
        self.eve_log_path = eve_log_path
        self.notify_email = notify_email
        self.threshold = threshold
        self.alert_counts = defaultdict(int)
        self.known_alerts = set()
        self.start_time = datetime.datetime.now()
        
        # Create stats directory if it doesn't exist
        self.stats_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "stats")
        if not os.path.exists(self.stats_dir):
            os.makedirs(self.stats_dir)
            
        print(f"{Fore.CYAN}Suricata Alert Manager{Style.RESET_ALL}")
        print(f"Monitoring: {eve_log_path}")
        print(f"Started at: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("-" * 80)
        
    def determine_severity(self, alert):
        """Determine alert severity based on signature"""
        if "ssh" in alert.get("alert", {}).get("signature", "").lower() or "brute force" in alert.get("alert", {}).get("signature", "").lower():
            return "HIGH"
        if "icmp" in alert.get("alert", {}).get("signature", "").lower():
            return "LOW"
        if "injection" in alert.get("alert", {}).get("signature", "").lower() or "xss" in alert.get("alert", {}).get("signature", "").lower():
            return "CRITICAL"
        return "MEDIUM"
        
    def format_alert(self, alert):
        """Format the alert for display"""
        timestamp = alert.get("timestamp", "Unknown")
        src_ip = alert.get("src_ip", "Unknown")
        dest_ip = alert.get("dest_ip", "Unknown")
        signature = alert.get("alert", {}).get("signature", "Unknown")
        category = alert.get("alert", {}).get("category", "Unknown")
        severity = self.determine_severity(alert)
        
        formatted = f"{timestamp} | {SEVERITY[severity]}{severity}{Style.RESET_ALL} | "
        formatted += f"{src_ip} -> {dest_ip} | {signature} | {category}"
        return formatted
        
    def send_email_notification(self, alert):
        """Send email notification for critical alerts"""
        if not self.notify_email:
            return
            
        try:
            msg = EmailMessage()
            msg.set_content(f"""
            Suricata Alert Notification
            --------------------------
            Time: {alert.get('timestamp')}
            Severity: {self.determine_severity(alert)}
            Source IP: {alert.get('src_ip')}
            Destination IP: {alert.get('dest_ip')}
            Signature: {alert.get('alert', {}).get('signature')}
            Category: {alert.get('alert', {}).get('category')}
            """)
            
            msg['Subject'] = f'SECURITY ALERT: {alert.get("alert", {}).get("signature")}'
            msg['From'] = 'suricata-alerts@example.com'
            msg['To'] = self.notify_email
            
            # Replace with actual SMTP server details
            # s = smtplib.SMTP('smtp.example.com')
            # s.send_message(msg)
            # s.quit()
            
            print(f"{Fore.YELLOW}Email notification would be sent to {self.notify_email}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Error sending email: {e}{Style.RESET_ALL}")
            
    def log_to_file(self, alerts):
        """Log alerts to a daily log file"""
        today = datetime.datetime.now().strftime("%Y-%m-%d")
        log_file = os.path.join(self.stats_dir, f"alerts_{today}.log")
        
        with open(log_file, "a") as f:
            for alert in alerts:
                f.write(json.dumps(alert) + "\n")
                
    def save_stats(self):
        """Save alert statistics to a file"""
        stats_file = os.path.join(self.stats_dir, "alert_stats.json")
        
        # Prepare stats
        stats = {
            "start_time": self.start_time.strftime("%Y-%m-%d %H:%M:%S"),
            "end_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_alerts": sum(self.alert_counts.values()),
            "alert_types": dict(self.alert_counts)
        }
        
        with open(stats_file, "w") as f:
            json.dump(stats, f, indent=4)
            
    def get_hostname_from_ip(self, ip):
        """Try to resolve hostname from IP address"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror):
            return ip
            
    def monitor(self):
        """Monitor the eve.json file for new alerts"""
        if not os.path.exists(self.eve_log_path):
            print(f"{Fore.RED}Error: File {self.eve_log_path} does not exist{Style.RESET_ALL}")
            sys.exit(1)
            
        file_pos = os.path.getsize(self.eve_log_path)
        
        try:
            while True:
                if os.path.getsize(self.eve_log_path) > file_pos:
                    with open(self.eve_log_path, "r") as f:
                        f.seek(file_pos)
                        new_alerts = []
                        
                        for line in f:
                            try:
                                event = json.loads(line)
                                if "alert" in event:
                                    event_id = f"{event.get('timestamp')}-{event.get('src_ip')}-{event.get('dest_ip')}-{event.get('alert', {}).get('signature_id')}"
                                    
                                    if event_id not in self.known_alerts:
                                        self.known_alerts.add(event_id)
                                        new_alerts.append(event)
                                        alert_type = event.get("alert", {}).get("signature", "Unknown")
                                        self.alert_counts[alert_type] += 1
                                        
                                        # Print the alert
                                        print(self.format_alert(event))
                                        
                                        # Send notification for critical alerts
                                        if self.determine_severity(event) == "CRITICAL":
                                            self.send_email_notification(event)
                            except json.JSONDecodeError:
                                continue
                        
                        # Log new alerts to file
                        if new_alerts:
                            self.log_to_file(new_alerts)
                            
                        file_pos = f.tell()
                
                # Save stats periodically
                if sum(self.alert_counts.values()) > 0 and sum(self.alert_counts.values()) % 10 == 0:
                    self.save_stats()
                    
                time.sleep(1)
        except KeyboardInterrupt:
            print(f"\n{Fore.CYAN}Alert monitoring stopped{Style.RESET_ALL}")
            self.save_stats()
            print(f"Statistics saved to {self.stats_dir}")

def main():
    parser = argparse.ArgumentParser(description="Suricata Alert Manager")
    parser.add_argument("eve_log_path", help="Path to Suricata's eve.json file")
    parser.add_argument("--email", help="Email address for notifications")
    parser.add_argument("--threshold", type=int, default=10, help="Alert threshold for notifications")
    
    args = parser.parse_args()
    
    alert_manager = SuricataAlertManager(args.eve_log_path, args.email, args.threshold)
    alert_manager.monitor()

if __name__ == "__main__":
    main() 