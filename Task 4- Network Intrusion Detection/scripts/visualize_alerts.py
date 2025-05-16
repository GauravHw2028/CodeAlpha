#!/usr/bin/env python3
"""
Suricata Alert Visualization Tool
---------------------------------
This script generates visualizations from Suricata alert logs.

Usage:
    python visualize_alerts.py [--log-dir LOG_DIR] [--output OUTPUT_DIR]

Dependencies:
    pip install matplotlib pandas seaborn geoip2
"""

import os
import json
import argparse
import datetime
from collections import Counter, defaultdict
import ipaddress

# Visualization libraries
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import pandas as pd
import seaborn as sns
from matplotlib.ticker import MaxNLocator

# Optional for geolocation
try:
    import geoip2.database
    has_geoip = True
except ImportError:
    has_geoip = False
    print("GeoIP functionality not available. Install with: pip install geoip2")

class AlertVisualizer:
    def __init__(self, log_dir, output_dir=None):
        self.log_dir = log_dir
        self.output_dir = output_dir or os.path.join(os.path.dirname(log_dir), "visualization")
        
        # Create output directory if it doesn't exist
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
            
        # Set the plotting style
        sns.set_style("darkgrid")
        plt.rcParams.update({'font.size': 10})
        
        # Initialize GeoIP database if available
        self.geoip_reader = None
        if has_geoip:
            geoip_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "GeoLite2-City.mmdb")
            if os.path.exists(geoip_path):
                self.geoip_reader = geoip2.database.Reader(geoip_path)
                
        print(f"Alert Visualizer initialized")
        print(f"Log directory: {self.log_dir}")
        print(f"Output directory: {self.output_dir}")
        
    def load_alerts(self):
        """Load all alert logs from the log directory"""
        alerts = []
        
        for filename in os.listdir(self.log_dir):
            if filename.startswith("alerts_") and filename.endswith(".log"):
                log_path = os.path.join(self.log_dir, filename)
                with open(log_path, "r") as f:
                    for line in f:
                        try:
                            alert = json.loads(line.strip())
                            alerts.append(alert)
                        except json.JSONDecodeError:
                            continue
                            
        print(f"Loaded {len(alerts)} alerts from log files")
        return alerts
        
    def preprocess_alerts(self, alerts):
        """Convert alerts to a pandas DataFrame for analysis"""
        processed_alerts = []
        
        for alert in alerts:
            if "alert" in alert:
                timestamp = alert.get("timestamp", "")
                if timestamp:
                    try:
                        # Convert timestamp to datetime
                        dt = datetime.datetime.strptime(timestamp.split(".")[0], "%Y-%m-%dT%H:%M:%S")
                    except ValueError:
                        continue
                        
                    processed_alert = {
                        "timestamp": dt,
                        "date": dt.date(),
                        "hour": dt.hour,
                        "src_ip": alert.get("src_ip", ""),
                        "dest_ip": alert.get("dest_ip", ""),
                        "src_port": alert.get("src_port", 0),
                        "dest_port": alert.get("dest_port", 0),
                        "protocol": alert.get("proto", ""),
                        "signature": alert.get("alert", {}).get("signature", ""),
                        "category": alert.get("alert", {}).get("category", ""),
                        "severity": self._determine_severity(alert)
                    }
                    
                    # Add country info if GeoIP is available
                    if self.geoip_reader and processed_alert["src_ip"]:
                        try:
                            if not self._is_private_ip(processed_alert["src_ip"]):
                                country = self.geoip_reader.city(processed_alert["src_ip"]).country.name
                                processed_alert["src_country"] = country
                        except Exception:
                            processed_alert["src_country"] = "Unknown"
                            
                    processed_alerts.append(processed_alert)
                    
        df = pd.DataFrame(processed_alerts)
        print(f"Preprocessed {len(df)} alerts")
        return df
        
    def _is_private_ip(self, ip):
        """Check if an IP address is private"""
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False
            
    def _determine_severity(self, alert):
        """Determine alert severity based on signature"""
        signature = alert.get("alert", {}).get("signature", "").lower()
        
        if "brute force" in signature or "ssh" in signature:
            return "HIGH"
        if "injection" in signature or "xss" in signature:
            return "CRITICAL"
        if "icmp" in signature:
            return "LOW"
        return "MEDIUM"
        
    def visualize_alert_timeline(self, df):
        """Generate a timeline visualization of alerts"""
        if df.empty:
            print("No data available for timeline visualization")
            return
            
        # Group by date and count
        daily_counts = df.groupby("date").size()
        
        plt.figure(figsize=(12, 6))
        ax = daily_counts.plot(kind="line", marker="o", color="dodgerblue")
        
        # Format the plot
        plt.title("Alert Timeline", fontsize=16)
        plt.xlabel("Date", fontsize=12)
        plt.ylabel("Number of Alerts", fontsize=12)
        plt.grid(True, linestyle="--", alpha=0.7)
        
        # Format x-axis dates
        ax.xaxis.set_major_formatter(mdates.DateFormatter("%Y-%m-%d"))
        plt.xticks(rotation=45)
        
        # Ensure y-axis uses integers
        ax.yaxis.set_major_locator(MaxNLocator(integer=True))
        
        plt.tight_layout()
        plt.savefig(os.path.join(self.output_dir, "alert_timeline.png"))
        plt.close()
        print("Generated alert timeline visualization")
        
    def visualize_alert_categories(self, df):
        """Generate a pie chart of alert categories"""
        if df.empty or "category" not in df.columns:
            print("No category data available for visualization")
            return
            
        # Count categories
        category_counts = df["category"].value_counts()
        
        # Create pie chart
        plt.figure(figsize=(10, 8))
        plt.pie(category_counts, labels=category_counts.index, autopct="%1.1f%%", 
                shadow=True, startangle=90, wedgeprops={"edgecolor": "black"})
        plt.title("Alert Categories", fontsize=16)
        plt.axis("equal")  # Equal aspect ratio ensures that pie is drawn as a circle
        
        plt.tight_layout()
        plt.savefig(os.path.join(self.output_dir, "alert_categories.png"))
        plt.close()
        print("Generated alert categories visualization")
        
    def visualize_severity_distribution(self, df):
        """Generate a bar chart of alert severity distribution"""
        if df.empty or "severity" not in df.columns:
            print("No severity data available for visualization")
            return
            
        # Count by severity
        severity_counts = df["severity"].value_counts()
        
        # Define colors for severity levels
        colors = {
            "CRITICAL": "red",
            "HIGH": "orange",
            "MEDIUM": "yellow",
            "LOW": "green",
            "INFO": "blue"
        }
        
        # Use the defined colors or default to gray
        bar_colors = [colors.get(sev, "gray") for sev in severity_counts.index]
        
        plt.figure(figsize=(10, 6))
        severity_counts.plot(kind="bar", color=bar_colors)
        
        plt.title("Alert Severity Distribution", fontsize=16)
        plt.xlabel("Severity Level", fontsize=12)
        plt.ylabel("Number of Alerts", fontsize=12)
        plt.grid(True, axis="y", linestyle="--", alpha=0.7)
        
        plt.tight_layout()
        plt.savefig(os.path.join(self.output_dir, "severity_distribution.png"))
        plt.close()
        print("Generated severity distribution visualization")
        
    def visualize_top_attackers(self, df):
        """Generate a bar chart of top source IPs (attackers)"""
        if df.empty or "src_ip" not in df.columns:
            print("No source IP data available for visualization")
            return
            
        # Count by source IP and get top 10
        top_sources = df["src_ip"].value_counts().head(10)
        
        plt.figure(figsize=(12, 6))
        ax = top_sources.plot(kind="barh", color="firebrick")
        
        plt.title("Top 10 Source IPs (Potential Attackers)", fontsize=16)
        plt.xlabel("Number of Alerts", fontsize=12)
        plt.ylabel("Source IP", fontsize=12)
        plt.grid(True, axis="x", linestyle="--", alpha=0.7)
        
        # Add count labels to bars
        for i, v in enumerate(top_sources):
            ax.text(v + 0.1, i, str(v), va="center")
            
        plt.tight_layout()
        plt.savefig(os.path.join(self.output_dir, "top_attackers.png"))
        plt.close()
        print("Generated top attackers visualization")
        
    def visualize_hourly_distribution(self, df):
        """Generate a histogram of alerts by hour of day"""
        if df.empty or "hour" not in df.columns:
            print("No timestamp data available for hourly visualization")
            return
            
        plt.figure(figsize=(12, 6))
        
        # Create histogram with 24 bins (one for each hour)
        n, bins, patches = plt.hist(df["hour"], bins=24, range=(0, 24), 
                                    color="steelblue", edgecolor="black", alpha=0.7)
        
        plt.title("Alert Distribution by Hour of Day", fontsize=16)
        plt.xlabel("Hour of Day", fontsize=12)
        plt.ylabel("Number of Alerts", fontsize=12)
        plt.grid(True, axis="y", linestyle="--", alpha=0.7)
        
        # Set x-ticks to show all hours
        plt.xticks(range(0, 24))
        
        plt.tight_layout()
        plt.savefig(os.path.join(self.output_dir, "hourly_distribution.png"))
        plt.close()
        print("Generated hourly distribution visualization")
        
    def visualize_protocol_distribution(self, df):
        """Generate a bar chart of protocols"""
        if df.empty or "protocol" not in df.columns:
            print("No protocol data available for visualization")
            return
            
        protocol_counts = df["protocol"].value_counts()
        
        plt.figure(figsize=(10, 6))
        protocol_counts.plot(kind="bar", color="teal")
        
        plt.title("Protocol Distribution", fontsize=16)
        plt.xlabel("Protocol", fontsize=12)
        plt.ylabel("Number of Alerts", fontsize=12)
        plt.grid(True, axis="y", linestyle="--", alpha=0.7)
        
        plt.tight_layout()
        plt.savefig(os.path.join(self.output_dir, "protocol_distribution.png"))
        plt.close()
        print("Generated protocol distribution visualization")
        
    def generate_report(self, df):
        """Generate an HTML report with all visualizations"""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        total_alerts = len(df)
        
        # Start building HTML content
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Suricata Alert Analysis Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1 {{ color: #2c3e50; }}
                h2 {{ color: #3498db; }}
                .summary {{ background-color: #f8f9fa; padding: 15px; border-radius: 5px; }}
                .visualization {{ margin-top: 30px; }}
                img {{ max-width: 100%; border: 1px solid #ddd; border-radius: 5px; }}
            </style>
        </head>
        <body>
            <h1>Suricata Alert Analysis Report</h1>
            <div class="summary">
                <h2>Summary</h2>
                <p><strong>Generated:</strong> {timestamp}</p>
                <p><strong>Total Alerts:</strong> {total_alerts}</p>
                <p><strong>Date Range:</strong> {df['date'].min() if not df.empty else 'N/A'} to {df['date'].max() if not df.empty else 'N/A'}</p>
            </div>
        """
        
        # Add each visualization section
        visualizations = [
            ("alert_timeline.png", "Alert Timeline", "Number of alerts detected over time"),
            ("alert_categories.png", "Alert Categories", "Distribution of alert categories"),
            ("severity_distribution.png", "Alert Severity", "Distribution of alert severity levels"),
            ("top_attackers.png", "Top Attackers", "Source IPs generating the most alerts"),
            ("hourly_distribution.png", "Hourly Distribution", "Distribution of alerts by hour of day"),
            ("protocol_distribution.png", "Protocol Distribution", "Distribution of network protocols in alerts")
        ]
        
        for img_file, title, description in visualizations:
            if os.path.exists(os.path.join(self.output_dir, img_file)):
                html_content += f"""
                <div class="visualization">
                    <h2>{title}</h2>
                    <p>{description}</p>
                    <img src="{img_file}" alt="{title}">
                </div>
                """
                
        # Close HTML
        html_content += """
        </body>
        </html>
        """
        
        # Write HTML report
        report_path = os.path.join(self.output_dir, "alert_report.html")
        with open(report_path, "w") as f:
            f.write(html_content)
            
        print(f"Generated HTML report at: {report_path}")
        
    def create_all_visualizations(self):
        """Create all visualizations and generate a report"""
        # Load and preprocess alerts
        alerts = self.load_alerts()
        if not alerts:
            print("No alerts found in the specified log directory")
            return
            
        df = self.preprocess_alerts(alerts)
        if df.empty:
            print("No valid alerts after preprocessing")
            return
            
        # Generate visualizations
        self.visualize_alert_timeline(df)
        self.visualize_alert_categories(df)
        self.visualize_severity_distribution(df)
        self.visualize_top_attackers(df)
        self.visualize_hourly_distribution(df)
        self.visualize_protocol_distribution(df)
        
        # Generate HTML report
        self.generate_report(df)
        
        print(f"All visualizations have been generated in: {self.output_dir}")

def main():
    parser = argparse.ArgumentParser(description="Suricata Alert Visualization Tool")
    parser.add_argument("--log-dir", default="../stats", help="Directory containing Suricata alert logs")
    parser.add_argument("--output", help="Output directory for visualizations")
    
    args = parser.parse_args()
    
    # Resolve path relative to script location if needed
    log_dir = args.log_dir
    if not os.path.isabs(log_dir):
        log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), log_dir)
        
    visualizer = AlertVisualizer(log_dir, args.output)
    visualizer.create_all_visualizations()

if __name__ == "__main__":
    main() 