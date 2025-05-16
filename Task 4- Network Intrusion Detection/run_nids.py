#!/usr/bin/env python3
"""
Network Intrusion Detection System - Main Runner Script
------------------------------------------------------
This script provides a user-friendly interface to run the different
components of the Network Intrusion Detection System.

Usage:
    python run_nids.py [command]

Commands:
    monitor     - Start the alert monitoring system
    analyze     - Analyze a PCAP file for intrusions
    visualize   - Generate visualizations from collected alerts
    help        - Show this help message
"""

import os
import sys
import argparse
import subprocess
import platform

# Set paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SCRIPTS_DIR = os.path.join(BASE_DIR, "scripts")
STATS_DIR = os.path.join(BASE_DIR, "stats")
PCAP_FILE = os.path.join(BASE_DIR, "capture.pcap")  # Hardcoded for simplicity
EVE_JSON = os.path.join(BASE_DIR, "eve.json")  # Adjust path if needed

# Create stats directory if it doesn't exist
if not os.path.exists(STATS_DIR):
    os.makedirs(STATS_DIR)

def print_header():
    """Print a nice header for the application"""
    print("\n" + "=" * 80)
    print(" " * 20 + "NETWORK INTRUSION DETECTION SYSTEM")
    print("=" * 80 + "\n")

def detect_os():
    """Detect the operating system and return some default paths"""
    system = platform.system()
    
    if system == "Linux":
        eve_json_path = "/var/log/suricata/eve.json"
        suricata_config = "/etc/suricata/suricata.yaml"
    elif system == "Windows":
        eve_json_path = os.path.join("C:", os.sep, "Program Files", "Suricata", "log", "eve.json")
        suricata_config = os.path.join("C:", os.sep, "Program Files", "Suricata", "conf", "suricata.yaml")
    else:  # macOS or other
        eve_json_path = "/usr/local/var/log/suricata/eve.json"
        suricata_config = "/usr/local/etc/suricata/suricata.yaml"
        
    return system, eve_json_path, suricata_config

def monitor_command(args):
    """Run the alert monitoring system"""
    print_header()
    print("Starting Alert Monitoring System...")
    
    # Import alert manager to get default paths
    sys.path.insert(0, SCRIPTS_DIR)
    
    # Set the eve.json path
    if args.logfile:
        eve_json_path = args.logfile
    else:
        _, eve_json_path, _ = detect_os()
        if not os.path.exists(eve_json_path):
            print(f"Warning: Default log file not found at {eve_json_path}")
            eve_json_path = input("Please enter the path to your Suricata eve.json file: ")
    
    # Build the command
    cmd = [sys.executable, os.path.join(SCRIPTS_DIR, "alert_manager.py"), eve_json_path]
    
    # Add optional arguments
    if args.email:
        cmd.extend(["--email", args.email])
    if args.threshold:
        cmd.extend(["--threshold", str(args.threshold)])
        
    print(f"Monitoring alerts from: {eve_json_path}")
    if args.email:
        print(f"Sending notifications to: {args.email}")
    print("\nPress Ctrl+C to stop monitoring...\n")
    
    # Run the command
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print("\nAlert monitoring stopped by user.")

def analyze_command(args):
    """Run the PCAP analyzer"""
    print_header()
    print("Starting PCAP Analysis...")
    
    if not args.pcap_file:
        print("Error: No PCAP file specified.")
        print("Usage: python run_nids.py analyze --pcap /path/to/capture.pcap")
        return
        
    if not os.path.exists(args.pcap_file):
        print(f"Error: PCAP file not found at {args.pcap_file}")
        return
        
    # Build the command
    cmd = [sys.executable, os.path.join(SCRIPTS_DIR, "pcap_analyzer.py"), args.pcap_file]
    
    # Add optional arguments
    if args.output:
        cmd.extend(["--output", args.output])
        
    print(f"Analyzing PCAP file: {args.pcap_file}")
    
    # Run the command
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print("\nPCAP analysis stopped by user.")

def visualize_command(args):
    """Run the visualization tool"""
    print_header()
    print("Starting Visualization Generation...")
    
    # Set log directory
    log_dir = args.log_dir if args.log_dir else STATS_DIR
    
    # Build the command
    cmd = [sys.executable, os.path.join(SCRIPTS_DIR, "visualize_alerts.py"), "--log-dir", log_dir]
    
    # Add optional arguments
    if args.output:
        cmd.extend(["--output", args.output])
        
    print(f"Generating visualizations from logs in: {log_dir}")
    if args.output:
        print(f"Output will be saved to: {args.output}")
    
    # Run the command
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print("\nVisualization generation stopped by user.")

def analyze_alerts():
    print("Analyzing Suricata alerts...")
    os.system(f"{sys.executable} {os.path.join(SCRIPTS_DIR, 'alert_manager.py')} {EVE_JSON}")

def visualize_alerts():
    print("Visualizing detected attacks...")
    os.system(f"{sys.executable} {os.path.join(SCRIPTS_DIR, 'visualize_alerts.py')}")

def main():
    """Main entry point for the script"""
    parser = argparse.ArgumentParser(description="Network Intrusion Detection System")
    subparsers = parser.add_subparsers(dest="command", help="Command to run")
    
    # Monitor command
    monitor_parser = subparsers.add_parser("monitor", help="Start the alert monitoring system")
    monitor_parser.add_argument("--logfile", help="Path to Suricata's eve.json file")
    monitor_parser.add_argument("--email", help="Email address for notifications")
    monitor_parser.add_argument("--threshold", type=int, help="Alert threshold for notifications")
    
    # Analyze command
    analyze_parser = subparsers.add_parser("analyze", help="Analyze a PCAP file for intrusions")
    analyze_parser.add_argument("--pcap", dest="pcap_file", help="Path to the PCAP file to analyze")
    analyze_parser.add_argument("--output", help="Output directory for analysis results")
    
    # Visualize command
    visualize_parser = subparsers.add_parser("visualize", help="Generate visualizations from collected alerts")
    visualize_parser.add_argument("--log-dir", help="Directory containing Suricata alert logs")
    visualize_parser.add_argument("--output", help="Output directory for visualizations")
    
    # Parse arguments
    args = parser.parse_args()
    
    # Run the appropriate command
    if args.command == "monitor":
        monitor_command(args)
    elif args.command == "analyze":
        analyze_command(args)
    elif args.command == "visualize":
        visualize_command(args)
    else:
        # No command or help command
        parser.print_help()
        print("\nFor more detailed information, check the documentation in the docs/ directory.")

if __name__ == "__main__":
    analyze_alerts()
    visualize_alerts() 