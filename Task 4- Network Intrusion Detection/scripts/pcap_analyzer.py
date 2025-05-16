#!/usr/bin/env python3
"""
PCAP File Analyzer for Network Intrusion Detection
--------------------------------------------------
This script analyzes PCAP files for suspicious network activity
that might indicate intrusion attempts.

Usage:
    python pcap_analyzer.py /path/to/capture.pcap

Dependencies:
    pip install scapy dpkt
"""

import os
import sys
import time
import argparse
import socket
import struct
from collections import Counter, defaultdict
import logging

# Import scapy for packet analysis
try:
    from scapy.all import rdpcap, IP, TCP, UDP, ICMP
    has_scapy = True
except ImportError:
    has_scapy = False
    print("Scapy not installed. Install with: pip install scapy")
    
# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("PCAPAnalyzer")

class PCAPAnalyzer:
    def __init__(self, pcap_file, output_dir=None):
        self.pcap_file = pcap_file
        self.output_dir = output_dir or os.path.dirname(os.path.abspath(pcap_file))
        
        # Create output directory if it doesn't exist
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
            
        # Initialize data structures for analysis
        self.ip_conversations = defaultdict(int)
        self.port_scan_detection = defaultdict(set)
        self.syn_flood_detection = defaultdict(int)
        self.http_requests = []
        self.dns_queries = []
        self.suspicious_connections = []
        
        logger.info(f"Initializing PCAP analysis for: {pcap_file}")
        
    def analyze(self):
        """Main analysis function for the PCAP file"""
        if not has_scapy:
            logger.error("Scapy is required for PCAP analysis")
            return False
            
        logger.info(f"Starting analysis of {self.pcap_file}")
        start_time = time.time()
        
        try:
            # Load the PCAP file
            packets = rdpcap(self.pcap_file)
            logger.info(f"Loaded {len(packets)} packets from file")
            
            # Process each packet
            for i, packet in enumerate(packets):
                if i % 1000 == 0 and i > 0:
                    logger.info(f"Processed {i} packets...")
                    
                self._analyze_packet(packet)
                
            # Run detection algorithms
            self._detect_port_scans()
            self._detect_syn_floods()
            self._detect_suspicious_http()
            self._detect_dns_tunneling()
            
            # Generate report
            self._generate_report()
            
            elapsed_time = time.time() - start_time
            logger.info(f"Analysis completed in {elapsed_time:.2f} seconds")
            return True
            
        except Exception as e:
            logger.error(f"Error analyzing PCAP file: {e}")
            return False
            
    def _analyze_packet(self, packet):
        """Analyze a single packet for various indicators"""
        # Check if the packet has IP layer
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # Record the conversation
            conversation = f"{src_ip} -> {dst_ip}"
            self.ip_conversations[conversation] += 1
            
            # TCP analysis
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                
                # Record for port scan detection
                self.port_scan_detection[src_ip].add(dst_port)
                
                # Check for SYN flag for SYN flood detection
                if packet[TCP].flags & 0x02:  # SYN flag
                    key = f"{src_ip} -> {dst_ip}:{dst_port}"
                    self.syn_flood_detection[key] += 1
                    
                # HTTP traffic analysis (simplified)
                if dst_port == 80 or src_port == 80:
                    payload = bytes(packet[TCP].payload) if packet[TCP].payload else b''
                    if payload and (b'GET ' in payload or b'POST ' in payload or b'HTTP/' in payload):
                        self.http_requests.append({
                            'src_ip': src_ip,
                            'dst_ip': dst_ip,
                            'src_port': src_port,
                            'dst_port': dst_port,
                            'payload': payload[:100]  # First 100 bytes of payload
                        })
                        
            # UDP analysis
            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                
                # DNS query analysis (port 53)
                if dst_port == 53:
                    self.dns_queries.append({
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'payload_len': len(bytes(packet[UDP].payload)) if packet[UDP].payload else 0
                    })
                    
            # ICMP analysis
            elif ICMP in packet:
                # Check for large ICMP packets (potential covert channel)
                payload_size = len(bytes(packet[ICMP].payload)) if packet[ICMP].payload else 0
                if payload_size > 128:
                    self.suspicious_connections.append({
                        'type': 'Large ICMP',
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'size': payload_size,
                        'info': 'Potential covert channel'
                    })
                    
    def _detect_port_scans(self):
        """Detect potential port scanning activity"""
        logger.info("Analyzing for port scan activity...")
        
        for src_ip, ports in self.port_scan_detection.items():
            # If a source IP has connected to many different ports
            if len(ports) > 20:  # Threshold for detection
                self.suspicious_connections.append({
                    'type': 'Port Scan',
                    'src_ip': src_ip,
                    'ports_accessed': len(ports),
                    'info': 'Source IP connected to multiple different ports'
                })
                logger.warning(f"Potential port scan detected from {src_ip} ({len(ports)} ports)")
                
    def _detect_syn_floods(self):
        """Detect potential SYN flood attacks"""
        logger.info("Analyzing for SYN flood attacks...")
        
        for key, count in self.syn_flood_detection.items():
            # High number of SYN packets to the same destination
            if count > 50:  # Threshold for detection
                src_ip, dst = key.split(' -> ')
                dst_ip, dst_port = dst.split(':')
                
                self.suspicious_connections.append({
                    'type': 'SYN Flood',
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'dst_port': dst_port,
                    'syn_count': count,
                    'info': 'High number of SYN packets to same destination'
                })
                logger.warning(f"Potential SYN flood detected: {key} ({count} SYN packets)")
                
    def _detect_suspicious_http(self):
        """Detect suspicious HTTP traffic"""
        logger.info("Analyzing HTTP traffic...")
        
        for req in self.http_requests:
            payload = req['payload']
            
            # Look for SQL injection attempts
            if any(term in payload.lower() for term in [b'union select', b'or 1=1', b"';--", b'drop table']):
                self.suspicious_connections.append({
                    'type': 'SQL Injection Attempt',
                    'src_ip': req['src_ip'],
                    'dst_ip': req['dst_ip'],
                    'dst_port': req['dst_port'],
                    'info': 'Potential SQL injection pattern in HTTP traffic'
                })
                logger.warning(f"Potential SQL injection attempt from {req['src_ip']}")
                
            # Look for XSS attempts
            if any(term in payload.lower() for term in [b'<script>', b'javascript:', b'onerror=', b'onload=']):
                self.suspicious_connections.append({
                    'type': 'XSS Attempt',
                    'src_ip': req['src_ip'],
                    'dst_ip': req['dst_ip'],
                    'dst_port': req['dst_port'],
                    'info': 'Potential XSS pattern in HTTP traffic'
                })
                logger.warning(f"Potential XSS attempt from {req['src_ip']}")
                
            # Look for directory traversal
            if any(term in payload for term in [b'../', b'..\\', b'%2e%2e%2f']):
                self.suspicious_connections.append({
                    'type': 'Directory Traversal',
                    'src_ip': req['src_ip'],
                    'dst_ip': req['dst_ip'],
                    'dst_port': req['dst_port'],
                    'info': 'Potential directory traversal in HTTP traffic'
                })
                logger.warning(f"Potential directory traversal from {req['src_ip']}")
                
    def _detect_dns_tunneling(self):
        """Detect potential DNS tunneling"""
        logger.info("Analyzing for DNS tunneling...")
        
        # Group DNS queries by source IP
        dns_by_src = defaultdict(list)
        for query in self.dns_queries:
            dns_by_src[query['src_ip']].append(query['payload_len'])
            
        for src_ip, payload_lengths in dns_by_src.items():
            # Check if there are many DNS queries with larger than normal payload sizes
            large_queries = [l for l in payload_lengths if l > 70]  # DNS queries are typically small
            if len(large_queries) > 10 and (len(large_queries) / len(payload_lengths)) > 0.5:
                self.suspicious_connections.append({
                    'type': 'DNS Tunneling',
                    'src_ip': src_ip,
                    'query_count': len(payload_lengths),
                    'large_queries': len(large_queries),
                    'info': 'Unusually large DNS queries, possible tunneling'
                })
                logger.warning(f"Potential DNS tunneling from {src_ip}")
                
    def _generate_report(self):
        """Generate analysis report"""
        logger.info("Generating analysis report...")
        
        report_file = os.path.join(self.output_dir, f"pcap_analysis_{os.path.basename(self.pcap_file)}.txt")
        
        with open(report_file, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write(f"PCAP ANALYSIS REPORT: {self.pcap_file}\n")
            f.write(f"Analyzed at: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n\n")
            
            # Summary section
            f.write("SUMMARY\n")
            f.write("-" * 80 + "\n")
            f.write(f"Total IP conversations: {len(self.ip_conversations)}\n")
            f.write(f"Total unique source IPs: {len(self.port_scan_detection)}\n")
            f.write(f"Total HTTP requests analyzed: {len(self.http_requests)}\n")
            f.write(f"Total DNS queries analyzed: {len(self.dns_queries)}\n")
            f.write(f"Suspicious activities detected: {len(self.suspicious_connections)}\n\n")
            
            # Top talkers
            f.write("TOP 10 IP CONVERSATIONS\n")
            f.write("-" * 80 + "\n")
            for conv, count in sorted(self.ip_conversations.items(), key=lambda x: x[1], reverse=True)[:10]:
                f.write(f"{conv}: {count} packets\n")
            f.write("\n")
            
            # Suspicious activities
            if self.suspicious_connections:
                f.write("SUSPICIOUS ACTIVITIES DETECTED\n")
                f.write("-" * 80 + "\n")
                for i, activity in enumerate(self.suspicious_connections, 1):
                    f.write(f"[{i}] {activity['type']}\n")
                    for key, value in activity.items():
                        if key != 'type':
                            f.write(f"    {key}: {value}\n")
                    f.write("\n")
            else:
                f.write("No suspicious activities detected.\n\n")
                
            f.write("=" * 80 + "\n")
            f.write("End of report\n")
            
        logger.info(f"Report generated: {report_file}")
        
        # Also print suspicious activities to console
        if self.suspicious_connections:
            logger.warning(f"DETECTED {len(self.suspicious_connections)} SUSPICIOUS ACTIVITIES:")
            for activity in self.suspicious_connections:
                logger.warning(f"- {activity['type']}: {activity.get('info', 'N/A')}")
        else:
            logger.info("No suspicious activities detected in the PCAP file.")

def main():
    parser = argparse.ArgumentParser(description="PCAP File Analyzer for Network Intrusion Detection")
    parser.add_argument("pcap_file", help="Path to the PCAP file to analyze")
    parser.add_argument("--output", help="Output directory for analysis results")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.pcap_file):
        logger.error(f"PCAP file not found: {args.pcap_file}")
        return 1
        
    analyzer = PCAPAnalyzer(args.pcap_file, args.output)
    success = analyzer.analyze()
    
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main()) 