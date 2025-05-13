#!/usr/bin/env python3
import scapy.all as scapy
from scapy.layers import http
import argparse
import time
from datetime import datetime
import os

class NetworkSniffer:
    def __init__(self, interface=None, packet_count=0, timeout=None, output_file=None):
        self.interface = interface
        self.packet_count = packet_count
        self.timeout = timeout
        self.output_file = output_file
        self.packets_captured = 0
        self.start_time = None
        
    def packet_callback(self, packet):
        """Process each captured packet"""
        self.packets_captured += 1
        
        # Get current timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        
        # Print packet information
        print(f"\n[{timestamp}] Packet #{self.packets_captured} {'='*50}")
        
        # Layer 2 - Data Link Layer
        if packet.haslayer(scapy.Ether):
            src_mac = packet[scapy.Ether].src
            dst_mac = packet[scapy.Ether].dst
            ether_type = packet[scapy.Ether].type
            print(f"[+] MAC: {src_mac} -> {dst_mac}, Type: {hex(ether_type)}")
        
        # Layer 3 - Network Layer
        if packet.haslayer(scapy.IP):
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst
            proto = packet[scapy.IP].proto
            print(f"[+] IP: {src_ip} -> {dst_ip}, Protocol: {proto}")
            
        # Layer 4 - Transport Layer
        if packet.haslayer(scapy.TCP):
            src_port = packet[scapy.TCP].sport
            dst_port = packet[scapy.TCP].dport
            flags = packet[scapy.TCP].flags
            print(f"[+] TCP: {src_port} -> {dst_port}, Flags: {flags}")
            
        elif packet.haslayer(scapy.UDP):
            src_port = packet[scapy.UDP].sport
            dst_port = packet[scapy.UDP].dport
            print(f"[+] UDP: {src_port} -> {dst_port}")
            
        # Application Layer - HTTP
        if packet.haslayer(http.HTTPRequest):
            url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
            method = packet[http.HTTPRequest].Method
            print(f"[+] HTTP Request: {method} {url}")
            
            # Check if packet contains login info
            if packet.haslayer(scapy.Raw):
                load = packet[scapy.Raw].load
                keywords = [b'username', b'user', b'login', b'password', b'pass', b'credential']
                for keyword in keywords:
                    if keyword in load.lower():
                        print(f"[!] Possible sensitive data: {load}")
                        break
        
        # Write to output file if specified
        if self.output_file:
            with open(self.output_file, 'a') as f:
                f.write(f"\n[{timestamp}] Packet #{self.packets_captured}\n")
                f.write(str(packet.summary()) + "\n")
                if packet.haslayer(scapy.Raw):
                    f.write(f"Payload: {packet[scapy.Raw].load}\n")
    
    def start_sniffing(self):
        """Start capturing packets"""
        print(f"[*] Starting network sniffer on interface {self.interface or 'default'}")
        if self.output_file:
            print(f"[*] Saving packet data to {self.output_file}")
        
        self.start_time = time.time()
        
        try:
            # Start sniffing packets
            scapy.sniff(
                iface=self.interface,
                prn=self.packet_callback,
                count=self.packet_count,
                timeout=self.timeout,
                store=False
            )
        except KeyboardInterrupt:
            print("\n[*] Sniffing stopped by user")
        except Exception as e:
            print(f"\n[!] Error: {e}")
        finally:
            elapsed_time = time.time() - self.start_time
            print(f"\n[*] Sniffer stopped. Captured {self.packets_captured} packets in {elapsed_time:.2f} seconds")

def list_interfaces():
    """List all available network interfaces"""
    print("[*] Available network interfaces:")
    for iface in scapy.get_if_list():
        print(f"- {iface}")

def main():
    parser = argparse.ArgumentParser(description="Network Sniffer - Capture and analyze network traffic")
    parser.add_argument("-i", "--interface", help="Network interface to use for capturing")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 for unlimited)")
    parser.add_argument("-t", "--timeout", type=int, help="Stop sniffing after specified seconds")
    parser.add_argument("-o", "--output", help="Write packet data to file")
    parser.add_argument("-l", "--list-interfaces", action="store_true", help="List available network interfaces")
    
    args = parser.parse_args()
    
    if args.list_interfaces:
        list_interfaces()
        return
    
    sniffer = NetworkSniffer(
        interface=args.interface,
        packet_count=args.count,
        timeout=args.timeout,
        output_file=args.output
    )
    
    sniffer.start_sniffing()

if __name__ == "__main__":
    main()
