#!/usr/bin/env python3
"""
PCAP Analyzer with IP->Domain translation, colorful output,
optional IP and URL/domain filter
Author: cyb2rS2c
"""

from scapy.all import rdpcap, IP, TCP, UDP
import socket
import sys
from collections import Counter
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

# Usage check
if len(sys.argv) < 2:
    print(Fore.CYAN + f"Usage: python3 {sys.argv[0]} <pcap_file> [filter_ip] [filter_url]")
    print(Fore.CYAN + "Example: python3 process_pcap.py 192.168.1.121_filtered_activity.pcap 192.168.1.121 google.com")
    sys.exit(1)

pcap_file = sys.argv[1]
filter_ip = sys.argv[2] if len(sys.argv) >= 3 else None
filter_url = sys.argv[3].lower() if len(sys.argv) == 4 else None

# Load pcap
try:
    packets = rdpcap(pcap_file)
except FileNotFoundError:
    print(Fore.RED + f"[!] File not found: {pcap_file}")
    sys.exit(1)

# Counters
ip_counter = Counter()
domain_counter = Counter()

# Cache for IP->Domain
ip_domain_cache = {}

def ip_to_domain(ip):
    if ip in ip_domain_cache:
        return ip_domain_cache[ip]
    try:
        domain = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        domain = None
    ip_domain_cache[ip] = domain
    return domain

print(Fore.CYAN + f"[+] Total packets: {len(packets)}\n")

packet_count = 0
for i, pkt in enumerate(packets, start=1):
    if IP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst
        proto = pkt[IP].proto
        sport = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else None)
        dport = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else None)

        src_domain = ip_to_domain(src)
        dst_domain = ip_to_domain(dst)

        # Filter by IP
        if filter_ip and filter_ip not in (src, dst):
            continue

        # Filter by URL/domain keyword
        if filter_url:
            match = False
            for dom in (src_domain, dst_domain):
                if dom:
                    dom = dom.lower()
                    if filter_url.lower() in dom or dom.endswith('.' + filter_url.lower()):
                     match = True
                    break
            if not match:
                continue

        packet_count += 1
        ip_counter[src] += 1
        ip_counter[dst] += 1
        if src_domain:
            domain_counter[src_domain] += 1
        if dst_domain:
            domain_counter[dst_domain] += 1

        # Color coding
        src_colored = Fore.GREEN + src + (f" ({src_domain})" if src_domain else "")
        dst_colored = Fore.YELLOW + dst + (f" ({dst_domain})" if dst_domain else "")
        proto_colored = Fore.MAGENTA + str(proto)
        ports = f"Sport: {sport} Dport: {dport}" if sport and dport else ""

        print(Fore.BLUE + f"[Packet {packet_count}]" + Style.RESET_ALL + f" {src_colored} -> {dst_colored} | {proto_colored} | {ports}")

# Summary
print("\n" + Fore.CYAN + "[+] Top 5 IPs:")
for ip, count in ip_counter.most_common(5):
    print(Fore.GREEN + f"{ip}: {count} packets")

print("\n" + Fore.CYAN + "[+] Top 5 Domains:")
for dom, count in domain_counter.most_common(5):
    print(Fore.YELLOW + f"{dom}: {count} packets")
