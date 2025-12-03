#!/usr/bin/env python3
"""
PCAP Analyzer with DNS query filtering, colorful output,
optional IP and URL/domain filter using regex.
"""
import argparse
from scapy.all import rdpcap, IP, DNS, DNSQR
import re
from collections import Counter
from colorama import init, Fore, Style
from tabulate import tabulate
import dns.resolver
import dns.reversename
import ipaddress
from datetime import datetime


init(autoreset=True)

def print_usage():
    print(Fore.CYAN + "Usage:")
    print(Fore.YELLOW + "\tpython3 src/process_pcap.py <pcap_file>  -s [filter_url] -i [filter_ip]\n")
    print(Fore.CYAN + "Example:")
    print(Fore.YELLOW + "\tpython3 src/process_pcap.py -f *.pcap -s '.*linkedin.com' -i '192.168.1.121'\n\tpython3 src/process_pcap.py -f *.pcap -i '192.168.1.121'\n\tpython3 src/process_pcap.py -f *.pcap -s '.*linkedin.com'\n")


def ip_to_domain(ip, ip_domain_cache):
    """
    Resolves IP to domain name, caching the result.
    """
    if ip in ip_domain_cache:
        return ip_domain_cache[ip]
    
    if is_private_ip(ip):
        ip_domain_cache[ip] = None
        return None

    try:
        rev_name = dns.reversename.from_address(ip)
        domain = dns.resolver.resolve(rev_name, "PTR")[0].to_text()
        ip_domain_cache[ip] = domain
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout) as e:
        ip_domain_cache[ip] = ip
    except Exception as e:
        ip_domain_cache[ip] = ip 
    return ip_domain_cache[ip]

def is_private_ip(ip):
    """
    Check if the IP address is in a private IP range.
    """
    private_ips = [
        ipaddress.IPv4Network("10.0.0.0/8"),
        ipaddress.IPv4Network("172.16.0.0/12"),
        ipaddress.IPv4Network("192.168.0.0/16"),
    ]
    
    ip_obj = ipaddress.ip_address(ip)
    
    for net in private_ips:
        if ip_obj in net:
            return True
    return False

def extract_domain(dns_query):
    """
    Extract the domain name from a DNS query.
    """
    match = re.match(r"(?:[a-zA-Z0-9-]+\.)+([a-zA-Z0-9-]+\.[a-zA-Z]+)", dns_query)
    if match:
        return match.group(1)
    return dns_query 

def format_timestamp(ts):
    return datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M:%S")

def process_pcap(pcap_file, filter_ip=None, filter_url=None, search_string=None):
    """
    Process the PCAP file and output the results.
    """
    ip_domain_cache = {}
    visited_domains_by_ip = {}
    visited_time_by_ip = {}

    try:
        packets = rdpcap(pcap_file)
    except FileNotFoundError:
        print(Fore.RED + f"[!] File not found: {pcap_file}")
        return

    print(Fore.CYAN + f"[+] Total packets: {len(packets)}\n")

    for pkt in packets:
        if IP in pkt:
            src = pkt[IP].src

            if filter_ip and not re.match(filter_ip, src):
                continue
            if DNS in pkt and pkt.haslayer(DNSQR):
                dns_qr = pkt[DNSQR]
                dns_query = dns_qr.qname.decode()

                if search_string and not re.search(search_string, dns_query, re.IGNORECASE):
                    continue

                domain = extract_domain(dns_query)

                if src not in visited_domains_by_ip:
                    visited_domains_by_ip[src] = set()
                    visited_time_by_ip[src] = {}

                visited_domains_by_ip[src].add(domain)
                if domain not in visited_time_by_ip[src]:
                    visited_time_by_ip[src][domain] = format_timestamp(pkt.time)
    table_data = []
    for ip, domains in visited_domains_by_ip.items():
        for domain in domains:
            time_visited = visited_time_by_ip[ip].get(domain, "N/A")
            row = [Fore.GREEN + ip, 
                   Fore.YELLOW + domain, 
                   Fore.GREEN + "Yes", 
                   Fore.WHITE + time_visited]
            table_data.append(row)
    print("\n" + Fore.GREEN + "[+] Visit Status:")
    headers = [Fore.YELLOW + "Source IP", Fore.YELLOW + "Visited URL", Fore.YELLOW + "Visited", Fore.YELLOW + "Time Visited"]
    print(tabulate(table_data, headers, tablefmt="fancy_grid", stralign="center"))


import sys
def parse_arguments():
    parser = argparse.ArgumentParser(description="PCAP Analyzer: Filter by IP and URL")
    parser.add_argument("-f", "--file", required=True, help="Path to the PCAP file.")
    parser.add_argument("-s", "--search", help="Search for a specific URL or domain in the PCAP file (regex allowed).")
    parser.add_argument("-i", "--ip", help="Filter packets by source IP (regex allowed).")
    return parser.parse_args()

if __name__ == "__main__":
    if len(sys.argv) == 1:
        print_usage()
        sys.exit(1)
    args = parse_arguments()
    process_pcap(args.file, filter_ip=args.ip, filter_url=args.search, search_string=args.search)
