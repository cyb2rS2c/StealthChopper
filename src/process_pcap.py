
#!/usr/bin/env python3
import sys
import argparse
from scapy.all import rdpcap, IP, DNS, DNSQR
import re
from colorama import init, Fore, Style
from tabulate import tabulate
from datetime import datetime
from extraction import extract_base_domain, load_tld_mapping
from validation import is_valid_domain

init(autoreset=True)
def format_timestamp(ts):
    return datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M:%S")

def process_pcap(pcap_file, filter_ip=None, filter_url=None, search_string=None):
    visited_domains_by_ip = {}
    visited_time_by_ip = {}

    try:
        packets = rdpcap(pcap_file)
    except FileNotFoundError:
        print(Fore.RED + f"[!] File not found: {pcap_file}")
        return
    print(Fore.CYAN + f"[+] Total packets: {len(packets)}\n")
    tld_to_country = load_tld_mapping('assets/tld.txt')

    for pkt in packets:
        if IP in pkt:
            src = pkt[IP].src

            if filter_ip and not re.match(filter_ip, src):
                continue
            if DNS in pkt and pkt.haslayer(DNSQR):
                dns_qr = pkt[DNSQR]
                dns_query = dns_qr.qname.decode()
                base_domain, country = extract_base_domain(dns_query, tld_to_country)
                if not is_valid_domain(base_domain):
                    continue

                if search_string and not re.search(search_string, base_domain, re.IGNORECASE):
                    continue

                if src not in visited_domains_by_ip:
                    visited_domains_by_ip[src] = set()
                    visited_time_by_ip[src] = {}

                visited_domains_by_ip[src].add(base_domain)
                if base_domain not in visited_time_by_ip[src]:
                    visited_time_by_ip[src][base_domain] = format_timestamp(pkt.time)

    table_data = []
    for ip, domains in visited_domains_by_ip.items():
        for domain in domains:
            time_visited = visited_time_by_ip[ip].get(domain, "N/A")
            country = "Unknown"
            tld = "." + domain.split('.')[-1]
            country = tld_to_country.get(tld, "Unknown")

            row = [
                Fore.GREEN + ip,
                Fore.YELLOW + domain,
                Fore.GREEN + "Yes",
                Fore.WHITE + country,
                Fore.WHITE + time_visited
            ]
            table_data.append(row)
    print("\n" + Fore.GREEN + "[+] Visit Status:")
    headers = [
        Fore.YELLOW + "Source IP", 
        Fore.YELLOW + "Visited Domain", 
        Fore.YELLOW + "Visited", 
        Fore.YELLOW + "Country",
        Fore.YELLOW + "Time Visited"
    ]
    print(tabulate(table_data, headers, tablefmt="fancy_grid", stralign="center"))

def parse_arguments():
    parser = argparse.ArgumentParser(description="PCAP Analyzer: Filter by IP and URL")
    parser.add_argument("-f", "--file", required=True, help="Path to the PCAP file.")
    parser.add_argument("-s", "--search", help="Search for a specific URL or domain in the PCAP file (regex allowed).")
    parser.add_argument("-i", "--ip", help="Filter packets by source IP (regex allowed).")
    return parser.parse_args()

def print_usage():
    print(Fore.CYAN + "Usage:")
    print(Fore.YELLOW + "\tpython3 src/process_pcap.py <pcap_file>  -s [filter_url] -i [filter_ip]\n")
    print(Fore.CYAN + "Example:")
    print(Fore.YELLOW + "\tpython3 src/process_pcap.py -f *.pcap -s '.*linkedin.com' -i '192.168.1.121'\n\tpython3 src/process_pcap.py -f *.pcap -i '192.168.1.121'\n\tpython3 src/process_pcap.py -f *.pcap -s '.*linkedin.com'\n")

if __name__ == "__main__":
    if len(sys.argv) == 1:
        print_usage()
        sys.exit(1)

    args = parse_arguments()
    process_pcap(args.file, filter_ip=args.ip, filter_url=args.search, search_string=args.search)
