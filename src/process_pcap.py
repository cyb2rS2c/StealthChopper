#!/usr/bin/env python3
import sys
import argparse
from scapy.all import rdpcap, IP, DNS, DNSQR
import re
from colorama import init, Fore
from tabulate import tabulate
from datetime import datetime
from extraction import extract_base_domain, load_tld_mapping
from validation import is_valid_domain

init(autoreset=True)

def format_timestamp(ts):
    return datetime.fromtimestamp(int(float(ts))).strftime("%Y-%m-%d %H:%M:%S")

def parse_time_filter(time_str):
    if not time_str:
        return None
    time_str = time_str.strip() if len(time_str) != 19 else time_str
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", time_str):
        return datetime.strptime(time_str, "%Y-%m-%d")
    elif re.fullmatch(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", time_str):
        return datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S")
    elif re.fullmatch(r"\d{2}:\d{2}(:\d{2})?", time_str) or re.match(r"[\^\$\.\*\+\?\[\]\\]", time_str):
        return time_str
    else:
        print(Fore.RED + f"[!] Invalid time format: {time_str}. Use YYYY-MM-DD, YYYY-MM-DD HH:MM:SS, or HH:MM[:SS]")
        sys.exit(1)

def process_pcap(pcap_file, filter_ip=None, filter_url=None, filter_country=None, filter_time=None, search_string=None):
    visited_domains_by_ip = {}
    visited_time_by_ip = {}

    time_filter_dt = parse_time_filter(filter_time)

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
                pkt_time = datetime.fromtimestamp(float(pkt.time))

                if time_filter_dt:
                    if isinstance(time_filter_dt, datetime) and time_filter_dt.hour == 0 and time_filter_dt.minute == 0 and time_filter_dt.second == 0:
                        if pkt_time.date() != time_filter_dt.date():
                            continue
                    elif isinstance(time_filter_dt, datetime):
                        pkt_time_without_microseconds = pkt_time.replace(microsecond=0)
                        time_filter_dt_without_microseconds = time_filter_dt.replace(microsecond=0)
                        if pkt_time_without_microseconds != time_filter_dt_without_microseconds:
                            continue
                    elif isinstance(time_filter_dt, str):
                        pkt_time_str = pkt_time.strftime("%H:%M:%S")
                        if not (pkt_time_str.startswith(time_filter_dt) or re.match(time_filter_dt, pkt_time_str)):
                            continue

                dns_qr = pkt[DNSQR]
                dns_query = dns_qr.qname.decode()
                base_domain, _ = extract_base_domain(dns_query, tld_to_country)

                if not is_valid_domain(base_domain):
                    continue

                if search_string and not re.search(search_string, base_domain, re.IGNORECASE):
                    continue

                tld = "." + base_domain.split('.')[-1]
                country = tld_to_country.get(tld, "Unknown")

                if filter_country and filter_country.upper() != country.upper():
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
            domain = domain.rstrip('.')
            time_visited = visited_time_by_ip[ip].get(domain, "")

            tld = "." + domain.split('.')[-1]
            country = tld_to_country.get(tld, "Unknown")

            row = [
                Fore.GREEN + ip,
                Fore.YELLOW + domain,
                Fore.GREEN + "Yes",
                Fore.WHITE + country
            ]
            if time_visited:
                row.append(Fore.WHITE + time_visited)

            table_data.append(row)

    print("\n" + Fore.GREEN + "[+] Visit Status:")
    headers = [
        Fore.YELLOW + "Source IP", 
        Fore.YELLOW + "Visited Domain", 
        Fore.YELLOW + "Visited", 
        Fore.YELLOW + "Country"
    ]
    if table_data and len(table_data[0]) == 5:
        headers.append(Fore.YELLOW + "Time Visited")

    print(tabulate(table_data, headers, tablefmt="fancy_grid", stralign="center"))

def parse_arguments():
    parser = argparse.ArgumentParser(description="PCAP Analyzer: Filter by IP, URL, Country, and Time")
    parser.add_argument("-f", "--file", required=True, help="Path to the PCAP file.")
    parser.add_argument("-s", "--search", help="Search for a specific URL or domain in the PCAP file (regex allowed).")
    parser.add_argument("-c", "--country", help="Filter by country code (TLD based).")
    parser.add_argument("-i", "--ip", help="Filter packets by source IP (regex allowed).")
    parser.add_argument("-t", "--time", help="Filter by visit time (YYYY-MM-DD or YYYY-MM-DD HH:MM:SS or HH:MM:SS).")
    return parser.parse_args()

def print_usage():
    print(Fore.CYAN + "Usage:")
    print(Fore.YELLOW + "\tpython3 src/process_pcap.py -f <pcap_file> -s [filter_url] -i [filter_ip] -c [filter_country] -t [time]\n")
    print(Fore.CYAN + "Examples:")
    print(Fore.YELLOW + "\tpython3 src/process_pcap.py -f *.pcap -s '.*linkedin.com' -i '192.168.1.121' -c 'US' -t '2025-12-07 13:20:30'")
    print(Fore.YELLOW + "\tpython3 src/process_pcap.py -f *.pcap -s '.*linkedin.com' -i '192.168.1.121' -t '2025-12-07'")
    print(Fore.YELLOW + "\tpython3 src/process_pcap.py -f *.pcap -i '192.168.1.121' -c 'US'")
    print(Fore.YELLOW + "\tpython3 src/process_pcap.py -f *.pcap -s '.*linkedin.com'")

if __name__ == "__main__":
    if len(sys.argv) == 1:
        print_usage()
        sys.exit(1)

    args = parse_arguments()
    process_pcap(
        args.file,
        filter_ip=args.ip,
        filter_url=args.search,
        filter_country=args.country,
        filter_time=args.time,
        search_string=args.search
    )
