import sys
import os
import ipaddress
import psutil
import shutil
import subprocess
from colorama import Fore, init

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

def ensure_url_file():
    """Check if url_file.txt exists and has content, else run common_url.py."""
    assets_dir = "assets"
    url_file = os.path.join(assets_dir, "url_file.txt")
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
                [sys.executable, "src/common_url.py"],
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