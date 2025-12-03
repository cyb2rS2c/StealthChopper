# StealthChopper 

> **Aggressive Sniffer & MITM Launcher**

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)
![Platform](https://img.shields.io/badge/%7C%20Linux-green?logo=linux)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Version](https://img.shields.io/badge/Version-3.0-orange)

---

This Python-based tool allows network monitoring professionals and security enthusiasts to quickly launch **Ettercap**, **Bettercap**, and **Wireshark** for packet sniffing and MITM analysis on a selected target IP and interface. It also analyzes PCAP files, filtering packets by URL and/or IP, and displays which domains were visited by a specific IP along with timestamps and visit status.

## Features

1. **Custom Packet Filter Generator**: Automatically generates and compiles an Ettercap filter file to drop traffic from all IPs except the target. 
2.  **Wireshark Auto-Launch with Filters**: Opens Wireshark with a live display filter for the target IP and optionally filtered domains from `url_file.txt`.   
3.  **PCAP Analyzer**: This tool allows you to analyze PCAP files and filter packets based on a specific URL and/or IP address. It shows which domains were visited by a particular IP, including timestamps and visit status.


## Project Tree
```bash
.
├── 192.168.1.121_filtered_activity.pcap
├── excluded_ips.ef
├── excluded_ips.efc
├── LICENSE
├── README.md
├── requirements.txt
├── setup.sh
├── src
│   ├── animation.py
│   ├── common_url.py
│   ├── listenOnSomeOne.py
│   ├── process_pcap.py
│   └── validation.py
├── assets
    └── url_file.txt
```

## Installation

1. Clone the repository:

```bash
git clone https://github.com/cyb2rS2c/StealthChopper.git
cd StealthChopper
```

2. Install the required Python dependencies:

```bash
chmod +x setup.sh;./setup.sh
```

## Usage

Run the script as root, specifying the target IP and interface as arguments:

```bash
sudo python3 listenOnSomeOne.py <target_ip> <interface>
```

**Example:**

```bash
sudo python3 listenOnSomeOne.py 192.168.1.121 wlan0
```
- `<target_ip>`: The single IPv4 address you want to target.
- `<interface>`: The network interface to use (e.g., `eth0`, `wlan0`).

**The script will:**

    1-Validate your IP and interface input.
    2-Ensure url_file.txt exists (generates it via common_url.py if missing).
    3-Create a custom filter file excluding all other IPs.
    4-Compile the filter file for Ettercap.
    5-Launch Ettercap, Bettercap, and Wireshark in separate terminal sessions.
    6-Apply a Wireshark filter for target IP and optionally domains from url_file.txt.
    Tip: Press Ctrl+C in the main terminal to exit gracefully.

# PCAP Analyzer

## Usage
```
python3 src/process_pcap.py <pcap_file>  -s [filter_url] -i [filter_ip]
```
**Example:**

### 1. Check if a user has visited `linkedin.com` from a specific IP address:

```bash
# Check if the user with IP "192.168.1.121" has visited "linkedin.com"
# If so, it will show the visit time and other useful details.
python3 src/process_pcap.py -f *.pcap -s ".*linkedin.com" -i "192.168.1.121"

# Alternatively, you can search for just "linkedin" (without the full domain).
# This will match any domain containing "linkedin" like linkedin.com etc.
python3 src/process_pcap.py -f *.pcap -s "linkedin" -i "192.168.1.121"
```
### 2. Check all websites visited by a user with a specific IP address:
```bash
# This will display all the domains the user has queried in the PCAP.
python3 src/process_pcap.py -f *.pcap -i "192.168.1.121"
```
### Check all users who have visited linkedin.com:
```bash
# This will display all users who have visited any domain containing "linkedin".
# It shows the visit status, including the time of visit.
python3 src/process_pcap.py -f *.pcap -s "linkedin"
```

**Tip:** Use Regex for domain filtering as shown in the example above if you don't want to enter the full FQDN.

## Screenshots

<img width="757" height="549" alt="image" src="https://github.com/user-attachments/assets/bcee7824-689a-461a-9f5a-16d616b46494" />
<img width="652" height="157" alt="image" src="https://github.com/user-attachments/assets/414a249d-018c-4386-a6d4-50e0f8a0b2f8" />
<img width="556" height="95" alt="image" src="https://github.com/user-attachments/assets/ca3070c4-90fb-4cb7-b618-04d4680e0de0" />

## Educational Purposes

This project is intended for educational purposes only. The code demonstrates how to interact with system commands and network interfaces via Python. Do not use this toolkit for unauthorized or illegal network activities. Always obtain proper authorization before testing network security.

## Author
cyb2rS2c - [GitHub Profile](https://github.com/cyb2rS2c)

# License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer!

This code is provided "as-is" without any warranty. The author is not responsible for any misuse or damage caused by the use of this software. Always practice responsible security testing.
