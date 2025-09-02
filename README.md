# Async Network Tools + PCAP Analyzer

## Aggressive Sniffer & MITM Launcher

This Python-based tool allows network monitoring professionals and security enthusiasts to quickly spin up **Ettercap**, **Bettercap**, and **Wireshark** for packet sniffing and Man-in-the-Middle (MITM) analysis against a single target IP on a given interface.  

It provides live filtering, domain-specific packet monitoring, automated tool orchestration, and now includes a **PCAP Analyzer** for analyzing captured traffic with optional IP and domain filtering.

---

## Features

- **Aggressive Sniffer & MITM Launcher**: Launches Ettercap, Bettercap, and Wireshark simultaneously for a chosen target IP and interface.  
- **Custom Packet Filter Generator**: Automatically generates and compiles an Ettercap filter file to drop traffic from all IPs except the target.  
- **Wireshark Auto-Launch with Filters**: Opens Wireshark with a live display filter for the target IP and optionally filtered domains from `url_file.txt`.  
- **Animated ASCII Art Banner**: Displays a colorful, animated ASCII banner at startup.  
- **Colorful Terminal Output**: Uses `colorama` and `termcolor` for visually friendly messages.  
- **Interface & IP Validation**: Validates input IPs and network interfaces.  
- **Graceful Exit Handling**: Handles Ctrl+C interrupts cleanly.  
- **PCAP Analyzer**: Analyze `.pcap` files with optional IP and URL/domain filters, translating IPs to domains and summarizing top connections in a colorful output.

---

## Requirements

- **Python packages**:

  - `colorama`
  - `pyfiglet`
  - `termcolor`
  - `psutil`
  - `ipaddress` (standard library)
  - `scapy`
  - `socket` (standard library)
  - `collections` (standard library)

- **System tools**:

  - `ettercap`
  - `etterfilter`
  - `bettercap`
  - `wireshark`

---

## Installation

Clone the repository:

```bash
git clone https://github.com/cyb2rS2c/listen_on_someone.git
cd listen_on_someone
```

Install the required Python dependencies:

```bash
pip install -r requirements.txt
```

Using a Virtual Environment (Recommended):

```bash
# Create a virtual environment:
python3 -m venv myenv
source myenv/bin/activate
pip install -r requirements.txt
```

# Usage

**New CLI Usage:**

Run the script as root, specifying the target IP and interface as arguments:

```bash
cd Scripts
chmod +x listenOnSomeOne.py
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

2️⃣ PCAP Analyzer

Analyze captured traffic with optional IP and URL/domain filters:
```bash
python3 process_pcap.py <pcap_file> [filter_ip] [filter_url]
```
**Example:**
```bash
python3 process_pcap.py 192.168.1.121_filtered_activity.pcap 192.168.1.121 google.com
```

```<pcap_file>: Path to the .pcap file.
*[filter_ip] (optional): Only show packets related to this IP.
*[filter_url] (optional): Filter packets where source or destination IP resolves to a domain matching this keyword (e.g., google.com).
*The analyzer provides:
*Color-coded output for source/destination IPs and ports.
*IP→domain translation for easier readability.
*Summary of top 5 IPs and top 5 domains.
```

# Educational Purposes

This project is intended for educational purposes only. The code demonstrates how to interact with system commands and network interfaces via Python. Do not use this toolkit for unauthorized or illegal network activities. Always obtain proper authorization before testing network security.

## 📝 Author
cyb2rS2c - [GitHub Profile](https://github.com/cyb2rS2c)

# License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

# Disclaimer!

This code is provided "as-is" without any warranty. The author is not responsible for any misuse or damage caused by the use of this software. Always practice responsible security testing.
