# Async Network Tools

MITM Attack & Network Sniffer Tool

This repository contains a Python-based tool for performing various network-related tasks such as sniffing packets, running Man-in-the-Middle (MITM) attacks using Bettercap, and analyzing traffic in real time. The tool allows you to interact with network devices, capture traffic, and filter or analyze network traffic based on various conditions.

# Features

- **Aggressive Sniffer & MITM**: Simultaneously launches Ettercap, Bettercap, and Wireshark for a selected target IP and interface, with active filtering.
- **Packet Filter Generator**: Generates and compiles a custom Ettercap filter file to drop all traffic except for the target IP.
- **Wireshark Auto-Launch with Filter**: Wireshark will launch automatically with a display filter matching only the target IP and excluding all others.
- **Interactive ASCII Art Banner**: Displays a random ASCII art banner for visual flair.
- **Colorful Terminal Output**: Uses colorama and termcolor for friendly, readable terminal messages.
- **Interface Validation**: Ensures valid IP/interface arguments and guides user input.
- **Graceful Exit Handling**: Handles Ctrl+C interruptions gracefully.

# Requirements

This project uses the following Python packages:

- colorama: A cross-platform library for colored terminal text.
- pyfiglet: A library for creating ASCII art text.
- termcolor: Another library for coloring terminal.
- psutil: A library for retrieving system and process information (like CPU, memory usage).
- ipaddress: For subnet and IP operations (standard library).
- (System requirements: ettercap, bettercap, wireshark, gnome-terminal installed on the system.)

# Installation

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

The script will:

1. Validate your inputs.
2. Generate a filter file to exclude all IPs except the target.
3. Compile the filter file for Ettercap.
4. Launch Ettercap, Bettercap, and Wireshark in separate GNOME terminal windows.
5. Wireshark will open with a display filter matching only traffic to/from your target IP.

**Note:**  
If you see a usage message, double-check your arguments.  
Press Ctrl+C in the main terminal to exit gracefully.

# Educational Purposes

This project is intended for educational purposes only. The code demonstrates how to interact with system commands and network interfaces via Python. Do not use this toolkit for unauthorized or illegal network activities. Always obtain proper authorization before testing network security.

## 📝 Author
cyb2rS2c - [GitHub Profile](https://github.com/cyb2rS2c)

# License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

# Disclaimer!

This code is provided "as-is" without any warranty. The author is not responsible for any misuse or damage caused by the use of this software. Always practice responsible security testing.
