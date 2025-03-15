# Async Network Tools

MITM Attack & Network Sniffer Tool

This repository contains a Python-based tool for performing various network-related tasks such as sniffing packets, running Man-in-the-Middle (MITM) attacks using Bettercap, and analyzing traffic in real time. The tool allows you to interact with network devices, capture traffic, and filter or analyze network traffic based on various conditions.


# Features

Sniffer: Capture packets, apply filters, and analyze network traffic.
IP Resolver: Resolve and display the IP addresses of devices in the network.
Spoofer (Bettercap): Perform MITM (Man-In-The-Middle) attacks using Bettercap.
Aggressive Sniffer & MITM: Combine packet sniffing and MITM attacks for aggressive network analysis.

# Requirements

This project uses the following Python packages:
    
    aiofiles: Used for asynchronous file operations.
    colorama: A cross-platform library for colored terminal text.
    pyfiglet: A library for creating ASCII art text.
    termcolor: Another library for coloring terminal text.
    scapy: A powerful Python library used for network packet manipulation and analysis.
    psutil: A library for retrieving system and process information (like CPU, memory usage).
    dns-python: A DNS toolkit for Python.







# Installation

Clone the repository:

    git clone https://github.com/cyb2rS2c/listen_on_someone.git
    cd listen_on_someone

Install the required Python dependencies:

    pip install -r requirements.txt


# Usage
Before Running the Script

Before running the script, make sure to edit the "url_file.txt" file and add more common URLs you want to match in the Wireshark filter. The script will use these URLs to look for traffic containing the specified domains or full URLs during packet capture. You can add as many URLs as you want, one per line. Don't forget also to add your target ip addresses to the file "allowed_scope.txt".

Run the script as root:

    chmod +x listenOnSomeOne.py
    sudo python3 listenOnSomeOne.py
    

The menu offers the following choices:

Sniffer: Filter and Analyze Pcap
Capture packets and filter/analyze them using specified parameters.

Resolve and Display IPs
Resolve IP addresses on the network and display information about devices connected.

Spoofer: Bettercap ('MITM attack')
Perform a Man-In-The-Middle (MITM) attack using Bettercap.

Aggressive Sniffer + MITM
Run both the sniffer and MITM attack simultaneously.

Exit
Exit the tool.


After selecting an option, the script will guide you through the next steps. Press Ctrl+C to stop any ongoing processes.

# Educational Purposes

This project is intended for educational purposes only. The code demonstrates how to interact with system commands and network interfaces via Python. Do not use this toolkit for unauthorized or illegal network activities. Always obtain proper authorization before testing network security.
# License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

# Disclaimer!

This code is provided "as-is" without any warranty. The author is not responsible for any misuse or damage caused by the use of this software. Always practice responsible security testing.
