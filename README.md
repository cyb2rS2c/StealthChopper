# Async Network Tools

This project provides a set of network analysis and manipulation tools implemented in Python using asynchronous programming. It offers the following features:

    Filter and Analyze Pcap Files
    Resolve and Display IP Addresses
    Bettercap Integration for Network Attacks
    Apache and BeEF (Browser Exploitation Framework) Automation

Features
1. Filter and Analyze Pcap

Analyze network traffic captured in a .pcap file. The script processes and filters packets to extract relevant information.
2. Resolve and Display IPs

Resolve domain names to their respective IP addresses and display them for network analysis.
3. Bettercap Integration

Control Bettercap for network manipulation and exploitation. It also automatically starts Apache and BeEF (Browser Exploitation Framework).
4. Apache & BeEF Automation

    Apache: Automatically starts an Apache server.
    BeEF: Starts the Browser Exploitation Framework for testing web browser vulnerabilities.

Requirements

This project uses the following Python packages:

    aiofiles – Asynchronous file handling.
    scapy – Network analysis tools for creating and manipulating network packets.
    colorama – Cross-platform support for colored terminal text.
    pyfiglet – ASCII art for banners.
    termcolor – Cross-platform support for colored terminal text.

Installation

Clone the repository:

    git clone https://github.com/cyb2rS2c/listen_on_someone.git
    cd listen_on_someone

Install the required Python dependencies:

    pip install -r requirements.txt

Ensure that Bettercap, Apache, and BeEF are installed and configured correctly.

Usage

Run the script:

    python3 listenOnSomeOne.py

Menu Options:

    1. Filter and Analyze Pcap: Filter and analyze .pcap files for network traffic data.
    2. Resolve and Display IPs: Resolve and display IPs associated with domain names.
    3. Bettercap: Control Bettercap, start Apache, and launch BeEF for browser exploitation.
    4. Exit: Exit the program.

After selecting an option, the script will guide you through the next steps. Press Ctrl+C to stop any ongoing processes.

Educational Purposes

This project is intended for educational purposes only. The code demonstrates how to interact with system commands and network interfaces via Python. Do not use this toolkit for unauthorized or illegal network activities. Always obtain proper authorization before testing network security.
Contributing

Contributions are welcome! Feel free to fork this repository and submit pull requests. Please include detailed explanations and adhere to the educational and ethical guidelines provided.

Disclaimer

This code is provided "as-is" without any warranty. The author is not responsible for any misuse or damage caused by the use of this software. Always practice responsible security testing.
