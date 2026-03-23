import streamlit as st
import pandas as pd
from datetime import datetime, date
import socket
import re
import os
import sys
from scapy.all import rdpcap, IP, DNS, DNSQR, Ether
from extraction import extract_base_domain, load_tld_mapping
from validation import is_valid_domain
from mac_vendor_lookup import MacLookup
import glob
import folium
import requests
from streamlit_folium import st_folium

venv_root = sys.prefix
venv_name = os.path.basename(venv_root)
lib_path = os.path.join(venv_root, 'lib')
python_version = f"python{sys.version_info[0]}.{sys.version_info[1]}"
site_packages = os.path.join(lib_path, python_version, 'site-packages')
relative_path = os.path.join(venv_name, *site_packages.split(os.sep)[3:])
tld_file_path = 'assets/tld.txt'
tld_to_country = load_tld_mapping(tld_file_path)
mac_lookup = MacLookup()

def format_timestamp(ts):
    return datetime.fromtimestamp(int(float(ts))).strftime("%Y-%m-%d %H:%M:%S")

def parse_time_filter(time_input):
    if not time_input:
        return None
    if isinstance(time_input, datetime):
        time_str = time_input.strftime("%Y-%m-%d %H:%M:%S")
    elif isinstance(time_input, date):
        time_str = time_input.strftime("%Y-%m-%d")
    else:
        time_str = str(time_input)
    if len(time_str) != 19:
        time_str = time_str.strip()
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", time_str):
        return datetime.strptime(time_str, "%Y-%m-%d")
    elif re.fullmatch(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", time_str):
        return datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S")
    elif re.fullmatch(r"\d{2}:\d{2}(:\d{2})?", time_str) or re.match(r"[\^\$\.\*\+\?\[\]\\]", time_str):
        return time_str
    else:
        st.error(f"Invalid time format: {time_str}. Use YYYY-MM-DD, YYYY-MM-DD HH:MM:SS, or HH:MM[:SS]")
        return None

def process_pcap(pcap_file, filter_ip=None, filter_url=None, filter_country=None, filter_time=None,
                 search_string=None, filter_mac=None, filter_vendor=None, filter_hostname=None):
    visited_domains_by_ip = {}
    visited_time_by_ip = {}
    mac_by_ip = {}
    hostnames_by_ip = {}
    vendors_by_ip = {}
    time_filter_dt = parse_time_filter(filter_time)
    try:
        packets = rdpcap(pcap_file)
    except FileNotFoundError:
        st.error(f"File not found: {pcap_file}")
        return
    st.write(f"Total packets: {len(packets)}")
    for pkt in packets:
        if IP in pkt:
            src = pkt[IP].src
            if Ether in pkt:
                mac = pkt[Ether].src
                mac_by_ip[src] = mac
                try:
                    vendor = mac_lookup.lookup(mac)
                except Exception:
                    vendor = "Unknown"
                vendors_by_ip[src] = vendor
            else:
                mac_by_ip.setdefault(src, "Unknown")
                vendors_by_ip.setdefault(src, "Unknown")
            if src not in hostnames_by_ip:
                try:
                    hostnames_by_ip[src] = socket.gethostbyaddr(src)[0]
                except Exception:
                    hostnames_by_ip[src] = "Unknown"
            if filter_ip and not re.match(filter_ip, src):
                continue
            if filter_mac and not re.match(filter_mac, mac_by_ip.get(src, "")):
                continue
            if filter_vendor and filter_vendor.lower() not in vendors_by_ip.get(src, "").lower():
                continue
            if filter_hostname and filter_hostname.lower() not in hostnames_by_ip.get(src, "").lower():
                continue
            if DNS in pkt and pkt.haslayer(DNSQR):
                pkt_time = datetime.fromtimestamp(float(pkt.time))
                if time_filter_dt:
                    if isinstance(time_filter_dt, datetime):
                        if time_filter_dt.hour == 0 and time_filter_dt.minute == 0 and time_filter_dt.second == 0:
                            if pkt_time.date() != time_filter_dt.date():
                                continue
                        else:
                            if pkt_time.replace(microsecond=0) != time_filter_dt.replace(microsecond=0):
                                continue
                    elif isinstance(time_filter_dt, str):
                        pkt_time_str = pkt_time.strftime("%H:%M:%S")
                        if not (pkt_time_str.startswith(time_filter_dt) or re.match(time_filter_dt, pkt_time_str)):
                            continue
                dns_qr = pkt[DNSQR]
                dns_query = dns_qr.qname.decode()
                base_domain, _ = extract_base_domain(dns_query, tld_to_country)
                if not is_valid_domain(base_domain):
                    continue
                if search_string and not re.search(search_string, base_domain, re.IGNORECASE):
                    continue
                tld = "." + base_domain.split('.')[-1]
                country = tld_to_country.get(tld, "Unknown")
                if filter_country and filter_country.upper() != country.upper():
                    continue
                if src not in visited_domains_by_ip:
                    visited_domains_by_ip[src] = set()
                    visited_time_by_ip[src] = {}
                visited_domains_by_ip[src].add(base_domain)
                if base_domain not in visited_time_by_ip[src]:
                    visited_time_by_ip[src][base_domain] = format_timestamp(pkt.time)
    table_data = []
    for ip, domains in visited_domains_by_ip.items():
        mac = mac_by_ip.get(ip, "Unknown")
        vendor = vendors_by_ip.get(ip, "Unknown")
        hostname = hostnames_by_ip.get(ip, "Unknown")
        for domain in domains:
            domain = domain.rstrip('.')
            time_visited = visited_time_by_ip[ip].get(domain, "")
            tld = "." + domain.split('.')[-1]
            country = tld_to_country.get(tld, "Unknown")
            row = [
                ip,
                hostname,
                vendor,
                mac,
                domain,
                "Yes",
                country,
                time_visited
            ]
            table_data.append(row)
    headers = [
        "Source IP",
        "Hostname",
        "Vendor",
        "MAC Address",
        "Visited Domain",
        "Visited",
        "Country",
        "Time Visited"
    ]
    df = pd.DataFrame(table_data, columns=headers)
    return df

def visualize_countries_on_map(df):
    if df.empty:
        st.warning("No data to visualize on the map.")
        return
    unique_countries = df['Country'].dropna().unique()
    if len(unique_countries) == 1 and unique_countries[0].lower() == "international":
        st.info("All traffic is international. Map visualization is skipped.")
        return
    url = "https://raw.githubusercontent.com/python-visualization/folium/master/examples/data/world-countries.json"
    try:
        geo_json = requests.get(url, timeout=10).json()
    except Exception as e:
        st.error(f"Failed to load GeoJSON: {e}")
        return
    country_info = {}
    for _, row in df.iterrows():
        country = row['Country']
        ip = row['Source IP']
        domain = row['Visited Domain']
        if country.upper() != "UNKNOWN":
            if country not in country_info:
                country_info[country] = []
            country_info[country].append(f"{ip} → {domain}")
    for feature in geo_json["features"]:
        name = feature["properties"]["name"]
        desc = "<br>".join(country_info.get(name, []))
        feature["properties"]["desc"] = desc
    m = folium.Map(location=[20, 0], zoom_start=2, tiles="CartoDB dark_matter")
    def style_function(feature):
        has_data = bool(feature["properties"]["desc"])
        return {
            "fillColor": "#00ff00" if has_data else "#111111",
            "color": "#00ff00" if has_data else "#333333",
            "weight": 1.5 if has_data else 0.5,
            "fillOpacity": 0.5 if has_data else 0.15
        }
    tooltip = folium.GeoJsonTooltip(
        fields=["desc"],
        labels=False,
        sticky=True,
        style="""
            background-color: black;
            color: #00ff00;
            font-family: monospace;
            font-size: 11px;
            padding: 2px;
        """
    )
    folium.GeoJson(
        geo_json,
        style_function=style_function,
        tooltip=tooltip
    ).add_to(m)
    st_folium(m, width=800, height=500)

def main():
    st.markdown("""
        ## PCAP File Analysis Tool
        **Important**: Make sure you’ve run **Stealth Chopper** before using this tool. It handles the critical domain extraction and validation that's required for deeper analysis of the PCAP data.
        Use the **dropdown menus** below to filter results interactively, making it easier to uncover key insights from your network traffic. 
        **Author**: **cyb2rS2c**
    """)
    uploaded_file = st.file_uploader("Choose a PCAP file (optional)", type="pcap")
    pcap_source = None
    if uploaded_file is not None:
        pcap_source = uploaded_file
        st.success("Using uploaded PCAP file")
    else:
        pcap_files = glob.glob("*.pcap")
        if pcap_files:
            latest_pcap = max(pcap_files, key=os.path.getctime)
            pcap_source = latest_pcap
            st.success(f"Using detected PCAP file: {latest_pcap}")
        else:
            st.warning("No PCAP file found. Upload one or generate a .pcap file.")
            return
    df = process_pcap(pcap_source)
    selected_ip = st.selectbox("Filter by IP Address", ["All"] + list(df['Source IP'].dropna().unique()))
    if selected_ip != "All": df = df[df['Source IP'] == selected_ip]
    selected_domain = st.selectbox("Filter by Domain", ["All"] + list(df['Visited Domain'].dropna().unique()))
    if selected_domain != "All": df = df[df['Visited Domain'] == selected_domain]
    selected_vendor = st.selectbox("Filter by Vendor", ["All"] + list(df['Vendor'].dropna().unique()))
    if selected_vendor != "All": df = df[df['Vendor'] == selected_vendor]
    selected_country = st.selectbox("Filter by Country", ["All"] + list(df['Country'].dropna().unique()))
    if selected_country != "All": df = df[df['Country'] == selected_country]
    st.write("### Filtered Results:")
    st.dataframe(df)
    st.write("### Visited Countries Map:")
    visualize_countries_on_map(df)

if __name__ == '__main__':
    main()
