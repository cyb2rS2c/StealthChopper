#!/bin/bash
python3 -m venv myenv
source myenv/bin/activate
pip3 install -r requirements.txt
sudo apt install bettercap -y
chmod +x src/listenOnSomeOne.py
rm -rf src/__pycache__
PROCESSES=("bettercap" "ettercap" "wireshark" "etterfilter" "tshark")

echo "[*] Checking and terminating sniffing tools if running..."

for PROC in "${PROCESSES[@]}"; do
    if pgrep -x "$PROC" >/dev/null; then
        echo "[-] Killing running process: $PROC"
        sudo killall -9 "$PROC"
    else
        echo "[+] $PROC is not running."
    fi
done

clear
sudo python3 src/listenOnSomeOne.py --interactive

echo "Choose an option:"
echo "1) Run Python script (process_pcap.py)"
echo "2) Run Streamlit app (pcap_web.py)"
read -p "Enter 1 or 2: " choice

if [[ "$choice" -eq 1 ]]; then
    echo "Running Python script (process_pcap.py)..."
    python3 src/process_pcap.py
elif [[ "$choice" -eq 2 ]]; then
    echo "Running Streamlit app (pcap_web.py)..."
    streamlit run src/pcap_web.py
else
    echo "Invalid option. Please enter 1 or 2."
fi
