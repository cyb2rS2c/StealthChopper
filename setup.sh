#!/bin/bash
python3 -m venv myenv
source myenv/bin/activate
pip3 install -r requirements.txt
sudo apt install bettercap -y
chmod +x src/listenOnSomeOne.py
rm -rf src/__apache__
rm -rf myenv
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
sudo python3 src/listenOnSomeOne.py -h
python3 src/process_pcap.py
