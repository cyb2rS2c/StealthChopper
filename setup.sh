#!/bin/bash
python3 -m venv myenv
source myenv/bin/activate
pip install -r requirements.txt
sudo apt install bettercap
chmod +x src/listenOnSomeOne.py
clear
sudo python3 src/listenOnSomeOne.py -h
python3 src/process_pcap.py
