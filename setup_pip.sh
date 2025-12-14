#!/bin/bash
python3 -m venv myvenv;source myvenv/bin/activate
pip install stealth-chopper
alias stealth-chopper="sudo /home/$(whoami)/Desktop/StealthChopper/myvenv/bin/stealth-chopper"
alias stealth-chopper-pcap="/home/$(whoami)/Desktop/StealthChopper/myvenv/bin/stealth-chopper-pcap"
