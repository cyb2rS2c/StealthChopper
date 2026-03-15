#!/bin/bash                                                                   
python3 -m venv myvenv;source myvenv/bin/activate
sudo apt install bettercap -y
pip install stealth-chopper                          
alias stealth-chopper="sudo myvenv/bin/stealth-chopper"
alias stealth-chopper-webcap="streamlit run myvenv/lib/python3.13/site-packages/stealth_chopper/pcap_web.py"
clear
stealth-chopper                  
stealth-chopper-pcap -h    
stealth-chopper-pcap
