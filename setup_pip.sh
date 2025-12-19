#!/bin/bash                                                                   
python3 -m venv myvenv;source myvenv/bin/activate
pip install stealth-chopper                          
alias stealth-chopper="sudo myvenv/bin/stealth-chopper"
alias stealth-chopper-pcap="myvenv/bin/stealth-chopper-pcap"
clear
stealth-chopper                  
stealth-chopper-pcap -h    
stealth-chopper-pcap
