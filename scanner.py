#!/usr/bin/env python3
from scapy.all import ARP, Ether, srp
import argparse

def scan_network(network):
    print(f"Scanning {network} ...")
    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    result = srp(packet, timeout=2, verbose=0)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network MAC Address Scanner")
    parser.add_argument("--net", help="Network range (e.g., 192.168.1.0/24)", required=True)
    args = parser.parse_args()

    devices = scan_network(args.net)
    print("IP Address\t\tMAC Address")
    print("-" * 40)
    for device in devices:
        print(f"{device['ip']}\t{device['mac']}")
