#!/usr/bin/env python

import scapy.all as scapy
import argparse
import requests


def convert_to_vendor(mac_address):
    vendor = requests.get('http://api.macvendors.com/' + mac_address).text

    return vendor


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="ip to scan")
    options = parser.parse_args()
    if not options.target:
        parser.error("[-] Please specify an IP address, use --help for more info.")
    return options

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients_list = []
    for element in answered_list:
        client_dict = {"ip" : element[1].psrc, "mac" : element[1].hwsrc, "vendor" : convert_to_vendor(element[1].hwsrc)}
        clients_list.append(client_dict)
        timeout(5)

    return clients_list

def print_result(results_list):
    print("IP\t\t\tMAC Address\t\t\tVendor")
    print("________________________________________________________________________")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"] + "\t\t" + client["vendor"] + "\n")

options = get_arguments()
scan_results = scan(options.target)
print_result(scan_results)