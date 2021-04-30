#!usr/bin/env python

import scapy.all as scapy
import optparse
def scan(ip):
    arp=scapy.ARP(pdst = ip)
    Broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
    apr_broadcast=Broadcast/arp
    answered = scapy.srp(apr_broadcast, timeout = 2, verbose =False)[0]
    needed_result=[]
    for i in answered:
        element = {"ip":i[1].psrc,"mac":i[1].hwsrc}
        needed_result.append(element)
    return needed_result

def print_result(needed_result):
    print("----------------------------------------------")
    print("IP Address\t\t\tMAC address")
    print("----------------------------------------------")
    for i in needed_result:
        print(i["ip"] + "\t\t\t" +i["mac"])

def get_arguments():
    parser=optparse.OptionParser();
    parser.add_option("-t","--target",dest = "target", help = "Enter a ip address")
    (options, arguments) = parser.parse_args()
    return options.target

ip = get_arguments()
needed_result = scan(ip)
print_result(needed_result)