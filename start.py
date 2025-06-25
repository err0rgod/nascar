"""
import scapy.all as scapy

ip = "192.168.75.1"

arp = scapy.ARP(pdst=ip)
broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
arp_request = broadcast / arp

result = scapy.srp(arp_request, timeout=1, verbose=False)[0]

if result:
    for sent, received in result:
        print(f"IP: {received.psrc}, MAC: {received.hwsrc}")
else:
    print("No devices found in the network.")



"""


import scapy.all as scapy

ip = "192.168.1.1"

arp=scapy.ARP(pdst=ip)
broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

packet=broadcast/arp

result = scapy.srp(packet,timeout=1,verbose=True)[0]

if result:
    print(f"IP:{result[0][1].psrc},MAC:{result[0][1].hwsrc}")
else:
    print(f"No response{ip}")