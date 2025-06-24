import scapy.all as scapy

ip = "192.168.1.1"

arp = scapy.ARP(pdst=ip)
broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
arp_request = broadcast / arp

result = scapy.srp(arp_request, timeout=1, verbose=False)[0]

if result:
    for sent, received in result:
        print(f"IP: {received.psrc}, MAC: {received.hwsrc}")
else:
    print("No devices found in the network.")

    

