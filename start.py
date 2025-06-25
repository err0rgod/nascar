import scapy.all as scapy
import ipaddress

network = input("Enter the network in cidr format: ")


net = ipaddress.ip_network(network, strict=False)
for ip in net.hosts():
    print(ip)


ip = "192.168.75.1"

arp=scapy.ARP(pdst=ip)
broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

packet=broadcast/arp

result = scapy.srp(packet,timeout=1,verbose=True)[0]

if result:
    print(f"IP: {result[0][1].psrc}, MAC: {result[0][1].hwsrc}")
else:
    print(f"No response {ip}")

