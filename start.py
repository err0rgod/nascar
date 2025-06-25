import scapy.all as scapy
import ipaddress
import socket

network = input("Enter the network in cidr format: ")


net = ipaddress.ip_network(network, strict=False)
for ip in net.hosts():
    print(ip)
    arp = scapy.ARP(pdst=str(ip))
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp
    result = scapy.srp(packet, timeout=1, verbose=False)[0]
    if result:
        try:
            hostname = socket.gethostbyaddr(result[0][1].psrc)[0]
        except Exception:
            hostname = "Unknown"
        print(f"IP: {result[0][1].psrc}, MAC: {result[0][1].hwsrc}, Hostname: {hostname}")
    else:
        print(f"No response {ip}")


