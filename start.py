import scapy.all as scapy
import ipaddress
import socket
import threading
from queue import Queue

network = input("Enter the network in cidr format: ")

net = ipaddress.ip_network(network, strict=False)
ip_queue = Queue()

def worker():
    while not ip_queue.empty():
        ip = ip_queue.get()
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
        ip_queue.task_done()

# Fill the queue with all IPs
for ip in net.hosts():
    ip_queue.put(ip)

# Start threads
threads = []
for _ in range(20):  # You can adjust the number of threads
    t = threading.Thread(target=worker)
    t.start()
    threads.append(t)

# Wait for the queue to be empty
ip_queue.join()

# Optionally, join the threads if you want to wait for them to finish
for t in threads:
    t.join()


