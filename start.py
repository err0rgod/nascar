import scapy.all as scapy
import ipaddress
import socket
import threading
import argparse
from queue import Queue



parser = argparse.ArgumentParser(description="Network Scanner")
parser.add_argument("-i","--ip", type=str, help="ip address to scan (e.g., 192.168.1.1)")
parser.add_argument("-n", "--network", type=str, help="Network in CIDR format (e.g., 192.168.1.0/24)")
parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads to use")
parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
parser.add_argument("-s", "--silent", action="store_true", help="Run in silent mode")
args = parser.parse_args()

network = args.network
if not network:
    if args.ip:
        # If an IP is provided, derive the network from it
        ip = ipaddress.ip_address(args.ip)
        network = f"{ip}/24"  # Default to /24 if no network is specified
    else:
        raise ValueError("Please provide a network in CIDR format or an IP address.")
    
threads_count = args.threads
if args.verbose:
    print(f"Scanning network: {network} with {threads_count} threads")

net = ipaddress.ip_network(network, strict=False)
ip_queue = Queue()
results = []  # List to store info about alive hosts
results_lock = threading.Lock()  # To prevent race conditions

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
            info = {
                "ip": result[0][1].psrc,
                "mac": result[0][1].hwsrc,
                "hostname": hostname
            }
            with results_lock:
                results.append(info)
            print(f"IP: {info['ip']}, MAC: {info['mac']}, Hostname: {info['hostname']}")
        else:
            print(f"No response {ip}")
        ip_queue.task_done()

# Fill the queue with all IPs
for ip in net.hosts():
    ip_queue.put(ip)

# Start threads
threads = []
for _ in range(threads_count):
    t = threading.Thread(target=worker)
    t.start()
    threads.append(t)

# Wait for the queue to be empty
ip_queue.join()
for t in threads:
    t.join()

# Show all alive hosts at the end
print("\nScan complete. Alive hosts:")
print("{:<16} {:<18} {}".format("IP Address", "MAC Address", "Hostname"))
print("-" * 50)
for info in results:
    print("{:<16} {:<18} {}".format(info['ip'], info['mac'], info['hostname']))


