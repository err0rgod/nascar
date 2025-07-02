import scapy.all as scapy
import ipaddress
import socket
import threading
import argparse
from queue import Queue

f

parser = argparse.ArgumentParser(description="Network Scanner")
parser.add_argument("-i","--ip", type=str, help="ip address to scan (e.g., 192.168.1.1)")
parser.add_argument("-n", "--network", type=str, help="Network in CIDR format (e.g., 192.168.1.0/24)")
parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads to use")
parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
parser.add_argument("-s", "--silent", action="store_true", help="Run in silent mode")
parser.add_argument("-lm", "--lateral", action="store_true", help="Enable lateral movement (port scan on alive hosts)")
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
            # Lateral movement: port scan if enabled
            if args.lateral:
                info["open_ports"] = port_scan(info["ip"], COMMON_PORTS)
            with results_lock:
                results.append(info)
            print(f"IP: {info['ip']}, MAC: {info['mac']}, Hostname: {info['hostname']}" +
                  (f", Open Ports: {info['open_ports']}" if args.lateral else ""))
        else:
            print(f"No response {ip}")
        ip_queue.task_done()

# Define ports to scan for lateral movement
COMMON_PORTS = [22, 80, 443, 3389, 445, 139, 21, 23, 25, 53]

def port_scan(ip, ports):
    open_ports = []
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            result = s.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            s.close()
        except Exception:
            pass
    return open_ports

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
if args.lateral:
    print("{:<16} {:<18} {:<20} {}".format("IP Address", "MAC Address", "Hostname", "Open Ports"))
    print("-" * 70)
    for info in results:
        print("{:<16} {:<18} {:<20} {}".format(
            info['ip'], info['mac'], info['hostname'], 
            ",".join(str(p) for p in info.get('open_ports', []))
        ))
else:
    print("{:<16} {:<18} {}".format("IP Address", "MAC Address", "Hostname"))
    print("-" * 50)
    for info in results:
        print("{:<16} {:<18} {}".format(info['ip'], info['mac'], info['hostname']))


