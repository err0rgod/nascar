import scapy.all as scapy
import ipaddress
import socket
import threading
import argparse
from queue import Queue

parser = argparse.ArgumentParser(description="WAN/LAN Network Scanner")
parser.add_argument("-n", "--network", type=str, required=True, help="Network in CIDR format (e.g., 192.168.1.0/24 or 185.199.110.0/24)")
parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads to use")
parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
parser.add_argument("-s", "--silent", action="store_true", help="Run in silent mode")
parser.add_argument("-lm", "--lateral", action="store_true", help="Enable lateral movement (port scan on alive hosts)")
args = parser.parse_args()


network = args.network
threads_count = args.threads

if args.verbose:
    print(f"Scanning network: {network} with {threads_count} threads")

net = ipaddress.ip_network(network, strict=False)
ip_queue = Queue()
results = []
results_lock = threading.Lock()

# Define ports to scan for lateral movement
COMMON_PORTS = [22, 80, 443, 3389, 445, 139, 21, 23, 25, 53]

def is_host_alive_icmp(ip):
    try:
        icmp = scapy.IP(dst=str(ip))/scapy.ICMP()
        resp = scapy.sr1(icmp, timeout=1, verbose=0)
        if resp is not None:
            return True, int(resp.ttl)
        else:
            return False, None
    except Exception:
        return False, None
    


def guess_os(ttl):
    if ttl is None:
        return "Unknown"
    elif ttl >= 120:
        return "Windows"
    elif ttl >= 60:
        return "Linux/Unix"
    else:
        return "Ye kya hai"

def port_scan(ip, ports):
    open_ports = []
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            result = s.connect_ex((str(ip), port))
            if result == 0:
                open_ports.append(port)
            s.close()
        except Exception:
            pass
    return open_ports

def worker():
    while not ip_queue.empty():
        ip = ip_queue.get()
        ip_str = str(ip)
        mac = "N/A"
        hostname = "Unknown"
        alive = False

        # Check if IP is in local subnet
        is_local = ipaddress.ip_address(ip) in net and net.prefixlen >= 24 and ipaddress.ip_network(net).is_private

        if is_local:
            # Use ARP for LAN
            arp = scapy.ARP(pdst=ip_str)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = broadcast / arp
            result = scapy.srp(packet, timeout=1, verbose=False)[0]
            if result:
                alive = True
                mac = result[0][1].hwsrc
                try:
                    hostname = socket.gethostbyaddr(result[0][1].psrc)[0]
                except Exception:
                    pass
        else:
            # Use ICMP for WAN
            alive, ttl = is_host_alive_icmp(ip_str)
            os_name = guess_os(ttl) if alive else "Unknown"
            try:
                hostname = socket.gethostbyaddr(ip_str)[0]
            except Exception:
                pass

        if alive:
            info = {
                "ip": ip_str,
                "mac": mac,
                "hostname": hostname
            }
            if args.lateral:
                info["open_ports"] = port_scan(ip_str, COMMON_PORTS)
            with results_lock:
                results.append(info)
            if not args.silent:
                print(f"IP: {info['ip']}, MAC: {info['mac']}, Hostname: {info['hostname']}" +
                      (f", Open Ports: {info['open_ports']}" if args.lateral else ""))
        elif args.verbose:
            print(f"No response {ip_str}")
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


