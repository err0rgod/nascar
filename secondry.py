import scapy.all as scapy
import ipaddress
import socket
import threading
import argparse
from queue import Queue

#imported required librarires

# adding parser vars to get the user input of the required feilds

parser =  argparse.ArgumentParser(description="Network Scanner")

parser.add_argument("-n","--network", type=str, required=True , help="Network In CIDR Form" ) # user se ip ka input lene ke liye cidr form me
parser.add_argument("-t","--threads", type=int, default=20, help="to set the threads") # for setiing threads
parser.add_argument("-v", "--verbose", action="store_true", help="enable verbosity") # help wale se padh na
parser.add_argument("-s","--silent", action="store_true", help="for stealthy look")
parser.add_argument("-lm", "--lateral", action="store_true", help="to enable lateral movement for ports")

#adding args def

network = args.network
threads_count = args.threads


if args.verbose:
    print(f"scanning network : {network} with  {threads_count} threads")

net = ipaddress.ip_address(network, strict= False)
ip_queue = Queue()

results = []

results_lock = threading.Lock()

#ports to scan

Common_ports = [22,80,443,3389,445,139,21,23,25,53]


def is_host_alive(ip):
    try:
        icmp = scapy.IP(dst=str(ip))/scapy.ICMP()
        resp = scapy.sr1(icmp, timeout=1, verbose=0)
        if resp is not None:
            return True, int(resp.ttl)
        else:
            return False, None
    except Exception:
        return False, None
    

#guess os by the ttl value from Ping request samjhe


def os_guess(ttl):
    if ttl is None:
        return "Unknown"
    elif ttl >=120:
        return "Windows"
    elif ttl >=60:
        return "Linux/Unix"
    else:
        return "Ye kya Hai"
    

#check for the ports 

def port_scan(ip,ports):
    open_ports = []
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            results = s.connect_ex((str(ip), port))
            if results == 0:
                open_ports.append(port)
            s.close()

        except Exception:
            pass
    return open_ports


