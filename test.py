import socket
import argparse
from concurrent.futures import ThreadPoolExecutor
import subprocess
import sys

def parse_ports(port_arg):
    """Parse port range (e.g., '1-1000')"""
    try:
        if '-' in port_arg:
            start, end = map(int, port_arg.split('-'))
            return range(start, end + 1)
        else:
            return [int(port_arg)]
    except ValueError:
        print("❌ Invalid port format. Use 'start-end' or single port.")
        sys.exit(1)

def resolve_target(target):
    """Convert domain to IP"""
    try:
        ip = socket.gethostbyname(target)
        print(f"🎯 Target: {target} → {ip}")
        return ip
    except socket.gaierror:
        print(f"❌ Could not resolve {target}")
        sys.exit(1)

def is_host_up(ip):
    """Check if host responds to ping (ICMP)"""
    try:
        param = '-n' if os.name == 'nt' else '-c'
        command = ['ping', param, '1', ip]
        return subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
    except:
        return False

def scan_port(ip, port):
    """Scan a single port (thread-safe)"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            if s.connect_ex((ip, port)) == 0:
                print(f"🚪 Port {port}: OPEN")
                return port
    except Exception as e:
        print(f"⚠️ Error scanning {ip}:{port} → {e}")
    return None

def main():
    parser = argparse.ArgumentParser(description="🔥 Gaand Phaad Network Scanner 🔥")
    parser.add_argument("-i", "--target", required=True, help="Target IP/Domain")
    parser.add_argument("-p", "--ports", default="1-1024", help="Port range (e.g., '20-80')")
    args = parser.parse_args()

    ports = parse_ports(args.ports)
    ip = resolve_target(args.target)

    if not is_host_up(ip):
        print(f"🔴 Host {ip} is DOWN or blocking ICMP!")
        return

    print(f"\n🔍 Scanning {ip} (Ports: {args.ports})...")
    open_ports = []

    with ThreadPoolExecutor(max_workers=100) as executor:
        results = executor.map(lambda port: scan_port(ip, port), ports)
        open_ports = [port for port in results if port]

    print(f"\n✅ Open ports: {sorted(open_ports)}")

if __name__ == "__main__":
    main()