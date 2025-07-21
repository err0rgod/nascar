def port_scan(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        if s.connect_ex((ip, port)) == 0:
            print(f"Port {port}: OPEN")
            return port  # Return the open port number
        s.close()
    except Exception as e:
        print(f"Error on {ip}:{port} → {e}")
    return None  # Return None if closed/error