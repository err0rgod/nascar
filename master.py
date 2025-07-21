import socket 
import argparse


parser =  argparse.ArgumentParser(description="Gaand Phaad Network Scanner")


parser.add_argument("-i","--network", type=str, required=True, help="Enter the target Domain or IP")
parser.add_argument("-p","--port",type=str, default="1-1024",help="Enter the start and end of ports to scan")


args = parser.parse_args()


target= args.network
port = args.port

open_ports = []




#for ports decode
def ip_ressolve(target):
    try:
        start_port, end_port = map(int, args.port.split('-'))
        ports = range(start_port, end_port)
        return ports
    
    except ValueError:
        print("Error : Invalid Port format. Use start - end (eg. -> 1-100)")
        exit(1)




# ressolve initial domain

def resolve_target(target):

    ip = socket.gethostbyname(target)
    
    print(ip)
    return ip


#port scan without proxy
def port_scan(ip,ports):
    for port in ports:
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.settimeout(1)
        if s.connect_ex((ip,port))== 0:
            print(f"The Port {port} is Open")
            
        else:
            print("port  Not open")

        s.close()

        







portse = ip_ressolve(target)
ip=resolve_target(target)
port_scan(ip,portse)
print(portse)