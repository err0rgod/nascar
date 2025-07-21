import socket 
import argparse


parser =  argparse.ArgumentParser(description="Gaand Phaad Network Scanner")


parser.add_argument("-i","--network", type=str, required=True, help="Enter the target Domain or IP")
parser.add_argument("-p","--port",type=str, default="1-1024",help="Enter the start and end of ports to scan")


args = parser.parse_args()


target= args.network
port = args.port

open_ports = []


ports = None

#for ports decode

try:
    start_port, end_port = map(int, args.port.split('-'))
    ports = range(start_port, end_port)

except ValueError:
    print("Error : Invalid Port format. Use start - end (eg. -> 1-100)")
    exit(1)


print(ports)





def resolve_target(target):

    ip = socket.gethostbyname(target)
    
    print(ip)




resolve_target(target)