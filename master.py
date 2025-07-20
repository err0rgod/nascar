import socket 
import argparse


parser =  argparse.ArgumentParser(description="Gaand Phaad Network Scanner")


parser.add_argument("-i","--network", type=str, required=True, help="Enter the target Domain or IP")
parser.add_argument("-p","--port",type=str, default="1-1024",help="Enter the start and end of ports to scan")


args = parser.parse_args()

target= args.network


open_ports = []


#for ports decode
def port_ressolve(port):
    try:
        start_port, end_port = map(int, args.portse.split('-'))
        ports = range(start_port, end_port + 1)

    except ValueError:
        print("Error : Invaluid Port format. Use start - end (eg. -> 1-100)")
        exit(1)



def resolve_target(target)

    ip = socket.gethostbyname(target)
    
    print(ip)




resolve_target(target)