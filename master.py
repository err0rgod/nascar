import socket 
import argparse


parser =  argparse.ArgumentParser(description="Gaand Phaad Network Scanner")


parser.add_argument("-i","--network", type=str, required=True, help="Enter the target Domain or IP")
parser.add_argument("-p","--port",type=str, default="1-1024",help="Enter the start and end of ports to scan")
parser.add_argument("-t","--threads",default=10,type=int,help="Enter the Number of threds")

args = parser.parse_args()


target= args.network
port = args.port
threads = args.threads
open_ports = []




#for ports decode
def parse_ports(port):
    try:
        if  '-'  in port:
             start_port, end_port = map(int, args.port.split('-'))
             ports = range(start_port, end_port)
             return ports
        
        else:
            return[int(port)]

    except ValueError:
        print("Error : Invalid Port format. Use start - end (eg. -> 1-100)")
        exit(1)




# ressolve initial domain

def resolve_target(target):

    ip = socket.gethostbyname(target)
    
    print(ip)
    return ip


#port scan without proxy
def port_scan(ip,ports=(1,1024)):
        
    try:
        for port in ports:
            s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.settimeout(1)
            result = s.connect_ex((ip,port))
            if result== 0:
                print(f"The Port {port} is Open")
                open_ports.append(port)

            s.close()

    except Exception as e:
        print(f"some error occured on {ip} with this : {e}")

        



#end result configuration and stuff
def result(ip,ports_range):

    
    port_scan(ip,ports_range)
    print(ports_range)
    print(open_ports)

    for i in open_ports:
        print(f"the port : {i} is Open")


ports_range = parse_ports(port)
ip=resolve_target(target)
result(ip,ports_range)