import socket 
import argparse
import subprocess
from concurrent.futures import ThreadPoolExecutor
import sys




open_ports = []

#for ports decode
def parse_ports(port):
    try:
        if  '-'  in port:
             start_port, end_port = map(int,port.split('-'))
             ports = range(start_port, end_port)
             return ports
        
        else:
            return[int(port)]

    except ValueError:
        print("Error : Invalid Port format. Use start - end (eg. -> 1-100)")
        exit(1)




# ressolve initial domain
def resolve_target(target):
        
    try:

        ip = socket.gethostbyname(target)

        print(ip)
        return ip
    
    except socket.gaierror :
        print(f"Could not ressolve the target {target} : Might be Invalid ")
        exit(1)




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



        
#Host  is alive or not by ICMP ping
'''def is_alive(ip):
    try:
        param = '-n' if os.name == 'nt' else '-c'
        command = ['ping', param, '1', ip]
        return subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
    except:
        return False   

'''
#leaved at implementing is host alive function yet to be done 



#end result configuration and stuff
def result(ip,ports_range):

    
    port_scan(ip,ports_range)
    print(ports_range)
    print(open_ports)

    for i in open_ports:
        print(f"the port : {i} is Open")




def main():

    parser =  argparse.ArgumentParser(description="Gaand Phaad Network Scanner")


    parser.add_argument("-i","--network", type=str, required=True, help="Enter the target Domain or IP")
    parser.add_argument("-p","--port",type=str, default="1-1024",help="Enter the start and end of ports to scan")
    parser.add_argument("-t","--threads",default=10,type=int,help="Enter the Number of threds")

    args = parser.parse_args()

    
    target= args.network
    port = args.port
    threads = args.threads


    ports_range = parse_ports(port)
    ip=resolve_target(target)







    
    print(f" \n Scanning {ip} started")


    with ThreadPoolExecutor(max_workers=threads) as executer:
        results = executer.map(lambda p: port_scan(ip,[p]),ports_range)
        '''open_ports = [port for port in results if port]'''


    print(f"Open Ports are  : {open_ports}")

   
    #ip=resolve_target(target)
    result(ip,ports_range)




if __name__ == "__main__":
    main()