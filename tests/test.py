import argparse
#for taking user input directly while interpretion
import socket
#for packet manipulation and connetion over a network
import threading
#for creating multiple threads
import socks
#for using socks5,4 to switch proxies 
from sys import exit

import random



parser = argparse.ArgumentParser(description="Advanced port scanner by err0rgod")

parser.add_argument("-t","--target",type=str,required=True,help="Enter the target to scan the port")
parser.add_argument("-p","--portse",type=str, default="1-1024",help="Enter the start and end of ports to scan")
parser.add_argument("-c","--concurrency",type=int,default=10,help="Enter the number of threads")
parser.add_argument("-np","--no_proxy",default=False,action="store_false",help="For not using proxy system")

#mutually exclusive parsers 

output_group =  parser.add_mutually_exclusive_group()
output_group.add_argument("-b", "--banner",action="store_true",help="Show brief banner info")
output_group.add_argument("-d", "--detailed",action="store_true",help="Show full banner output")

args = parser.parse_args()




open_ports= []    #storing the list of open ports to show up in the end
serv_dtc = []      #same with service detection 


USE_PROXY = not args.no_proxy # Toggle proxy on/off

proxy_ip = "185.59.100.55" #obiviously proxy ip
proxy_port = 1080

#user input through argparse

PROXY_LIST = [
    "185.59.100.55:1080",
    "185.59.100.55:1080"
]



tar = args.target
t = args.concurrency
#tar="steminfinity.in"#input("Enter the target: ")
#p=50#int(input("Enter the port number: "))
#t=30#int(input("Enter number of threads: "))
#ports = range(1,p)



try:
    start_port, end_port = map(int, args.portse.split('-'))
    ports = range(start_port, end_port + 1)

except ValueError:
    print("Error : Invaluid Port format. Use start - end (eg. -> 1-100)")
    exit(1)



def get_random_proxy():
    """Returns parsed proxy dict (host, port, auth)"""
    proxy_str = random.choice(PROXY_LIST)
    parts = proxy_str.split(":")
    
    proxy = {
        "host": parts[0],
        "port": int(parts[1])
    }
    
    if len(parts) > 2:  # Has auth
        proxy["username"] = parts[2]
        proxy["password"] = parts[3]
    
    return proxy






def port_scan(tar,port):          #main function for scanning ports and connecting other functions
    try:
        '''if USE_PROXY:   
            
            s = socket.socket()           #for the switch to turn on/off proxy
            socks.set_default_proxy(socks.SOCKS5, proxy_ip, 1080)''' #setting up proxy ip and port
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM) 
          #initializing the connection from the default proxy setted up in above line if switch is on the will connect to proxy otherwise will connet to system proxy
        s.settimeout(1)  

        result = s.connect_ex((tar,port))          #providing target and port to socket if alive will return 0 otherwise 1

        if result == 0 :           #if the target and port is alive then this statement will execute
 
            service=service_detect(port)         #calling service detection func 
            banner = grab_ban(s) if (args.banner or args.detailed) else ""
                        #calling banner garabbing func

            proxy_info = proxy_ip if USE_PROXY else "No proxy used"

            print(f"[+] Port {port} is open : {service}  :  {banner[:50]} : proxy :  {proxy_info}", end='\r')         # providing user output


            open_ports.append(port)                
            serv_dtc.append((service,banner))  
            
            if args.detailed:
                print(f"[+] Port : {port} open : {service}")
            elif args.banner:
                print(f"[+] Port : {port} open : {service}",end='\r')          #storing the port service and banners in a list mentioned above in the program
        else:
            print(f"port {port} not open. Failure.")
        s.close()
    
    except Exception as e:
        if args.detailed:
            print(f"Error while scanning port {port} {e}")



def proxy_scan(target, port):
    max_retries = 3
    for attempt in range(max_retries):
        proxy = get_random_proxy()
        try:
            s = socks.socksocket()
            s.set_proxy(
                socks.SOCKS5,
                proxy["host"],
                proxy["port"],
                username=proxy.get("username"),
                password=proxy.get("password")
            )
            s.settimeout(3)
            
            if s.connect_ex((target, port)) == 0:
                banner = grab_ban(s) if (args.banner or args.detailed) else ""
                s.close()
                return True, banner
        except Exception as e:
            print(f"Proxy {proxy['host']} failed (attempt {attempt+1}): {e}")
            continue
        finally:
            s.close()
    return False, "All proxies failed"



def multi_threading(tar,ports,max_threads=10):          #for multi threading 
    threads = []
    for port in ports:
        while threading.active_count() > max_threads:
            pass

        thread  = threading.Thread(target=scan, args=(tar,port))
        thread.start()
        threads.append(thread)
        


    for thread in threads:
        thread.join()


def service_detect (port):            #for service detection using socket
    try:
        return socket.getservbyport(port)
    except:
        return "Unknown"



def grab_ban(socket_conn, timeout =1):            #basic banner grabbing function
    try:
        socket_conn.settimeout(timeout)

        socket_conn.send(b"HELLO\r\n")
        return socket_conn.recv(1024).decode(errors="ignore").strip()
    
    except:
        return "No banner Grabbed"


def show_result():
    print(f"Results for {tar}")

    if not open_ports:
        print("No open ports Found")
        return
    
    if args.detailed:
        print("\n"+ "="*50)
        print(f"Detailed Scan Results for {args.target}")
        print("="*50)

        for port, (service,banner) in zip(open_ports, serv_dtc):
            print(f"\n[Port {port}] {service.upper()}")
            if banner and banner != "No Banner Grabbed":
                print("-"*50)
                print(banner)


    elif args.banner:
        print("\n"+ "="*50)
        print(f"Breif Scan Results for {args.target}")
        print("="*50)
        for port, (service, banner) in zip(open_ports,serv_dtc):
            clean_banner = banner.split('\r\n')[0][:60] if banner else ""
            print(f"-> Port {port} : {service} | {clean_banner}")


    else:
        print("\nOpen Ports:")
        for port, (service, _) in zip(open_ports,serv_dtc):
            print(f"-> Port {port} : {service}")


    
    
        
def scan(target, port):
    if USE_PROXY:  # When --no-proxy is used
        return port_scan(target, port)  # Original direct scan
    else:  # Default behavior (proxy rotation)
        return proxy_scan(target, port)  # New proxy logic


    


#end program code to be executed for providing smooth results to user

print(f"\n Scanning {tar} (ports {args.portse}) ")

multi_threading(tar,ports,t)
show_result()


'''if open_ports:
    print("OPEN PORTS FOUND:")
    for port,service in zip(sorted(open_ports),serv_dtc):
       
        print(f"→ Port {port} : {service} ")
else:
    print("No open ports found.")
print("-" * 30)
'''

print(f"The scan is completed")