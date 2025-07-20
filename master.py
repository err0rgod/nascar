import socket 
import argparse


parser =  argparse.ArgumentParser(description="Gaand Phaad Network Scanner")
parser.add_argument("-i","--network", type=str, required=True, help="Enter the target Domain or IP")

args = parser.parse_args()

target= args.network


def resolve_target(target)

    ip = socket.gethostbyname(target)
    
    print(ip)




resolve_target(target)