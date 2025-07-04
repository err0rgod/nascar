import scapy.all as scapy
import ipaddress
import socket
import threading
import argparse
from queue import Queue

#imported required librarires

# adding parser vars to get the user input of the required feilds

parser =  argparse.ArgumentParser(description="Network Scanner")

parser.add_argument("-n","-network", type=str, required=True , help="Network In CIDR Form" ) # user se ip ka input lene ke liye cidr form me
parser.add_argument("-t","-threads", type=int, default=20, help="to set the threads") # for setiing threads
parser.add_argument("-v", "-verbose", action="store_true", help="enable verbosity") # help wale se padh na
