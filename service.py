from scapy.all import *
import threading

from features.dnsBlocker import dnsBlockerObj
from features.dataLinkLayer import dataLinkLayerObj
from features.networkLayer import networkLayerObj
from features.transportLayer import transportLayerObj

#-- Start service handlers fucntion

## Main handler function starts
def start_services():
    for service in services:
        t = threading.Thread(target=service)
        t.start()
## Main handler function ends

## Unit handlers starts

## Unit handlers ends

services = []
#-- End service handlers fucntion


#-- Start packet handlers fucntion

## Main handler function starts
def packet_handler(packet):
    for handler_function in handlers:
        t = threading.Thread(target=handler_function,args=(packet,))
        t.start()
## Main handler function ends

## Unit handlers starts
def handle_dns(packet):
    if packet.haslayer('DNS'):
        dnsBlockerObj.handler(packet)
        return True
    return False

def handle_datalink(packet):
    if packet.haslayer('Ether'):
        dataLinkLayerObj.handler(packet)
        return True
    return False

def handle_networklayer(packet):
    if packet.haslayer('IP'):
        networkLayerObj.handler(packet)
        return True
    return False

def handle_transportlayer(packet):
    if packet.haslayer('IP'):
        transportLayerObj.handler(packet)
        return True
    return False
## Unit handlers ends

handlers = [handle_dns,handle_datalink,handle_networklayer,handle_transportlayer]
#-- End packet handlers fucntion

def main():
    print("Starting service...")

    start_services()

    try:
        sniff(iface='docker0',store=False,prn=packet_handler)
    except Exception as e:
        print(e)
    print("Exiting...")

if __name__ == "__main__":
    main()
