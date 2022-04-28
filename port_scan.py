import threading

import random
from ipaddress import IPv4Network
from typing import List

from scapy.all import ICMP, IP, sr1, TCP

# --------------------------------------------------

# Define TCP ports [most common ports]
port_range = [5601, 9300, 80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080, 1723, 111,
995, 993, 5900, 1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001, 10000, 514, 5060, 179,
1026, 2000, 8443, 8000, 32768, 554, 26, 1433, 49152, 2001, 515, 8008, 49154, 1027, 5666, 646,
5000, 5631, 631, 49153, 8081, 2049, 88, 79, 5800, 106, 2121, 1110, 49155, 6000, 513, 990, 5357,
427, 49156, 543, 544, 5101, 144, 7, 389, 8009, 3128, 444, 9999, 5009, 7070, 5190, 3000, 5432,
1900, 3986, 13, 1029, 9, 5051, 6646, 49157, 1028, 873, 1755, 2717, 4899, 9100, 119, 37, 1000,
3001, 5001, 82, 10010, 1030, 9090, 2107, 1024, 2103, 6004, 1801, 5050, 19, 8031, 1041, 255]


# Count of number of live hosts
live_count = 0

# Stores the open port information for each host
open_ports = {}

# Stores all the threads utitilized in the program
threads = []

# --------------------------------------------------

def host_scan(host:str, ports: List[int], addresses:IPv4Network) -> None:
    """
    Scans the host for live hosts using ICMP
    """
    global live_count
    if (host in (addresses.network_address, addresses.broadcast_address)):
        # Skip network and broadcast addresses
        return

    resp = sr1(IP(dst=str(host))/ICMP(), timeout=1, verbose=0)

    if resp is None:
        print(f"{host} is down or not responding.")
        
    elif (int(resp.getlayer(ICMP).type)==3 and int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
        print(f"{host} is blocking ICMP.")

    else :
        live_count += 1
        port_scan(host, ports)

def port_scan(host: str, ports: List[int]) -> None:
    """
    Scans the host for open ports using TCP SYN method
    """
    # Send SYN with random Src Port for each Dst port
    global open_ports
    open_ports[host] = []

    for dst_port in ports:
        src_port = random.randint(1025, 65534)
        resp = sr1(
            IP(dst=host)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=1,
            verbose=0,
        )

        if resp is None:
            print(f"{host}:{dst_port} is filtered (silently dropped).")
            
        elif(resp.haslayer(TCP)):
            # Check if SYN is received
            if(resp.getlayer(TCP).flags == 0x12):
                sr1(
                    IP(dst=host)/TCP(sport=src_port,dport=dst_port,flags='R'),
                    timeout=1,
                    verbose=0,
                )
                print(f"{host}:{dst_port} is open.")
                open_ports[host].append(dst_port)
            
            # Check if RST is received
            elif (resp.getlayer(TCP).flags == 0x14):
                print(f"{host}:{dst_port} is closed.")
                
        # In some networks the SYN packets are blocked by firewall we come to know this when the ICMP packet is of type 3 and has code 1,2,3,9,10 or 13
        # We can get past this firewall by using FIN flag in the packet 
        elif(resp.haslayer(ICMP) and int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code) in (1, 2, 3, 9, 10, 13)):
                print(f"{host}:{dst_port} is filtered (silently dropped).")


def scan(network: str) -> None:
    """
    Scans the network for live hosts.
    """
    global open_ports, live_count
    # make list of addresses out of network, set live host counter
    addresses = IPv4Network(network)

    # Create thread for each address in network
    for host in addresses:
        thread = threading.Thread(target=host_scan, args=(str(host), port_range, addresses))
        threads.append(thread)
        thread.start()
    
    for i in range(len(threads)):
        threads[i].join()

    for key, value in open_ports.items():
        print(f"{key} has open ports: {value}")
    
    print(f"{live_count}/{addresses.num_addresses} hosts are online.")
