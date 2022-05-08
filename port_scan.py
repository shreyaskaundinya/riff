import threading

import random
from ipaddress import IPv4Network
from typing import List
import time

from scapy.all import ICMP, IP, sr1, TCP

# --------------------------------------------------

# CONSTANTS

ICMP_TIMEOUT=1
ICMP_BLOCKED_CODES=[1,2,3,9,10,13]
ICMP_BLOCK_TYPE=3

TCP_TIMEOUT=1
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
online_host_count = 0

# Stores the open port information for each host
open_ports = {}

# Stores all the threads utitilized in the program
threads = []

# --------------------------------------------------

blocked_hosts = lambda host,addresses: host in (addresses.network_address, addresses.broadcast_address)

def host_scan(host:str, ports: List[int], addresses:IPv4Network) -> None:
    """
    Scans the host for live hosts using ICMP ping
    """
    global online_host_count

    if (blocked_hosts(host, addresses)):
        # Skip network and broadcast addresses
        return

    # Send a ICMP packet to the host
    # If the host is active, the ICMP packet will be answered with response
    # If the host is not active, the ICMP packet will be dropped silently
    # If the host blocks the ICMP packet, the ICMP packet will be answered with a ICMP packet of type 3 and code 1,2,3,9,10 or 13
    icmp_res = sr1(IP(dst=str(host))/ICMP(), timeout=ICMP_TIMEOUT, verbose=0)

    if icmp_res is None:
        print(f"{host} : DOWN/NON RESPONSIVE")
        
    elif (int(icmp_res.getlayer(ICMP).type)==ICMP_BLOCK_TYPE and int(icmp_res.getlayer(ICMP).code) in ICMP_BLOCKED_CODES):
        print(f"{host} : BLOCKING ICMP PACKET")

    else :
        online_host_count += 1
        # only if host is online scan it for open ports
        port_scan(host, ports)

def port_scan(host: str, ports: List[int]) -> None:
    """
    Scans the host for open ports using TCP SYN method
    """
    # Send SYN with random Src Port for each Dst port
    global open_ports
    open_ports[host] = []

    for dst_port in ports:
        src_port = random.randint(1025, 65565)
        tcp_res = sr1(
            IP(dst=host)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=TCP_TIMEOUT,
            verbose=0,
        )

        if tcp_res is None:
            print(f"{host}:{dst_port} : FILTERED [dropped]")
            
        elif(tcp_res.haslayer(TCP)):
            # Check if SYN is received
            if(tcp_res.getlayer(TCP).flags == 0x12):
                sr1(
                    IP(dst=host)/TCP(sport=src_port,dport=dst_port,flags='R'),
                    timeout=TCP_TIMEOUT,
                    verbose=0,
                )
                print(f"{host}:{dst_port} : OPEN")
                open_ports[host].append(dst_port)
            
            # Check if RST is received
            elif (tcp_res.getlayer(TCP).flags == 0x14):
                print(f"{host}:{dst_port} : CLOSED")
                
        # In some networks the SYN packets are blocked by firewall we come to know this when the ICMP packet is of type 3 and has code 1,2,3,9,10 or 13
        # We can get past this firewall by using FIN flag in the packet 
        elif(tcp_res.haslayer(ICMP) and int(tcp_res.getlayer(ICMP).type)==ICMP_BLOCK_TYPE and int(tcp_res.getlayer(ICMP).code) in ICMP_BLOCKED_CODES):
                print(f"{host}:{dst_port} : FILTERED [dropped]")


def scan(network: str) -> None:
    """
    Scans the network for live hosts and does port scan.
        - Creates one thread per host.
        - Each thread once joined
            - Checks if host is alive
            - If host is alive, scans the host for open ports
    """
    global open_ports, online_host_count

    start = time.time()
    # make list of addresses out of network, set live host counter
    addresses = IPv4Network(network)

    # Create thread for each address in network
    for host in addresses:
        thread = threading.Thread(target=host_scan, args=(str(host), port_range, addresses))
        threads.append(thread)
        thread.start()
    
    # await completion of each thread
    for i in range(len(threads)):
        threads[i].join()

    # calculate total time taken to scan the network
    end = time.time()
    elapsed = end - start

    # print the open ports of each online host
    for key, value in open_ports.items():
        print(f"{key} has open ports : {value}")
    
    print(f"{online_host_count}/{addresses.num_addresses} hosts are online.")
    
    print(f"Scanned {addresses.num_addresses} hosts in {elapsed} seconds.")