from port_scan import scan
from sniff import sniff_packets
from ip_stats import simple_ip_stats


import os
run = True

while run:
    choice  = input("1.TCP Port Scanner\n2.Packet Sniffing\n3.IP Stats [incoming and outgoing requests]\n4.Clear Screen\n0.Exit\nEnter Your Choice :")
    if choice == "1":
        network = input("Enter IP address with Subnet Mask : ")
        scan(network)
    elif choice == "2":
        count = int(input("Enter the Number of Packets to be Captured : "))
        sniff_packets(count)
    elif choice == "3":
        count = int(input("Enter the Number of Packets to be Captured : "))
        print("IP Stats [incoming and outgoing requests]")
        simple_ip_stats(count)
    elif choice == "4":
        os.system('cls')
    else:
        run = False
        print("Exit Initiated")
        exit(0)