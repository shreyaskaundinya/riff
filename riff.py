from port_scan import scan
from sniff import sniff_packets
import os
run = True

while run:
    choice  = input("1.TCP Port Scanner\n2.Packet Sniffing\n3.Clear Screen\n0.Exit\nEnter Your Choice :")
    if choice == "1":
        network = input("Enter IP address with Subnet Mask : ")
        scan(network)
    elif choice == "2":
        count = input("Enter the Number of Packets to be Captured : ")
        sniff_packets(count)
    elif choice == "3":
        os.system('cls')
    else:
        run = False
        print("Exit Initiated")
        exit(0)