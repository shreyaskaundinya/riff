from scapy.all import sniff, IP

ip_stats = {}

def get_info_from_packet(packet):
    global ip_stats

    if packet.haslayer(IP):
        if (ip_stats.get(packet.getlayer(IP).src) != None):
            ip_stats[packet.getlayer(IP).src]["out"] = ip_stats[packet.getlayer(IP).src]["out"] + 1
        if (ip_stats.get(packet.getlayer(IP).dst) != None):
            ip_stats[packet.getlayer(IP).dst]["in"] = ip_stats[packet.getlayer(IP).dst]["in"] + 1
        else :
            ip_stats[packet.getlayer(IP).src] = {"in": 0, "out": 1}
            ip_stats[packet.getlayer(IP).dst] = {"in": 1, "out": 0}


def simple_ip_stats(count):
    capture = sniff(count=count, prn=get_info_from_packet)

    for i in ip_stats:
        print(i)
        print("Incoming requests : ", ip_stats[i]["in"])
        print("Outgoing requests : ", ip_stats[i]["out"])
        print()


