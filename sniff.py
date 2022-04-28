from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP

# --------------------------------------------------


def sniff_packets(count:int) -> None:
    """
    Sniffs packets and categorizes them by protocol.
    """

    summary = {}
    protocols = [IP, TCP, UDP, ICMP, ARP]
    capture = sniff(count=int(count))
    for i in range(len(capture)):
        for p in protocols:
            if capture[i].haslayer(p):
                if p in summary:
                    summary[p] += 1
                else:
                    summary[p] = 1

    for i in summary:
        print(i, summary[i])


