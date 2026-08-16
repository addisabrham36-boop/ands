from scapy.all import sniff

def show(pkt):
    print(pkt.summary())

print("Sniffing 5 packets... generate some traffic (ping the VM) if nothing shows up.")
sniff(prn=show, count=5)
