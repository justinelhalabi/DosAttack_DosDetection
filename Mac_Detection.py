from scapy.all import *
from datetime import *

global packetType
global ether


packetType = TCP
ether = Ether
my_MAC_Address = 'b4:74:9f:df:94:c9'
my_IP_Address = '10.0.0.35'

def get_mac(packet):
    global ether
    if ether in packet:
        mac_addr = packet[ether].src
        # if(mac_addr != my_MAC_Address):
        return mac_addr

    elif (ARP in packet):
        mac_addr = packet[ARP].hwsrc
        if(mac_addr != my_MAC_Address):
            return mac_addr

def get_IP(packet):
    if IP in packet:
        ip_addr = packet[IP].src
        if(ip_addr != my_IP_Address):
            return ip_addr

#The following 5 functions I was trying to find out if a mac address is spoofed, and that is by pinging the IP address provided and
# and once I revcieve the reply I will check if the mac addresses are the same. But I was not getting any reply
# I also tried sending an ARP request and check if the recieved mac address is equal to the mac address is have, but I also
# was not getting any reply
# def ping_with_IP(ip):
#     TO = 2
#     for i in range(0,256):
#         packet = IP(dst=ip + str(i), ttl=20)/ICMP()
#         reply = sr1(packet, timeout=TO)
#         if not (reply is None):
#             print("REPLY IS HEREEEEEEEEEEEEE")
#             reply.show()
#         else:
#             print("Timeout waitng for %s" % packet[IP].dst)

# def get_mac_from_IP(ip_addr):
#     print ("Getting Mac for: %s" % ip_addr)
#     responses, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_addr),timeout=2,retry=10)
#     for s,r in responses:
#         return r[Ether].src
#     return None
#
# def get_mac_from_IP(ip_addr):
#     broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
#     arp_req = scapy.ARP(pdst=ip_addr)
#     arp_req_broadcast = broadcast/arp_req
#     answered_list = scapy.srp(arp_req_broadcast, timeout=1,verbose=False)[0]
#     return answered_list[0][1].hwsrc
#
# def get_mac_from_IP2(packet):
#     if (packetType in packet) and (packet[IP].src != my_IP_Address):
#         ip_addr = packet[IP].src
#         mac_addr = get_mac_from_IP(ip_addr)
#         print(mac_addr)
#
# def packetReader(packet):
#     global packetType
#     if packetType in packet:
#         print("NEW TCP PACKET ARRIVED:")
#         packet.show()
#
#     # else:
#     #     pkt.show()
#     #     print "This packet is not TCP"

def action2(MACdict):
    def start(packet):
        global MACdict
        if TCP in packet:
            if (packet[TCP].flags & 2) :
                mac_addr = get_mac(packet)
                if(mac_addr != None):
                    if not (mac_addr in MACdict):
                        MACdict[mac_addr] = [1, datetime.now()]
                    else:
                        MACdict[mac_addr][0] = MACdict[mac_addr][0] + 1
                        if(MACdict[mac_addr][0] > 15):
                            if ((datetime.now() - MACdict[mac_addr][1]).total_seconds() < 3 ):
                                print("DENIAL OF SERVICE ATTACK DETECTED FROM MAC ADDRESS: %s" % mac_addr)
                                MACdict = {}
                            else:
                                MACdict[mac_addr] = [1, datetime.now()]
                # print(MACdict)
    return start
    
#sniff(iface='wlp2s0', filter="", prn=packetReader)
#sniff(iface='wlp2s0', filter="", prn=get_mac)
#sniff(iface='wlp2s0', filter="", prn=get_IP)
# sniff(iface='wlp2s0', filter="", prn=get_mac_from_IP2)

MACdict = {}
sniff(iface='wlp2s0', filter="", prn=action2(dict))
