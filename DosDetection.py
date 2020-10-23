from scapy.all import *
from datetime import datetime

global packetType
global ether

#CHANGE THESE PARAMETERS TO THE USER'S PREFERNCE
packetType = TCP
ether = Ether
my_MAC_Address = 'b4:74:9f:df:94:c9'
my_IP_Address = '10.0.0.35'

#function that returns the MAC address from an arrived packet
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

#function that just reads the packets
def packetReader(packet):
    global packetType
    if packetType in packet:
        print("NEW TCP PACKET ARRIVED:")
        packet.show()

def action(MACdict, dict_packets, dict_time, start_time, count, general_counter) :
    def detect(packet):
        global MACdict
        global dict_packets
        global dict_time
        global start_time
        global count
        global general_counter
        #increase the number of packets received
        count = count+1
        if (TCP in packet) and (IP in packet):
            if (packet[TCP].flags & 2) :  #checks SYN flag
            #FOR IP ADDRESS ATTACK DETECTION:
                #get the source ip address
                source_ip = packet[IP].src
                if source_ip in dict_packets:
                    #if source ip address was encountered before, increment its value in dict_packets
                    dict_packets[source_ip] = dict_packets[source_ip] + 1
                    #if large number of packets is arriving within a short period of time from the same source ip address, detect DoS
                    if (dict_packets[source_ip] > 15) and (datetime.now() - dict_time[source_ip]).total_seconds() < 3:
                        print("Denial of Service is detected from :" + source_ip)
                        #reinitialize the dictionaries
                        dict_time={}
                        dict_packets = {}
                else:
                    # if source ip address is not encountered before, add it to dict_packets and set its value to 1
                    dict_packets[source_ip] = 1
                    # set first occurence of this ip
                    dict_time[source_ip] = datetime.now()

                #FOR MAC ADDRESS DETECTION:
                #getting the mac address from the previous function defined
                mac_addr = get_mac(packet)
                #since some packets are recieved with no mac_address, we have to make sure the mac address is not None
                if(mac_addr != None):
                    #if the mac address is not already in the dicionary, add it
                    if not (mac_addr in MACdict):
                        MACdict[mac_addr] = [1, datetime.now()] #description of MACdict is present below
                    else:
                        #incrementing the count of packets sent by a single mac address
                        MACdict[mac_addr][0] = MACdict[mac_addr][0] + 1
                        #checks if number of packets sent is more than 15, then start to get suspicious
                        if(MACdict[mac_addr][0] > 15):
                            #check if the 15 packets were sent within 3 seconds, then there is a DOS attack
                            if ((datetime.now() - MACdict[mac_addr][1]).total_seconds() < 3 ):
                                print("DENIAL OF SERVICE ATTACK DETECTED FROM MAC ADDRESS: %s" % mac_addr)
                                #reset the dictionay back to empty after detecting an attack, since this is a DOS attack, and not a dDOD
                                MACdict = {}
                            else:
                                #if the number of packets exceeded 15 but they were sent over a span of more than 3 total_seconds
                                # then this mac address is most probably not performing a DOS attack and therefore its number of
                                # packets sent is set back to 1 and its first recieved packet time is reset also
                                MACdict[mac_addr] = [1, datetime.now()]

        # if ip or mac address are spoofed and a very large traffic is detected, there might be a denial of service but not necessarly
        if (count>40) and (datetime.now() - start_time).total_seconds() < 1 :
            general_counter = general_counter +1
            start_time = datetime.now()
            count=0
        if general_counter >=5 :
            print("There might be a denial of service")
            general_counter =0
        # if statement for mac address
    return detect


#create a dictionary that stores the mac address as a key and has a list as thier value
# and this list includes two elements: first is number of packets recieved by this Mac
# address, and the second is the time of arrival of the first packet
MACdict = {}

#create a dictionary that stores the number of packets coming from each ip address
dict_packets = {}

#create a dictionary that stores the time of arrival of first packet for each ip
dict_time = {}

#interface = '' You can add an interface here instead of None
start_time = datetime.now()

#counter for the number of packets
count =0
general_counter = 0


sniff(prn= action(MACdict, dict_packets,dict_time, start_time, count, general_counter), iface=None, filter="")
