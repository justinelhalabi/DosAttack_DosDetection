from scapy.all import sniff
from scapy.all import IP
from scapy.all import TCP
from datetime import datetime

def action(dict_packets, dict_time, start_time, count, general_counter) :
    def detect(packet):
        global dict_packets
        global dict_time
        global start_time
        global count
        global general_counter
        #increase the number of packets received
        count = count+1
        if (TCP in packet) and (IP in packet):
            if (packet[TCP].flags & 2) :  #checks SYN flag
                #get the source ip address
                source_ip = packet[IP].src
                if source_ip in dict_packets:
                    #if source ip address was encountered before, increment its value in dict_packets
                    dict_packets[source_ip] = dict_packets[source_ip] + 1
                    #if large number of packets is arriving within a short period of time from the same source ip address, detect DoS
                    if (dict_packets[source_ip] > 15) and (datetime.now() - dict_time[source_ip]).total_seconds() < 2:
                        print("Denial of Service is detected from :" + source_ip)
                        #reinitialize the dictionaries
                        dict_time={}
                        dict_packets = {}
                else:
                    # if source ip address is not encountered before, add it to dict_packets and set its value to 1
                    dict_packets[source_ip] = 1
                    # set first occurence of this ip
                    dict_time[source_ip] = datetime.now()

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


#create a dictionary that stores the number of packets coming from each ip address
dict_packets = {}
#create a dictionary that stores the time of arrival of first packet for each ip
dict_time = {}
#interface = '' You can add an interface here instead of None
start_time = datetime.now()
#counter for the number of packets
count =0
general_counter = 0

while True :
    sniff(prn= action(dict_packets,dict_time, start_time, count, general_counter), iface=None, filter="")
