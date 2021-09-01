import socket
import struct
import binascii
import os
import pye
# run with administrator privilages

s = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_IP)
s.bind(("127.0.0.1",0))
s.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
s.ioctl(socket.SIO_RCVALL,socket.RCVALL_ON)

while True:
    packet = s.recvfrom(65565)

    unpack=pye.unpack()

    # Ethernet
    print("\n>>----- Ethernet Header -----")
    for i in unpack.eth_header(packet[0][0:14]).items():
        a,b=i
        print("{} : {}".format(a,b))
