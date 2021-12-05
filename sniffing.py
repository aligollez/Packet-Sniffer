import socket
import pye
from datetime import datetime

# run with administrator privilages

now = datetime.now()   # timestamp

# Create socket to capture packets
print("\nCreating socket...")
sock = socket.socket(socket.AF_PACKET,socket.SOCK_RAW)   #socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_IP
sock.bind(("127.0.0.1",0))
sock.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
sock.ioctl(socket.SIO_RCVALL,socket.RCVALL_ON)

print("\n", now.strftime("%d/%m/%Y %H:%M:%S"), "Receiving packets...")

while True:

    print("\n-------------------------------")
    packet, addr = sock.recvfrom(65565) # get data from socket !buffer size = 65565
    unpack = pye.unpack() # unpuck received data to get headers

    # Ethernet header - length: 14 bytes
    print("\n>> ----- Ethernet Header -----")
    unpack.eth_header(packet[:14])

    # IP header - length: 20 bytes
    print("\n>> ----- IP Header -----")
    protocol = unpack.ip_header(packet[:20])

    # If IP protocol is 6, TCP is used
    if protocol == 6:
        # TCP header - length: 20 bytes
        print("\n>> ----- TCP Header -----")
        src_port, dest_port, data = unpack.tcp_header(packet[:20])
        # If port is 80, HTTP is used
        if (src_port == 80 or dest_port == 80):
            print("\n>> ----- HTTP Header -----")
            print(data)

    # If IP protocol is 17, UDP is used
    elif protocol == 17:
        # UDP header - length: 8 bytes
        print("\n>> ----- UDP Header -----")
        unpack.udp_header(packet[:8])

    # If IP protocol is 1, ICMP is used
    elif protocol == 1:
        # ICMP header - length: 4 bytes
        print("\n>> ----- ICMP header -----")
        unpack.icmp_header(packet[:4])
