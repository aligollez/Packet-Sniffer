import socket
import pye
from datetime import datetime

# run with administrator privilages

now = datetime.now()   # timestamp

# Create socket to capture packets
print("\nCreating socket...")
sock = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_IP)
sock.bind(("127.0.0.1",0))
sock.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
sock.ioctl(socket.SIO_RCVALL,socket.RCVALL_ON)

print("\n", now.strftime("%d/%m/%Y %H:%M:%S"), "Receiving packets...")

while True:

    print("\n-------------------------------")
    packet = sock.recvfrom(65565) # get data from socket !buffer size = 65565
    unpack = pye.unpack() # unpuck received data to get headers

    # Ethernet header
    print("\n>> ----- Ethernet Header -----")
    unpack.eth_header(packet[0][0:14])

    # IP header
    print("\n>> ----- IP Header -----")
    unpack.ip_header(packet[0][14:34])

    # TCP header
    print("\n>> ----- TCP Header -----")
    unpack.tcp_header(packet[0][14:34])

    # UDP header
    print("\n>> ----- UDP Header -----")
    unpack.udp_header(packet[0][14:22])

    # ICMP header
    print("\n>> ----- ICMP header -----")
    unpack.icmp_header(packet[0][14:18])



