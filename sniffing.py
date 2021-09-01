import socket
import pye

# run with administrator privilages

# - not detecting os info

# Create socket to capture packets
print("\nCreating socket...")
sock = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_IP)
sock.bind(("127.0.0.1",0))
sock.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
sock.ioctl(socket.SIO_RCVALL,socket.RCVALL_ON)

while True:

    print("\nReceiving packet...")
    packet = sock.recvfrom(65565) # get data from socket
    unpack = pye.unpack() # unpuck received data to get headers

    # Ethernet header
    print("\n>> ----- Ethernet Header -----")
    for i in unpack.eth_header(packet[0][0:14]).items():
        a,b=i
        if ((a=="Destination Mac") or (a=="Source Mac")):
            b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]), ord(a[1]), ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5])) # Mac address format
        print("{} : {}".format(a,b))

    # IP header
    print("\n>> ----- IP Header -----")
    for i in unpack.ip_header(packet[0][14:34]).items():
        a,b=i
        print("{} : {}".format(a,b))

    # TCP header
    print("\n>> ----- TCP Header -----")
    for i in unpack.tcp_header(packet[0][14:34]).items():
        a,b=i
        print("{} : {}".format(a,b))


