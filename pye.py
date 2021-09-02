import struct
import binascii
import socket

class unpack:
    # Constructor
    def __cinit__(self):
        self.data=None

    # Ethernet Header
    def eth_header(self, data):

        # format
        # 6s - (string) for source/destination MAC addresses
        # H - (unsigned short) for ethernet protocol type
        header = struct.unpack("!6s6sH",data)

        destination_mac = binascii.hexlify(header[0])
        source_mac = binascii.hexlify(header[1])
        eth_protocol = header[2]
        #destimation_mac = "%2x:%2x:%2x:%2x:%2x:%2x" % struct.unpack("BBBBBB",destination_mac) # Mac address format
        print("Destination Mac : ",destination_mac,"\nSource Mac : ",source_mac,"\nProtocol Type : ",eth_protocol)

    # IP Header
    def ip_header(self, data):

        # format
        # BB - (unsigned char) for version + traffic class
        # HHH - (unsigned short) for total length + id + offset
        # BB - (unsigned char) for ttl + protocol
        # H - (unsigned short) for checksum
        # 4s4s - (string) IPs
        header = struct.unpack("!BBHHHBBH4s4s", data)

        version = header[0]
        tos = header[1]
        length = header[2]
        id = header[3]
        offset = header[4]
        ttl = header[5]
        protocol = header[6]
        checksum = header[7]
        source_ip = socket.inet_ntoa(header[8])
        destination_ip = socket.inet_ntoa(header[9])

        print("Version : ",version, "\nTOS : ",tos, "\nTotal length : ",length, "\nIdentification : ",id, "\nFragment Offset : ",offset,
        "\nTime-To-Live : ",ttl, "\nProtocol : ",protocol, "\nHeader CheckSum : ",checksum, "\nSource IP Address : ",source_ip,
        "\nDestination IP Address : ",destination_ip)

    # TCP header
    def tcp_header(self, data):

        # format
        # HH - (unsigned short) for ports
        # LL - (long int) for sequence number + acknowledgement number
        # BB - (unsigned char) for tcp flag + offset
        # HHH - (unsigned short) for window + checksum + urgent pointer
        header = struct.unpack("!HHLLBBHHH", data)

        source_port = header[0]
        destination_port = header[1]
        sequence_number = header[2]
        ack_number = header[3]
        offset = header[4]
        tcp_flag = header[5]
        window = header[6]
        checksum = header[7]
        urgent = header[8]

        print("Source Port : ",source_port, "\nDestination Port: ",destination_port, "\nSequence Number : ",sequence_number,
        "\nAcknowledge Number : ",ack_number, "\nOffset : ",offset, "\nTCP flag : ",tcp_flag, "\nWindow Size : ",window,
        "\nChecksum : ",checksum,"\nUrgent Pointer : ",urgent)

    # UDP header