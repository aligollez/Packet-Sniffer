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

        destination_mac = (binascii.hexlify(header[0])).decode('utf-8')
        destination_mac = ':'.join(destination_mac[i:i+2] for i in range(0,12,2)) # mac address format
        source_mac = (binascii.hexlify(header[1])).decode('utf-8')
        source_mac = ':'.join(source_mac[i:i+2] for i in range(0,12,2))
        eth_protocol = header[2]
        data = header[14:]

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

        version = header[0] >> 4
        tos = header[1]
        length = header[2]
        id = header[3]
        offset = header[4]
        ttl = header[5]
        protocol = header[6]
        checksum = header[7]
        source_ip = socket.inet_ntoa(header[8])  # ip address format
        destination_ip = socket.inet_ntoa(header[9])
        header_length = ((header[0] >> 4) & 15) * 4 # header length
        data = header[header_length:]

        print("Version : ",version, "\nTOS : ",tos, "\nTotal length : ",length, "\nIdentification : ",id, "\nFragment Offset : ",offset,
        "\nTime-To-Live : ",ttl, "\nProtocol : ",protocol, "\nHeader CheckSum : ",checksum, "\nSource IP Address : ",source_ip,
        "\nDestination IP Address : ",destination_ip)

        return protocol # return protocol TCP, UDP, ICMP + data

    # TCP header
    def tcp_header(self, data):

        # format
        # HH - (unsigned short) for ports
        # LL - (long int) for sequence number + acknowledgement number
        # BB - (unsigned char) for tcp flag + offset
        # HHH - (unsigned short) for window + checksum + urgent pointer
        header = struct.unpack("!HHLLHHHH", data)

        source_port = header[0]
        destination_port = header[1]
        sequence_number = header[2]
        ack_number = header[3]
        offset = header[4]
        window = header[5]
        checksum = header[6]
        urgent = header[7]
        offset_length = (offset >> 12) * 4
        data = header[offset_length:]

        print("Source Port : ",source_port, "\nDestination Port: ",destination_port, "\nSequence Number : ",sequence_number,
        "\nAcknowledge Number : ",ack_number, "\nOffset : ",offset, "\nWindow Size : ",window,
        "\nChecksum : ",checksum,"\nUrgent Pointer : ",urgent)

        return source_port, destination_port, data

    # UDP header
    def udp_header(self, data):

        # format
        # H - (unsigned short) ports + length + checksum
        header = struct.unpack('!HHHH', data)

        source_port = header[0]
        destination_port = header[1]
        length = header[2]
        checksum = header[3]

        print("Source Port : ",source_port,"\nDestination Port : ",destination_port,"\nLength : ",length,"\nCheckSum : ",checksum)

    # ICMP header
    def icmp_header(self, data):

        # format
        # B - (unsigned char) type + code
        # H - (unsigned short) checksum
        header  =struct.unpack('!BBH', data)

        icmp_type = header[0]
        code = header[1]
        checksum = header[2]

        print("ICMP Type : ",icmp_type,"\nCode : ",code,"\nCheckSum : ",checksum)