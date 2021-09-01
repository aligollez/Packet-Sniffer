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

        data = {"Destination Mac" : destination_mac, "Source Mac" : source_mac, "Protocol Type" : eth_protocol}
        return data

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

        data = {"Version" : version, "TOS" : tos, "Total length" : length, "Identification" : id, "Fragment Offset" : offset,
         "Time-To-Live" : ttl, "Protocol" : protocol, "Header CheckSum" : checksum, "Source IP Address" : source_ip, 
         "Destination IP Address" : destination_ip}
        return data

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

        data = {"Source Port" : source_port, "Destination Port" : destination_port, "Sequence Number" : sequence_number,
        "Acknowledge Number" : ack_number, "Offset" : offset, "TCP flag" : tcp_flag, "Window Size" : window, "Checksum" : checksum,
        "Urgent Pointer" : urgent}
        return data