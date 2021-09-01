import struct
import binascii
import socket

class unpack:
    def __cinit__(self):
        self.data=None

    # Ethernet Header
    def eth_header(self, data):

        # format - 6s=string type for source/destination MAC addresses - H=unsigned short for ethernet protocol type
        storeobj = struct.unpack("!6s6sH",data)

        destination_mac=binascii.hexlify(storeobj[0])
        source_mac=binascii.hexlify(storeobj[1])
        eth_protocol=storeobj[2]

        data={"Destination Mac":destination_mac, "Source Mac":source_mac, "Protocol":eth_protocol}
        return data