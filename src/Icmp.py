"""File to parse and create ICMP packet

Attributes:
    ICMP_ECHO_REPLY (int): ICMP echo reply constant
    ICMP_ECHO_REQUEST (int): ICMP echo request constant
"""
import socket
import struct
from Logger import logger

ICMP_ECHO_REPLY = 0
ICMP_ECHO_REQUEST = 8

class IcmpPacket(object):

    """Summary

    Attributes:
        checksum (int): Packets checksum
        code (int): ICMP packet code
        dst ((IP, Port)): Destination of the tcp packet that will receive the packet
        ICMP_HEADER (str): ICMP header parsing string
        ICMP_HEADER_SIZE (int): ICMP header size
        id (int): ICMP packet id
        IP_HEADER (str): IP packet header parsing string
        IP_HEADER_SIZE (int): IP header size
        MAGIC (int): Magic to validate its a tunnel packet
        magic (int): Magic to validate its a tunnel packet
        payload (bytearray): ICMP packet payload
        sequence (int): ICMP packet sequence
        srcIp (TYPE): Senders Ip
        type (TYPE): ICMP packet type
    """

    IP_HEADER =  "!BBHHHBBH4s4s"
    ICMP_HEADER =  "!BBHHH4sHL"
    MAGIC = 0x24426886

    IP_HEADER_SIZE = struct.calcsize(IP_HEADER)
    ICMP_HEADER_SIZE = struct.calcsize(ICMP_HEADER)

    def __init__(self, type, code, checksum, id, sequence, payload, srcIp, dst = (None, None), magic = IcmpPacket.MAGIC):
        """Holds information about an ICMP packet

        Args:
            type (int): ICMP packet type
            code (int): ICMP packet code
            checksum (int): ICMP packet checksum
            id (int): ICMP packet id
            sequence (int): ICMP packet sequence
            payload (bytearray): ICMP packet payload
            srcIp (IP): Senders Ip
            dst ((IP, Port), optional): Destination of the tcp packet that will receive the packet
            magic (int, optional): magic number for the IcmpTunnel
        """
        self.type = type
        self.code = code
        self.checksum = checksum
        self.id = id
        self.sequence = sequence
        self.payload = payload
        self.srcIp = srcIp
        self.dst = dst
        self.magic = magic

    def Create(self):
        """Creates a network ready ICMP packet from the saved data

        Returns:
            bytearray: Serialized ICMP packet data
        """
        logger.Log("DEBUG", "Creating ICMP packet")

        packStr = self.ICMP_HEADER
        packArgs = [self.type, self.code, 0, self.id, self.sequence, socket.inet_aton(self.dst[0]), self.dst[1], socket.inet_aton(self.magic)]

        # Add the payload
        if len(self.payload) > 0:
            packStr += "{}s".format(len(self.payload))
            packArgs.append(self.payload)

        # Add correct checksum
        checksum = self.Checksum(struct.pack(packStr, *packArgs))
        packArgs[2] = checksum

        return struct.pack(packStr, *packArgs)

    @classmethod
    def Parse(cls, packet):
        """Parses a received network packet into an ICMP packet

        Args:
            packet (bytearray): Network packet

        Returns:
            IcmpPacket: Parsed packet
        """
        rawIpPacket, rawIcmpPacket = packet[:IcmpPacket.IP_HEADER_SIZE], packet[IcmpPacket.IP_HEADER_SIZE:]
        ipPacket = struct.unpack(IcmpPacket.IP_HEADER, rawIpPacket)

        srcIp = ipPacket[8]

        # Get the payload
        payload = ""
        payloadSize = len(rawIcmpPacket) - IcmpPacket.ICMP_HEADER_SIZE
        if payloadSize > 0:
            payload = struct.unpack("{}s".format(payloadSize), rawIcmpPacket[IcmpPacket.ICMP_HEADER_SIZE:])[0]


        logger.Log("DEBUG", "Parsing ICMP packet, payload size {}".format(payloadSize))

        # Read the packet data
        type, code, checksum, id, sequence, dstIp, dstPort, magic = struct.unpack(IcmpPacket.ICMP_HEADER, rawIcmpPacket[:IcmpPacket.ICMP_HEADER_SIZE])

        # Convert to net data
        srcIp = socket.inet_ntoa(srcIp)
        dst = (socket.inet_ntoa(dstIp), dstPort)
        magic = socket.inet_ntoa(srcIp)

        return cls(type, code, checksum, id, sequence, payload, srcIp, dst, magic)


    @staticmethod
    def Checksum(packet):
        """Calculates a packet checksum

        Args:
            packet (bytearray): Array of bytes to calculates its checksum

        Returns:
            int: Calculated checksum
        """
        checksum = 0
        length = (len(packet) // 2) * 2

        # Sum everything
        for index in range(0, length, 2):
            checksum = (checksum + (packet[index] +  packet[index + 1]) * 256) & 0XFFFFFFFF

        # We have a leftover byte
        if length < len(packet):
            checksum = (checksum + packet[len(packet) - 1]) & 0XFFFFFFFF

        # Calculate the data
        checksum = (checksum >> 16) + (checksum & 0xFFFF)
        checksum = checksum + (checksum >> 16)

        answer = ~checksum & 0xFFFF
        answer = (answer >> 8) | ((answer << 8) & 0xFF00)
        return answer