"""Module that holds the basic icmp tunnel functions

Attributes:
    ICMP_BUFFER_SIZE (int): Maximum ICMP packet size
    TCP_BUFFER_SIZE (int): Maximum TCP packet size
"""
import socket
import select
import Icmp
from Logger import logger

TCP_BUFFER_SIZE = 1024
ICMP_BUFFER_SIZE = 65565

class Tunnel(object):

    """General class for all tunnel objects that need to run

    Knows how to create a TCP and ICMP sockets
    """

    @staticmethod
    def CreateIcmpSocket():
        """Create a Raw ICMP socket for sending and receiving

        Returns:
            socket: Raw ICMP socket
        """
        # Doesn't handle errors, calling function should
        logger.Log("DEBUG", "ICMP socket created")
        return socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

    @staticmethod
    def CreateTcpSocket(dst, server=False):
        """Create a TCP socket with given destination. Binds/Connects to ip depending on params

        Args:
            dst ((IP, Port)): Destination to connect to
            server (bool, optional): If true we bind to dst instead of connecting
        """
        logger.Log("DEBUG", "TCP socket created on {}.{}".format(dst[0], dst[1]))
        # Create reusable socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # If we are a server then bind, else connect to to destination
        if server:
            sock.bind(dst)
        else:
            sock.connect(dst)

        return sock

    def Run(self):
        """Run on sockets on we receive data on one
        """
        while True:
            socketsRead, _, _ = select.select(self.sockets, [], [])
            for sock in socketsRead:
                if sock.proto == socket.IPPROTO_ICMP:
                    self.HandleIcmp(sock)
                else:
                    self.HandleTcp(sock)

class Server(Tunnel):

    """ICMP Tunnel Server.

    Waits for ICMP packets, parses them and passes them forward as TCP

    Attributes:
        dst ((IP, Port)): Destination of pc we have a TCP connection with. This is the TCP server data
        icmpSocket (socket): Socket that receives and sends the ICMP data
        sockets (list): List of sockets to wait for data for them
        src ((Ip, Port)): Destination of pc that is initializing the TCP connection over the tunnel
        tcpSocket (socket): Socket that is connected to the destination TCP
    """

    def __init__(self):
        """Creates an ICMP Socket that will wait for a packet from the client on Run
        """
        self.src = None
        self.dst = None
        self.tcpSocket = None
        self.icmpSocket = Tunnel.CreateIcmpSocket()
        self.sockets = [self.icmpSocket]

    def HandleIcmp(self, socket):
        """Handle a received ICMP packet (from the client).
        Reads the ICMP packet and forwards the payload as a TCP packet to the TCP server.

        Args:
            socket (socket): ICMP socket that has data to read from
        """
        # Read and parse data
        packet, address = socket.recvfrom(ICMP_BUFFER_SIZE)

        try:
            packet = Icmp.IcmpPacket.Parse(packet)
        except Exception as x:
            logger.Log("DEBUG", "Failed parsing packet")
            return

        self.src = address[0]
        self.dst = packet.dst

        # If this is not an IcmpTunnelPacket ignore it
        if packet.magic != Icmp.IcmpPacket.MAGIC:
            return

        # Skip our packets
        if packet.type == Icmp.ICMP_ECHO_REPLY and packet.code == 0:
            logger.Log("DEBUG", "Failed parsing packet")
            return

        # Close requested
        if packet.type == Icmp.ICMP_ECHO_REQUEST and packet.code == 1:
            self.sockets.remove(self.tcpSocket)
            self.tcpSocket.close()
            self.tcpSocket = None
            logger.Log("INFO", "Client closed")
            return

        # Create socket if it doesnt exist
        if not self.tcpSocket:
            self.tcpSocket = self.CreateTcpSocket(self.dst)
            self.sockets.append(self.tcpSocket)
            logger.Log("INFO", "Client joined")

        # Send the packet
        self.tcpSocket.send(packet.payload)

    def HandleTcp(self, sock):
        """Handle a packet from the TCP connection.
        Reads the packet and forwards it over ICMP to the client ICMP tunnel.

        Args:
            sock (socket): Socket that we got the data from
        """
        # Read tcp data
        data = sock.recv(TCP_BUFFER_SIZE)

        # Wrap the data with an ICMP packet and send it to the client
        packet = Icmp.IcmpPacket(Icmp.ICMP_ECHO_REPLY, 0, 0, 0, 0, data, self.src, self.dst)
        self.icmpSocket.sendto(packet.Create(), (self.src, 0))


class Client(Tunnel):

    """ICMP Tunnel Client.

    Attributes:
        dst ((IP, Port)): Destination of the server TCP
        icmpSocket (socket): Socket that receives and sends the ICMP data
        proxy (string): IP address of the ICMP tunnel server
        sockets (list): List of sockets to wait for data for them
        tcpSocket (socket): Socket that is connected to the destination TCP
    """

    def __init__(self, proxy, sock, dst):
        """Creates a ICMP tunnel client that connects to the ICMP tunnel server and sends its tcp there.

        Args:
            proxy (string): IP address of the ICMP tunnel server
            sock (socket): The tcp socket that started the tunnel
            dst ((IP, Port)): Destination of the server TCP
        """
        self.proxy = proxy
        self.tcpSocket = sock
        self.dst = dst
        self.icmpSocket = self.CreateIcmpSocket()
        self.sockets = [self.tcpSocket, self.icmpSocket]

    def HandleIcmp(self, sock):
        """Handle a received ICMP packet (from the server).
        Reads the ICMP packet and forwards the payload as a TCP packet to the TCP client.

        Args:
            sock (socket): Our socket that received the ICMP data
        """

        # Get the data and try to parse it
        data, _ = sock.recvfrom(ICMP_BUFFER_SIZE)

        try:
            packet = Icmp.IcmpPacket.Parse(data)
        except:
            # Might not be our packet so the parsing will fail
            return

        # If this is not an IcmpTunnelPacket ignore it
        if packet.magic != Icmp.IcmpPacket.MAGIC:
            return

        # We send ICMP echo requests so ignore them
        if packet.type != Icmp.ICMP_ECHO_REQUEST:
            self.tcpSocket.send(packet.payload)

    def HandleTcp(self, sock):
        """Handle a packet from the TCP connection.
        Reads the packet and forwards it over ICMP to the server ICMP tunnel.

        Args:
            sock (socket): Socket that we got the data from
        """
        data = sock.recv(TCP_BUFFER_SIZE)

        # Build a ICMP packet with our TCP packet as the payload and send it to the server
        code = 0 if len(data) > 0 else 1
        packet = Icmp.IcmpPacket(Icmp.ICMP_ECHO_REQUEST, code, 0, 0, 0, data, self.tcpSocket.getsockname(), self.dst)
        self.icmpSocket.sendto(packet.Create(), (self.proxy, 1))

        # Connection closed, no data
        if code == 1:
            logger.Log("INFO", "Connection closed")
            exit()


class ClientProxy(Tunnel):

    """Waits for an incoming TCP connection and opens the connection to the server when received.

    Attributes:
        dst ((IP, Port)): Destination of the TCP server we want to connect to
        local ((IP, Port)): Destination of the requesting TCP client
        proxy (string): IP of the ICMP tunnel server
        tcpSocket (socket): Opened socket with the TCP client
    """

    def __init__(self, proxy, localHost, localPort, dstHost, dstPort):
        """Proxy of the Client Class. Creates a TCP connection and passes it to the client to handle the data

        Args:
            proxy (string): IP of the ICMP tunnel server
            localHost (string): Our TCP IP to bind to
            localPort (int): Our TCP port to bind to
            dstHost (string): Server TCP IP that we want to connect to
            dstPort (int): Server TCP IP that we want to connect to
        """
        self.proxy = proxy
        self.local = (localHost, localPort)
        self.dst = (dstHost, dstPort)
        self.tcpSocket = Tunnel.CreateTcpSocket(self.local, server=True)

    def Run(self):
        """Runs the proxy.
        Waits for a TCP connection and passes it forward to the Client class to parse
        """
        logger.Log("INFO", "Waiting for TCP connection")
        self.tcpSocket.listen(1)
        sock, addr = self.tcpSocket.accept()
        client = Client(self.proxy, sock, self.dst)
        client.Run()



