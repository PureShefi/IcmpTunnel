"""Module that holds the basic icmp tunnel functions

Attributes:
    ICMP_BUFFER_SIZE (int): Maximum ICMP packet size
    TCP_BUFFER_SIZE (int): Maximum TCP packet size
"""
import socket
import select

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
            TYPE: Raw ICMP socket
        """
        # Doesn't handle errors, calling function should
        return socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

    @staticmethod
    def CreateTcpSocket(dst, server=False):
        """Create a TCP socket with given destination. Binds/Connects to ip depending on params

        Args:
            dst (TYPE): (IP, Port) to connect to
            server (bool, optional): If true we bind to dst instead of connecting
        """
        # Create reusable socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # If we are a server then bind, else connect to to destination
        if server:
            sock.bind(dst)
        else:
            sock.connect(dst)

    def Run(self):
        """Run on sockets on we receive data on one
        """
        while True:
            socketsRead, _, _ = select.select(self.sockets, [], [])
            for sock in socketsRead:
                if sock.proto == socket.IPPROTO_ICMP:
                    self.HandleIcmp(socket)
                else:
                    # TODO: change to dict of functions if possible
                    self.HandleTcp(socket)

class Server(Tunnel):

    """ICMP Tunnel Server.

    Waits for ICMP packets, parses them and passes them forward as TCP

    Attributes:
        dst (TYPE): (IP, Port) of pc we have a TCP connection with. This is the TCP server data
        icmpSocket (TYPE): Socket that receives and sends the ICMP data
        sockets (TYPE): List of sockets to wait for data for them
        src (TYPE): (Ip, Port) of pc that is initializing the TCP connection over the tunnel
        tcpSocket (TYPE): Socket that is connected to the destination TCP
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
            socket (TYPE): ICMP socket that has data to read from

        Returns:
            TYPE: Nothing
        """
        # Read and parse data
        packet, address = socket.recvfrom(ICMP_BUFFER_SIZE)

        try:
            packet = Icmp.IcmpPacket.Parse(packet)
        except:
            print("Failed parsing packet")
            return

        self.src = address[0]
        self.dst = packet.dst

        # Skip our packets
        if packet.type == Icmp.ICMP_ECHO_REQUEST and packet.code == 0:
            return

        # Close requested
        if packet.type == Icmp.ICMP_ECHO_REPLY and packet.code == 1:
            self.sockets.remove(self.tcpSocket)
            self.tcpSocket.close()
            self.tcpSocket = None
            return

        # Create socket if it doesnt exist
        if not self.tcpSocket:
            self.tcpSocket = self.CreateTcpSocket(self.dst)
            self.sockets.append(self.tcpSocket)

        # Send the packet
        self.tcpSocket.send(packet.data)

    def HandleTcp(self, sock):
        """Handle a packet from the TCP connection.
        Reads the packet and forwards it over ICMP to the client ICMP tunnel.

        Args:
            sock (TYPE): Socket that we got the data from
        """
        # Read tcp data
        data = sock.recv(TCP_BUFFER_SIZE)

        # Wrap the data with an ICMP packet and send it to the client
        packet = Icmp.IcmpPacket(Icmp.ICMP_ECHO_REPLY, 0, 0, 0, 0, data, self.src, self.dst)
        self.icmpSocket.sendTo(packet.Create(), (self.src, 0))


class Client(object):

    """ICMP Tunnel Client.

    Attributes:
        dst (TYPE): (IP, Port) of the server TCP
        icmpSocket (TYPE): Socket that receives and sends the ICMP data
        proxy (TYPE): IP address of the ICMP tunnel server
        sockets (TYPE): List of sockets to wait for data for them
        tcpSocket (TYPE): Socket that is connected to the destination TCP
    """

    def __init__(self, proxy, sock, dst):
        """Creates a ICMP tunnel client that connects to the ICMP tunnel server and sends its tcp there.

        Args:
            proxy (TYPE): IP address of the ICMP tunnel server
            sock (TYPE): The tcp socket that started the tunnel
            dst (TYPE): (IP, Port) of the server TCP
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
            sock (TYPE): Our socket that received the ICMP data

        Returns:
            TYPE: Nothing
        """

        # Get the data and try to parse it
        data, _ = sock.recvfrom(ICMP_BUFFER_SIZE)

        try:
            packet = Icmp.IcmpPacket.Parse(data)
        except:
            # Might not be our packet so the parsing will fail
            return

        # We send ICMP echo requests so ignore them
        if packet.type != Icmp.ICMP_ECHO_REQUEST:
            self.tcpSocket.send(packet.data)

    def HandleTcp(self, sock):
        """Handle a packet from the TCP connection.
        Reads the packet and forwards it over ICMP to the server ICMP tunnel.

        Args:
            sock (TYPE): Socket that we got the data from
        """
        data = sock.recv(TCP_BUFFER_SIZE)

        # Build a ICMP packet with our TCP packet as the payload and send it to the server
        code = 0 if len(data) > 0 else 1
        packet = Icmp.IcmpPacket(Icmp.ICMP_ECHO_REQUEST, code, 0, 0, 0, data, self.tcpSocket.getsockname(), self.dst)
        self.icmpSocket.sendto(packet.Create(), (self.proxy, 1))

        # Connection closed, no data
        if code == 1:
            exit()


class ClientProxy(Tunnel):

    """Waits for an incoming TCP connection and opens the connection to the server when received.

    Attributes:
        dst (TYPE): (IP, Port) of the TCP server we want to connect to
        local (TYPE): (IP, Port) of the requesting TCP client
        proxy (TYPE): IP of the ICMP tunnel server
        tcpSocket (TYPE): Opened socket with the TCP client
    """

    def __init__(proxy, localHost, localPort, dstHost, dstPort):
        """Proxy of the Client Class. Creates a TCP connection and passes it to the client to handle the data

        Args:
            proxy (TYPE): IP of the ICMP tunnel server
            localHost (TYPE): Our TCP IP to bind to
            localPort (TYPE): Our TCP port to bind to
            dstHost (TYPE): Server TCP IP that we want to connect to
            dstPort (TYPE): Server TCP IP that we want to connect to
        """
        self.proxy = proxy
        self.local = (localHost, localPort)
        self.dst = (dstHost, dstPort)
        self.tcpSocket = Tunnel.CreateTcpSocket(self.local, server=True)

    def Run(self):
        """Runs the proxy.
        Waits for a TCP connection and passes it forward to the Client class to parse
        """
        tcpSocket.listen(1)
        sock, addr = tcpSocket.accept()
        client = Client(proxy, sock, dst)
        client.Run()



