"""ICMP tunnel

Runs TCP over ICMP packets.
"""
import argparse
from Tunnel import *
from Logger import logger

def main():
    """ICMP Tunnel, send TCP over ICMP

positional arguments:
  {client,server}       client - Run the client proxy (No flags needed)
                        server - Run the server proxy (All flags needed)

optional arguments:
  -h, --help            show this help message and exit
  -p PROXY_HOST, --proxy-host PROXY_HOST
                        IP of the server tunnel
  -lh LOCAL_HOST, --local-host LOCAL_HOST
                        Local IP for incoming TCP connections
  -lp LOCAL_PORT, --local-port LOCAL_PORT
                        Local port for incoming TCP connections
  -dh DESTINATION_HOST, --destination-host DESTINATION_HOST
                        Remote IP to send TCP connection to
  -dp DESTINATION_PORT, --destination-port DESTINATION_PORT
                        Remote port to send TCP connection to
  -v, --verbose         Print debug messages
    """
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter, description="ICMP Tunnel, send TCP over ICMP")

    # Add server or client
    parser.add_argument("type", choices=["client", "server"], help="client - Run the client proxy (No flags needed)\nserver - Run the server proxy (All flags needed)")
    parser.add_argument("-p", "--proxy-host", help="IP of the server tunnel")
    parser.add_argument("-lh", "--local-host", help="Local IP for incoming TCP connections")
    parser.add_argument("-lp", "--local-port", type=int, help="Local port for incoming TCP connections")
    parser.add_argument("-dh", "--destination-host", help="Remote IP to send TCP connection to")
    parser.add_argument("-dp", "--destination-port", type=int, help="Remote port to send TCP connection to")
    parser.add_argument("-v", "--verbose", default=False, action="store_true", help="Print debug messages")
    args = parser.parse_args()

    # Set the logger verbosity
    logger.SetVerbosity(args.verbose)

    if args.type == "server":
        logger.Log("INFO", "Starting server")
        Server().Run()

    else:
        # Make sure we have all params
        if  args.proxy_host is None or \
            args.local_host is None or \
            args.local_port is None or \
            args.destination_host is None or \
            args.destination_port is None:
            parser.error("client requires proxy,local and destination flags")

        logger.Log("INFO", "Starting client")
        ClientProxy(args.proxy_host, args.local_host, args.local_port, args.destination_host, args.destination_port).Run()


if __name__ == "__main__":
    main()