import argparse
from Tunnel import *

def main():
    parser = argparse.ArgumentParser(description="ICMP Tunnel, send TCP over ICMP")

    # Add server or client
    parser.add_argument("type", choices=["client", "server"])
    parser.add_argument("-p", "--proxy-host", help="IP of the server tunnel")
    parser.add_argument("-lh", "--local-host", default="127.0.0.1", help="Local IP for incoming TCP connections")
    parser.add_argument("-lp", "--local-port", type=int, help="Local port for incoming TCP connections")
    parser.add_argument("-dh", "--destination-host", help="Remote IP to send TCP connection to")
    parser.add_argument("-dp", "--destination-port", type=int, help="Remote port to send TCP connection to")
    args = parser.parse_args()

    if args.type == "server":
        Server().Run()

    else:
        ClientProxy(
                args["proxy-host"],
                args["local-host"],
                args["local-port"],
                args["destination-host"],
                args["destination-port"]
            ).Run()

if __name__ == "__main__":
    main()