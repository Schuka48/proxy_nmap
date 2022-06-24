import socket
import sys
import ipaddress
import struct
from functions import *


def Parser():
    listening_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    try:
        while True:
            buff, addr = listening_socket.recvfrom(65535)
            ether_fr = Ethernet_frame(buff)
            get_packet_info(ether_fr)
    except KeyboardInterrupt:
        print('\nStopped ...')
        print("By-By")
        sys.exit()


def main():
    Parser()


if __name__ == '__main__':
    main()
