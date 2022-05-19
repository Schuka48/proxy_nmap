import socket
import threading
import struct
import sys


def ethernet_header(raw_data):
    dest_mac, source_mac, proto = struct.unpack("! 6s 6s H", raw_data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(source_mac), socket.htons(proto), raw_data[14:]


def get_mac_addr(bytes_addr):
    str_bytes = map("{:02x}".format, bytes_addr)
    mac_addr = ":".join(str_bytes).upper()
    return mac_addr


def get_ip_addr(addr):
    return ".".join(map(str, addr))


def ipv4_header(raw_data):
    version_header_length = raw_data[0]
    version = version_header_length >> 4
    ihl_value = version_header_length & 0xF
    header_length = ihl_value * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])
    data = raw_data[header_length:]
    return version, header_length, ttl, proto, get_ip_addr(src), get_ip_addr(target), data


def tcp_head(raw_data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', raw_data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    data = raw_data[offset:]
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data


def icmp_head(raw_data):
    type_, code, checksum, other = struct.unpack('! s s L H', raw_data[:8])
    return type_, checksum, other


def get_port(bytes):
    return str(bytes)


def udp_head(raw_data):
    s_port, d_port, lenght = struct.unpack('! H H H', raw_data[:6])
    return get_port(s_port), get_port(d_port), lenght


def main():
    serv = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    while True:
        raw_data, addr = serv.recvfrom(65535)
        eth = ethernet_header(raw_data)
        print("\nEthernet Frame:")
        print(f"Destination: {eth[0]}, Source: {eth[1]}, Protocol: {eth[2]}")
        if eth[2] == 8:
            ipv4 = ipv4_header(eth[3])
            print('\t - ' + 'IPv4 Packet:')
            print(f'\t\t -  Version: {ipv4[0]} Header Length: {ipv4[1]} TTL: {ipv4[2]}')
            print(f'\t\t -  Protocol: {ipv4[3]} Source: {ipv4[4]} Destination: {ipv4[5]}')
            if ipv4[3] == 6:
                tcp = tcp_head(ipv4[6])
                print('\t' + 'TCP Segment:')
                print('\t\t' + 'Source Port: {}, Destination Port: {}'.format(tcp[0], tcp[1]))
                print('\t\t' + 'Sequence: {}, Acknowledgment: {}'.format(tcp[2], tcp[3]))
                print('\t\t' + 'Flags:')
                print('\t\t\t' + 'URG: {}, ACK: {}, PSH:{}'.format(tcp[4], tcp[5], tcp[6]))
                print('\t\t\t' + 'RST: {}, SYN: {}, FIN:{}'.format(tcp[7], tcp[8], tcp[9]))
            elif ipv4[3] == 1:
                icmp = icmp_head(ipv4[6])
                print('\t -' + 'ICMP Packet:')
                print('\t\t -' + 'Type: {}, Code: {}, Checksum:{},'.format(icmp[0], icmp[1], icmp[2]))
                print('\t\t -' + 'ICMP Data:')
                print('\t\t\t', icmp[3])
            elif ipv4[4] == 17:
                udp = udp_head(ipv4[6])
                print('\t -' + 'UDP Segment:')
                print('\t\t -' + 'Source Port: {}, Destination Port: {}, Length: {}'.format(udp[0], udp[1], udp[2]))


if __name__ == '__main__':
    main()
