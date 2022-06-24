import struct
import socket
import ipaddress


def get_icmp(bytes):
    type_, code, chsum, other = struct.unpack('!BBHI', bytes[:8])
    data = bytes[8:]
    return type_, code, chsum, data


class Ethernet_frame:
    def __init__(self, buff):
        dst, src, self.prototype = struct.unpack('!6s6sH', buff[:14])  # ethernet кадр
        self.dst = self.get_mac(dst)
        self.src = self.get_mac(src)
        self.proto = socket.htons(self.prototype)
        self.data = buff[14:]

    @staticmethod
    def get_mac(bytes):
        str_bytes = map("{:02x}".format, bytes)
        mac: str = ":".join(str_bytes).upper()
        return mac


class ICMP_packet:
    def __init__(self, buff):
        self.type, self.code, self.chsum, _ = struct.unpack('!BBHI', buff[:8])
        self.mess = buff[8:]


class IP_packet:
    def __init__(self, buff):
        ip_header = struct.unpack('!BBHHHBBH4s4s', buff[:20])  # ip заголовок
        self.ver = ip_header[0] >> 4
        self.ihl = ip_header[0] & 0xF
        self.tos = ip_header[1]
        self.len = ip_header[2]
        self.id = ip_header[3]
        self.offset__flags = ip_header[4]
        self.ttl = ip_header[5]
        self.protocol_num = ip_header[6]
        self.sum = ip_header[7]
        self.src = ip_header[8]
        self.dst = ip_header[9]
        self.ip_src_address = ipaddress.ip_address(self.src)
        self.ip_dst_address = ipaddress.ip_address(self.dst)
        self.data = buff[20:]
        self.ICMP_packet = None
        if self.protocol_num == 1:
            print("HELLLLL")
            self.icmp_packet = ICMP_packet(self.data)



class TCP_packet:
    def __init__(self, buff):
        tcp_header = struct.unpack('!HHLLHHHH', buff)  ## tcp заголовок
        self.src_tcp_port = tcp_header[0]
        self.dst_tcp_port = tcp_header[1]
        self.sequence = tcp_header[2]
        self.acknowledgment = tcp_header[3]
        self.offset__reserv_flags = tcp_header[4]
        self.flag_urg = (self.offset__reserv_flags & 32) >> 5
        self.flag_ack = (self.offset__reserv_flags & 16) >> 4
        self.flag_psh = (self.offset__reserv_flags & 8) >> 3
        self.flag_rst = (self.offset__reserv_flags & 4) >> 2
        self.flag_syn = (self.offset__reserv_flags & 2) >> 1
        self.flag_fin = (self.offset__reserv_flags & 1)
        self.window_size = tcp_header[5]
        self.check_sum = tcp_header[6]
        self.urgent_point = tcp_header[7]


class UDP_packet:
    def __init__(self, buff):
        udp_header = struct.unpack('HHHH', buff)  ## udp заголовок
        self.src_udp_port = udp_header[0]
        self.dst_udp_port = udp_header[1]
        self.lenght = udp_header[2]
        self.check_sum = udp_header[3]


def get_packet_info(ether_fr):
    print('[Ethernet Frame]')
    print(f'\tDestination: {ether_fr.dst}, Source: {ether_fr.src}, Protocol: {ether_fr.proto}')

    if ether_fr.proto == 8:
        eth_buffer = ether_fr.data
        ip_header = IP_packet(eth_buffer)
        print('\t[IP Packet]')
        print(
            f'\t\tid: {ip_header.id},src: {ip_header.ip_src_address}, dst: {ip_header.ip_dst_address}, protocol: {ip_header.protocol_num}, version: {ip_header.ver}, ttl: {ip_header.ttl}, lenght of packet: {ip_header.len}')
        if ip_header.protocol_num == 6:
            offset = ip_header.ihl * 4
            buff = eth_buffer[offset:offset + 20]
            tcp_header = TCP_packet(buff)
            print('\t\t[TCP packet]')
            print(f'\t\t\tsrc port: {tcp_header.src_tcp_port}, dst port: {tcp_header.dst_tcp_port}')
            print(f'\t\t\tseq: {tcp_header.sequence}, ack: {tcp_header.acknowledgment}')
            print(
                f'\t\t\turg: {tcp_header.flag_urg}, ack: {tcp_header.flag_ack}, psh: {tcp_header.flag_psh}, rst: {tcp_header.flag_rst}, syn: {tcp_header.flag_syn}, fin: {tcp_header.flag_fin}')
            print(
                f'\t\t\tWindow size: {tcp_header.window_size}, CheckSum: {hex(tcp_header.check_sum)}, Urgent Point: {tcp_header.urgent_point}')
            print('\n')

        if ip_header.protocol_num == 17:
            offset = ip_header.ihl * 4
            buff = eth_buffer[offset: offset + 8]
            udp_header = UDP_packet(buff)
            print('\t\t[UDP packet]')
            print(
                f'\t\t\tsrc port: {udp_header.src_udp_port}, dst port: {udp_header.dst_udp_port}, length: {udp_header.lenght}, CheckSum:{hex(udp_header.check_sum)}')
            print('\n')

        if ip_header.protocol_num == 1:
            icmp_pack = ip_header.icmp_packet
            # offset = ip_header.ihl * 4
            # params = get_icmp(eth_buffer[offset:])
            print('\t\t[ICMP packet]')
            print(
                f'\t\t\ttype: {icmp_pack.type}, code: {icmp_pack.code}, checksum: {hex(icmp_pack.chsum)}, message:{icmp_pack.mess.decode()}')
