import os, sys, time, threading
import socket
import struct
import binascii
import ipaddress
from typing import NamedTuple

ETH_HEADER_L = 14


class IPv4Packet(NamedTuple):
    ts: int
    length: int
    ttl: int
    proto: int
    src: ipaddress.IPv4Address
    dst: ipaddress.IPv4Address
    direction: int # AF_PACKET -> pkttype: PACKET_HOST=0, PACKET_OUTGOING=4

class IPv6Packet(NamedTuple):
    ts: int
    payload_len: int
    proto: int # next_header
    hop_limit: int
    src: ipaddress.IPv6Address
    dst: ipaddress.IPv6Address
    direction: int

class ICMPHeader(NamedTuple):
    msg_type: int
    code: int

class TCPHeader(NamedTuple):
    sport: int
    dport: int
    flags: bytes

class UDPHeader(NamedTuple):
    sport: int
    dport: int
    length: int


class PacketReader(threading.Thread):
    def __init__(self, buf):
        threading.Thread.__init__(self)
        self.buf = buf
        self.running = True
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003)) # ETH_P_ALL

    def stop(self):
        self.running = False

    def run(self):
        for pkt in self.sock_reader():
            self.buf.append(pkt)

    def sock_reader(self):

        while self.running:
            l3hdr = l4hdr = None

            data, addr = self.sock.recvfrom(65535)

            seek = ETH_HEADER_L
            ethernet_header = struct.unpack("! 6s 6s 2s", data[0:seek])
            ethertype = int.from_bytes(ethernet_header[2], "big")

            if ethertype == 0x0800:
                # ETHERTYPE_IPV4
                l3hdr, hlen = self.parse_ipv4_header(addr[2], data[seek:])

            elif ethertype == 0x86dd:
                # ETHERTYPE_IPV6
                l3hdr, hlen = self.parse_ipv6_header(addr[2], data[seek:])

            if not l3hdr:
                continue

            if not (l3hdr.direction == socket.PACKET_HOST or
                    l3hdr.direction == socket.PACKET_OUTGOING):
                continue

            seek += hlen

            if l3hdr.proto == 0x01:   # ICMP
                l4hdr = self.parse_icmp_header(data[seek:])

            elif l3hdr.proto == 0x06: # TCP
                l4hdr = self.parse_tcp_header(data[seek:])

            elif l3hdr.proto == 0x11: # UDP
                l4hdr = self.parse_udp_header(data[seek:])

            if not l4hdr:
                continue

            yield l3hdr, l4hdr


    # Layer 3 parsers
    def parse_ipv4_header(self, direction, data):
        ihl = (data[0] & 0x0f) * 4
        length, ttl, proto, src_addr, dst_addr = struct.unpack("! 2x H 4x B B 2x 4s 4s", data[:20])
        src = ipaddress.ip_address(socket.inet_ntoa(src_addr))
        dst = ipaddress.ip_address(socket.inet_ntoa(dst_addr))
        return IPv4Packet(time.time_ns(), length, ttl, proto, src, dst, direction), ihl

    def parse_ipv6_header(self, direction, data):
        # To be implemented
        return None, 0

    # Layer 4 parsers
    def parse_icmp_header(self, data):
        msg_type, code = struct.unpack("! B B", data[:2])
        return ICMPHeader(msg_type, code)

    def parse_tcp_header(self, data):
        sport, dport, flags = struct.unpack("! H H 9x B", data[:14])
        return TCPHeader(sport, dport, flags)

    def parse_udp_header(self, data):
        sport, dport, length = struct.unpack("! H H H 2x", data[:8])
        return UDPHeader(sport, dport, length)

    def get_local_ip_addr(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Might want to catch an exception in case connect and/or getsockname fails
        s.connect(("8.8.8.8", 80))
        ipaddr = ipaddress.ip_address(s.getsockname()[0])
        s.close()
        return ipaddr
