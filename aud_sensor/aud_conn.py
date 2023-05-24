import sys, time
import ipaddress

from typing import NamedTuple

# Local imports
import aud
import packetreader as pr


class ConnKey(NamedTuple):
    proto: int
    src_addr: str
    dst_addr: str
    #src_addr: ipaddress.ip_address
    #dst_addr: ipaddress.ip_address
    src_port: int
    dst_port: int

class Flags(NamedTuple):
    syn: bool
    ack: bool

class ConnList():
    def __init__(self, aud_handle):
        self.ah = aud_handle

        self.lookup = dict()
        self.conns = list()

        self.timeout = 60*1000000

    def __str__(self):
        out = "FIXTHIS ConnList:\n"
        out += "  conns length: "+str(len(self.conns))+"\n"
        out += "  lookup length: "+str(len(self.lookup))+"\n"
        out += "  lookup:\n"
        for key, conn in self.lookup.items():
            out += "    "+str(conn.key)+"\n"
        out += "  conns:\n"
        for conn in self.conns:
            out += "    "+str(conn.key)+"\n"
            out += str(conn)+"\n"
        return out

    def cleanup(self):
        for key in list(self.lookup.keys()):
            if self.lookup[key].active():
                continue

            # conn no longer active -> delete from lookup
            del self.lookup[key]

    def bind_conn_to_aud(self, ce):
        self.ah.local_ips.add(ce.local_ip)
        self.ah.aud.add_record(ce.get_acl_key(), ce)


    def connkeygen(self, proto, src, dst, sport, dport):
        if sport < dport:
            src, dst = dst, src
            sport, dport = dport, sport
        return ConnKey(proto, str(src), str(dst), sport, dport)

    def record(self, pkt):
        l3hdr, l4hdr = pkt

        try:
            sport, dport = l4hdr.sport, l4hdr.dport
        except AttributeError:
            # L4 protocols without port numbers, e.g. ICMP
            sport, dport = -1, -1

        key = self.connkeygen(l3hdr.proto, l3hdr.src, l3hdr.dst, sport, dport)

        if key not in self.lookup:
            entry = ConnEntry(key, l3hdr, l4hdr)
            self.conns.append(entry)
            self.lookup[key] = self.conns[-1]
            self.bind_conn_to_aud(entry)

        direction = 0 if l3hdr.direction == 0 else 1

        self.lookup[key].append(direction, l3hdr.ts, l3hdr.length, (None, None)) # TODO: flags


    def aggregate(self):
        acl_keys = set()

        for conn in self.conns:
            if conn.key.src_addr == conn.key.dst_addr:
                continue
            acl_keys.add(conn.get_acl_key())

        return acl_keys


class ConnEntry():
    def __init__(self, key, l3hdr, l4hdr): #ip_ver, t0):
        self.key = key

        if l3hdr.direction == pr.socket.PACKET_HOST:
            self.acl_direction = "to"
            self.acl_addr = l3hdr.src
            self.local_ip = l3hdr.dst

        elif l3hdr.direction == pr.socket.PACKET_OUTGOING:
            self.acl_direction = "from"
            self.acl_addr = l3hdr.dst
            self.local_ip = l3hdr.src

        if isinstance(l4hdr, pr.TCPHeader):
            self.timeout = 600
        elif isinstance(l4hdr, pr.UDPHeader):
            self.timeout = 120
        elif isinstance(l4hdr, pr.ICMPHeader):
            self.timeout = 30
        else:
            self.timeout = 60

        self.created = l3hdr.ts
        self.last_updated = l3hdr.ts
        self.last_accounted = 0
        self.data = aud.DataSeriesContainer(l3hdr.ts)


    def __str__(self):
        return str(self.key)+", active="+str(self.active())

    def active(self):
        return (self.last_updated > (time.time_ns() - (self.timeout * 1000000000)))

    def get_acl_key(self):
        return aud.ACLKey(ip_ver = self.local_ip.version,
                          direction = self.acl_direction,
                          proto = self.key.proto,
                          addr = self.acl_addr,
                          svc_port = self.key.dst_port)

    def append(self, direction, t, plen, flags):
        self.data.append(direction, t, plen)
        self.last_updated = t
