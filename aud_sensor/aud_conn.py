import sys, time
import aud

from typing import NamedTuple

class ConnKey(NamedTuple):
    proto: int
    src_addr: str
    dst_addr: str
    src_port: int
    dst_port: int

class Flags(NamedTuple):
    syn: bool
    ack: bool

class ConnList():
    def __init__(self, aud_handle):
        self.aud = aud_handle
        self.lookup = dict()
        self.connlist = list()
        self.timeout = 60*1000000

    def __str__(self):
        out = "ConnList:\n"
        out += "    connlist length: "+str(len(self.connlist))+"\n"
        out += "    lookup list length: "+str(len(self.lookup))+"\n"
        out += "    lookup:\n"
        for key, conn in self.lookup.items():
            out += "        "+str(conn.key)+"\n"
        out += "    connlist:\n"
        for conn in self.connlist:
            out += "        "+str(conn.key)+"\n"
        return out

    def cleanup(self):
        expiry_t = int(time.time_ns() / 1000) - self.timeout

        # Lookup cleanup
        for key in list(self.lookup.keys()):
            if self.lookup[key].last_updated < expiry_t:
                self.lookup[key].expired = True
                del self.lookup[key]

        # Prune connlist
        for idx in range(len(self.connlist)-1, -1, -1):
            if self.connlist[idx].expired and self.connlist[idx].src_proc and self.connlist[idx].dst_proc:
                del self.connlist[idx]

    def get_connkey(self, proto, src, dst, sport, dport):
        if sport < dport:
            src, dst = dst, src
            sport, dport = dport, sport
        return ConnKey(proto, src, dst, sport, dport)

    def add(self, t, direction, plen, src, dst, proto, sport, dport, flags):

        flags = Flags(True if "syn" in flags else False,
                      True if "ack" in flags else False)

        key = self.get_connkey(proto, src, dst, sport, dport)

        if key not in self.lookup:
            ce = ConnEntry(key, 4, t)
            self.connlist.append(ce)
            self.lookup[key] = self.connlist[-1]

        self.lookup[key].append(direction, plen, t, flags)


    def aggregate(self):

        acl_from = set()
        acl_to = set()

        for conn in self.connlist:
            if conn.key.src_addr == conn.key.dst_addr:
                continue

            if conn.key.src_addr in self.aud.local_ips:
                acl_from.add(aud.ACLKey(ip_ver=4, direction="from", proto=conn.key.proto,
                                        addr=conn.key.dst_addr, svc_port=conn.key.dst_port))

            if conn.key.dst_addr in self.aud.local_ips:
                acl_to.add(aud.ACLKey(ip_ver=4, direction="to", proto=conn.key.proto,
                                      addr=conn.key.src_addr, svc_port=conn.key.dst_port))

        return acl_from, acl_to


class ConnEntry():
    def __init__(self, key, ip_ver, t0):
        self.key = key
        self.ip_ver = ip_ver
        self.expired = False
        self.src_proc = False
        self.dst_proc = False
        self.created = t0
        self.last_updated = t0
        self.timeseries = [aud.IntervalSerie(t0),
                           aud.IntervalSerie(t0)]

    def __str__(self):
        count = 0
        out = str(self.key)+"\n"
        out += "    expired: "+str(self.expired)+"\n"
        out += "    created: "+str(self.created)+"\n"
        out += "    updated: "+str(self.last_updated)+"\n"
        out += "    self.getrefcount: "+str(sys.getrefcount(self))+"\n"
        #out += "    src proc: "+str(self.src_proc)+"\n"
        #out += "    dst proc: "+str(self.dst_proc)+"\n"
        for serie in self.timeseries:
            out += "    serie "+str(count)+": "+str(serie)+"\n"
            count += 1
        return out

    def append(self, idx, plen, t, flags):
        self.last_updated = t
        self.timeseries[idx].append(plen, t, flags)
