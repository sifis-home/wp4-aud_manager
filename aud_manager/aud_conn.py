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
    def __init__(self):
        self.lookup = dict()
        self.conns = list()
        self.timeout = 60*1000000


    def __str__(self):
        out = "ConnList:\n"
        out += "    connlist length: "+str(len(self.conns))+"\n"
        out += "    lookup list length: "+str(len(self.lookup))+"\n"
        out += "    lookup:\n"
        for key, conn in self.lookup.items():
            out += "        "+str(conn.key)+"\n"
        out += "    conns:\n"
        for conn in self.conns:
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
        for idx in range(len(self.conns)-1, -1, -1):
            if self.conns[idx].expired and self.conns[idx].src_proc and self.conns[idx].dst_proc:
                del self.conns[idx]


    def add(self, src, dst, proto, sport, dport, flags, plen, t):
        flags = Flags(True if "syn" in flags else False,
                      True if "ack" in flags else False)

        if sport >= dport:
            key, idx = ConnKey(proto, src.handle, dst.handle, sport, dport), 0
        else:
            key, idx = ConnKey(proto, dst.handle, src.handle, dport, sport), 1

        if key not in self.lookup:
            ce = ConnEntry(key, src.ip_ver, t)
            self.conns.append(ce)
            self.lookup[key] = self.conns[-1]

            src.add_conn(ce)
            dst.add_conn(ce)

        self.lookup[key].append(idx, plen, t, flags)



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
        out += "    self.getrefcount: "+str(sys.getrefcount(self))+"\n"
        out += "    src proc: "+str(self.src_proc)+"\n"
        out += "    dst proc: "+str(self.dst_proc)+"\n"
        out += "    last updated: "+str(self.last_updated)+"\n"
        for serie in self.timeseries:
            out += "    serie "+str(count)+": "+str(serie)+"\n"
            count += 1
        return out


    def append(self, idx, plen, t, flags):
        self.last_updated = t
        self.timeseries[idx].append(plen, t, flags)
