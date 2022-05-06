import os, time
import math, statistics
from collections import Counter, deque
from typing import NamedTuple

import aud_file


class ACLKey(NamedTuple):
    ip_ver: int
    direction: str
    proto: int
    addr: str
    svc_port: int


class IntervalSerie():
    def __init__(self, t0):
        self.created = t0
        self.intervals = deque(maxlen=250)

    def __str__(self):
        return str(self.intervals)

    def length(self):
        return len(self.intervals)

    def append(self, plen, t, flags):
        t -= self.created
        self.intervals.append((t, plen, flags))

    def get(self):
        return list(self.intervals)



class AUDRecord:
    def __init__(self):
        ml = 1000

        self.last_modified = None
        self.samples_seen = 0

        self.last_event_time = 0
        self.event_times = deque(maxlen=ml)
        self.initial_pkt_sizes = deque(maxlen=ml)

        self.pkts = (deque(maxlen=100),
                     deque(maxlen=100))

        self.plens = (deque(maxlen=100),
                      deque(maxlen=100))

        self.flags = (deque(maxlen=100),
                      deque(maxlen=100))


    def __str__(self):
        out = "                "+str(type(self))+"\n"
        out += "                samples seen: "+str(self.samples_seen)+"\n"
        out += "                event times: "+str(self.event_times)+"\n"
        if self.samples_seen > 2:
            out += self.get_digest()
        return out


    def mean_and_std(self, array):
        # TODO: Return an error if array length is less than 2
        mean = round(statistics.mean(array), 3)
        std = round(statistics.stdev(array), 3)

        return (mean, std)


    def flag_distribution(self, array):
        syn, synack, ack, total = 0, 0, 0, 0

        for f in array:
            if f.syn and f.ack:
                synack += 1
            elif f.syn:
                syn += 1
            elif f.ack:
                ack += 1

            total += 1
        return (syn, synack, ack, total)


    def get_digest(self):
        out = ""

        interevent_times = list()
        carry = -1

        for this in sorted(self.event_times):
            if carry > 0:
                interevent_times.append(round((this - carry)/1000000, 3))
            carry = this


        out += "                interevent times: "+str(interevent_times)+"\n"
        out += "                mean interval times:  %s   (std. = %s)\n" % self.mean_and_std(interevent_times)

        out += "                mean packets (dir-0): %s   (std. = %s)\n" % self.mean_and_std(self.pkts[0])
        out += "                mean packets (dir-1): %s   (std. = %s)\n" % self.mean_and_std(self.pkts[1])

        out += "                mean plen (dir-0):    %s   (std. = %s)\n" % self.mean_and_std(self.plens[0])
        out += "                mean plen (dir-1):    %s   (std. = %s)\n" % self.mean_and_std(self.plens[1])

        fd = self.flag_distribution(self.flags[0])
        out += "                flags (dir-0):\n"
        out += "                    SYN     "+str(round((fd[0]/fd[3])*100, 2))+"%\n"
        out += "                    SYN-ACK "+str(round((fd[1]/fd[3])*100, 2))+"%\n"
        out += "                    ACK     "+str(round((fd[2]/fd[3])*100, 2))+"%\n"

        fd = self.flag_distribution(self.flags[1])
        out += "                flags (dir-1):\n"
        out += "                    SYN     "+str(round((fd[0]/fd[3])*100, 2))+"%\n"
        out += "                    SYN-ACK "+str(round((fd[1]/fd[3])*100, 2))+"%\n"
        out += "                    ACK     "+str(round((fd[2]/fd[3])*100, 2))+"%\n"
        return out



class AUD:
    def __init__(self, ep, device_name):
        self.ep = ep
        self.name = device_name
        self.last_updated = int(time.time())
        self.initial = True
        self.records = dict()


    def __str__(self):
        output = "    AUD:\n"
        output += "        initial: "+str(self.initial)+"\n"
        output += "        last updated: "+str(self.last_updated)+"\n"
        output += "        records:\n"
        for key, val in self.records.items():
            output += "            "+str(key)+":\n"
            output += str(val)
        return output


    def update_records(self, key, conns):
        if key not in self.records:
            self.records[key] = AUDRecord()

        rec = self.records[key]

        while len(conns) > 0:
            conn = conns.pop()

            rec.samples_seen += 1
            rec.event_times.append(conn.created)

            for i in (0, 1):
                rec.pkts[i].append(conn.timeseries[i].length())
                rec.plens[i].append(sum(plen for t, plen, f in conn.timeseries[i].get()))
                for datapoint in conn.timeseries[i].get():
                    rec.flags[i].append(datapoint[2])

            # indicate that processing on our behalf has been done
            if key.direction == "to":
                conn.dst_proc = True
            elif key.direction == "from":
                conn.src_proc = True


    def export_aud_model(self):
        # TODO
        pass


    def export_aud_file(self):

        aces = {("ipv4", "from"): [],
                ("ipv4", "to"): [],
                ("ipv6", "from"): [],
                ("ipv6", "to"): []}

        for entry, _ in self.records.items():
            key = ("ipv"+str(entry.ip_ver), entry.direction)
            value = (entry.proto, entry.addr, entry.svc_port)
            aces[key].append(value)

        af = aud_file.AUDFile(self.ep.handle)
        af.add_aces(aces)

        return af.assemble_mud()
