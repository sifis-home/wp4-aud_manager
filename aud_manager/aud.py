import os, time, uuid
import math, statistics
import itertools

from datetime import datetime
from collections import Counter, deque
from typing import NamedTuple

l4proto = {1: "ICMP",
           2: "IGMP",
           6: "TCP",
           17: "UDP"}

class ACLKey(NamedTuple):
    ip_ver: int
    direction: str
    proto: int
    addr: str
    svc_port: int

class Anomaly():
    def __init__(self, category=None, conn=None):
        self.time = datetime.now().replace(microsecond=0)
        self.uuid = uuid.uuid4()
        self.category = category
        self.score = 0.0
        self.conn = conn

    def __str__(self):
        output  = "    uuid:     "+str(self.uuid)+"\n"
        output += "    time:     "+str(self.time)+"\n"
        output += "    category: "+str(self.category)+"\n"
        output += "    conn:     "+str(self.conn)
        output += "        initial_pkt:     "+str(self.conn.initial_pkt)
        return output

    def as_dict(self):
        acl_key = self.conn.get_acl_key()

        return {
            "uuid": str(self.uuid),
            "time": str(self.time),
            "category": str(self.category),
            "score": str(round(self.score, 3)),
            "details": {
                "direction": str(acl_key.direction),
                "proto": l4proto[acl_key.proto]+":"+str(acl_key.svc_port),
                "addr": str(acl_key.addr),
                "ip_ver": acl_key.ip_ver,
                #"svc_port": str(acl_key.svc_port),
            }
        }

class Bucket():
    def __init__(self):
        self.values = []

    def add(self, val):
        self.values.append(val)


class TimeSeries():
    def __init__(self):
        self.time = []
        self.value = []
        self.direction = []

    def __str__(self):
        output = ""
        for t, v, d in zip(self.time, self.value, self.direction):
            output += "d: "+str(d)+"  |  t: "+str(t).rjust(10)+"  |  v: "+str(v).rjust(6)+"\n"
        return output.rstrip()

    def add(self, ts, val, direction):
        self.time.append(ts)
        self.value.append(val)
        self.direction.append(direction)

    def length(self):
        assert len(self.time) == len(self.value)
        return len(self.time)

    def pep(self):
        return "".join(map(str, self.direction))


class TimeSeriesAggregator():
    def __init__(self):
        self.samples = 0
        self.last_updated = 0
        self.timeseries = []
        self.peps = [] # Packet Exchange Patterns


    def __str__(self):
        output = "TimeSeriesAggregator\n"
        output += "sample size: "+str(self.samples)+"\n"
        output += "last_updated: "+str(self.last_updated)+"\n"
        output += "pep_distribution: "+str(self.pep_distribution())
        return output


    def add_ts(self, data):
        self.timeseries.append(data)
        self.samples += 1

    def update(self):
        self.stats_update()
        self.pep_update()
        self.last_updated = time.time()

    def stats_update(self):
        pass


    def pep_update(self):
        self.peps = []
        for ts in self.timeseries:
            self.peps.append(ts.pep())

    def pep_distribution(self):
        return Counter(self.peps)


class DataSeriesContainer():
    def __init__(self, t0):
        self.created = t0
        self.sample = TimeSeries()
        self.buckets = []

    def __str__(self):
        #output = "Sample:\n"+str(self.sample)
        #return output
        return str(self)

    def length(self, idx):
        print("FIXTHIS, ref to beginning")
        return self.beginning[idx].length()

    def append(self, direction, t, plen):
        t -= self.created

        if self.sample.length() < 20:
            # sample beginning of flow
            self.sample.add(t, plen, direction)

        if t < 10 * 1000000000:
            # long-term evolution of flow, TBI
            pass


class AUDRecord:
    def __init__(self):
        self.conn_counter = 0
        self.conns = list()
        self.aggregator = TimeSeriesAggregator()
        self.pep_dist = None

    def __str__(self):
        pad = "  "
        output = ""
        for conn in self.conns:
            output += pad*4+str(conn)
            output += str(conn.data)

        return output

    def as_dict(self):
        return {
            "conn_counter": self.conn_counter,
            "conns": [conn.as_dict() for conn in self.conns],
        }

    def add(self, conn):
        self.conns.append(conn)
        self.conn_counter += 1


    def calc_aggregate(self):
        #print("\n*** Debug section: calc_aggregate() ***")

        for conn in self.conns:
            #print(conn)
            #print(conn.data)

            self.aggregator.add_ts(conn.data.sample)


        self.aggregator.update()
        self.dir_dist = self.aggregator.pep_distribution()


class AUD:
    def __init__(self):

        self.global_conn_counter = 0
        self.last_updated = 0
        self.initial = True
        self.records = dict()
        self.anomalies = deque()

    def __str__(self):
        pad = "  "
        output = pad+"AUD:\n"
        output += pad*2+"initial: "+str(self.initial)+"\n"
        output += pad*2+"last updated: "+str(self.last_updated)+"\n"
        output += pad*2+"global conn counter: "+str(self.global_conn_counter)+"\n"
        output += pad*2+"records:\n"

        for key, val in self.records.items():
            output += pad*3+str(key)+", prevalence="
            output += str(round((val.conn_counter/self.global_conn_counter)*100, 2))+"%\n"
            output += str(val)+"\n"
        output += "Anomalies:\n"
        for anomaly in self.anomalies:
            output += str(anomaly)

        return output

    def as_dict(self):

        res = {
            "global_conn_counter": str(self.global_conn_counter),
            "aud_records": [{"acl_key": str(key), "data": self.records[key].as_dict()} for key in self.records.keys()],
        }
        return res


    def add_record(self, key, entry):
        self.global_conn_counter += 1
        if key not in self.records:
            #print(" -> key "+str(key)+" not in "+str(self.records))
            self.records[key] = AUDRecord()
            self.anomalies.append(Anomaly(category="NovelFlow", conn=entry))
        else:
            print("New flow: "+str(key))
            print("  --> Check for anomalies")
        self.records[key].add(entry)

    def update(self):
        #print("aud.py:update()")
        self.last_updated = int(time.time())

        for key in self.records.keys():
            #print(str(key))
            self.records[key].calc_aggregate()

    def anomaly_wrapper(self):
        return [anomaly.as_dict() for anomaly in self.anomalies]

    def anomaly_iterator(self):
        for anomaly in self.anomalies:
            yield anomaly.as_dict()

    def evaluate(self, conn):
        print(" *** Evaluate: "+str(conn)+" ***")
