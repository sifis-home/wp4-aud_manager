import os, time, uuid
import math, statistics
#import numpy as np
import itertools
from datetime import datetime
from collections import Counter, deque
from typing import NamedTuple

import aud_file

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
        self.conn = conn

    def __str__(self):
        output  = "    uuid:     "+str(self.uuid)+"\n"
        output += "    time:     "+str(self.time)+"\n"
        output += "    category: "+str(self.category)+"\n"
        output += "    conn:     "+str(self.conn)
        return output

    def as_dict(self):
        acl_key = self.conn.get_acl_key()

        return {
            "uuid": str(self.uuid),
            "time": str(self.time),
            "category": str(self.category),
            "details": {
                "ip_ver": str(acl_key.ip_ver),
                "direction": str(acl_key.direction),
                "proto": l4proto[acl_key.proto],
                "addr": str(acl_key.addr),
                "svc_port": str(acl_key.svc_port),
            }
        }


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
        print("TODO: stats_update()")
        pass


    def pep_update(self):
        self.peps = []
        for ts in self.timeseries:
            self.peps.append(ts.pep())

    def pep_distribution(self):
        return Counter(self.peps)


"""
class AggregatedTimeSeries(): #TimeSeries):
    def __init__(self):
        #super().__init__(aggregator=True)
        #print(self.aggr)
        self.samples = 0

        self.mean_time = []
        self.mean_value = []
        self.std_time = []
        self.std_value = []




        self.agg_times = []
        self.agg_values = []

        self.dir_strings = []



    def __str__(self):
        output = "AggregatedTimeSeries\n"
        output += "sample size: "+str(self.samples)+"\n"
        #for d, t, t_std, v, v_std in zip(self.direction,
        #                                 self.time, self.time_std,
        #                                 self.value, self.value_std):
        #    output += "d: "+str(d)+" t: "+str(t).rjust(10)+" ("+str(t_std)+") "
        #    output += "d: "+str(d)+" t: "+str(v).rjust(6)+" ("+str(v_std)+")\n"

        output += "agg_times:   "+str(self.agg_times)+"\n"
        output += "agg_values:  "+str(self.agg_values)+"\n"
        output += "dir_strings: "+str(self.dir_strings)
        return output


    def add_ts(self, data):
        # data argument is of type TimeSeries

        if data.length() > len(self.agg_times):
            # extend aggregation arrays to the length of input timeserie
            n = data.length() - len(self.agg_times)
            self.agg_times.extend([[] for _ in range(n)])
            self.agg_values.extend([[] for _ in range(n)])

        for i in range(data.length()):
            self.agg_times[i].append(data.time[i])
            self.agg_values[i].append(data.value[i])

        self.dir_strings.append(data.dir_to_str())
        self.samples += 1


    def update(self):
        for t, v in zip(self.agg_times, self.agg_values):
            self.mean_time.append(round(statistics.mean(t), 3))
            self.mean_value.append(round(statistics.mean(v), 3))

            # Calculate variance only if there are enough data values
            if len(t) > 3:
                self.std_time.append(round(statistics.stdev(t), 3))
                self.std_value.append(round(statistics.stdev(v), 3))
            else:
                self.std_time.append(None)
                self.std_value.append(None)


    def dir_distribution(self):
        return Counter(self.dir_strings)
"""

class DataSeriesContainer():
    def __init__(self, t0):
        self.created = t0
        self.lastbucket = 0
        #self.beginning = [TimeSeries(),
        #                  TimeSeries()]

        self.sample = TimeSeries()

    def __str__(self):
        output = "Sample:\n"+str(self.sample)
        return output

    def length(self, idx):
        print("FIXTHIS, ref to beginning")
        return self.beginning[idx].length()

    def append(self, direction, t, plen):
        t -= self.created

        bucket_index = 0

        if t < 10 * 1000000000:
            # First 10 seconds of a flow are logged in more detail
            #print("-> 10 second bucket (short term data)")

            #if self.beginning[direction].length() < 5: # REMOVE THIS ONCE TESTING IS DONE
            #    self.beginning[direction].add(t, plen)
            if self.sample.length() < 10:
                self.sample.add(t, plen, direction)


        #elif t < 30 * 1000000000:
        #    print("-> 30 second bucket")
        #elif t < 60 * 1000000000:
        #    print("-> 60 second bucket")
        #elif t < 120 * 1000000000:
        #    print("-> 120 second bucket")
        #else:
        #    idx = t // (300 * 1000000000)
        #    print("-> 300 second bucket (idx="+str(idx)+")")

        #self.dataseries[direction]


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

    def add(self, conn):
        self.conns.append(conn)
        self.conn_counter += 1


    def calc_aggregate(self):
        print("\n*** Debug section: calc_aggregate() ***")

        for conn in self.conns:
            print(conn)
            print(conn.data)

            #mean.add_ts(conn.data.beginning[0])
            #self.aggregate.add_ts(conn.data.sample)

            self.aggregator.add_ts(conn.data.sample)


        self.aggregator.update()
        self.dir_dist = self.aggregator.pep_distribution()

        print(self.aggregator)
        print(self.pep_dist)


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

        """
        output += "        ACL \"from\":\n"
        for key, val in self.acl_from.items():
            output += "            "+str(key)+":\n"
            output += str(val)+"\n"

        output += "        ACL \"to\":\n"
        for key, val in self.acl_to.items():
            output += "            "+str(key)+":\n"
            output += str(val)+"\n"
        """
        return output

    def add_record(self, key, entry):
        self.global_conn_counter += 1
        if key not in self.records:
            print(" -> key "+str(key)+" not in "+str(self.records))
            self.records[key] = AUDRecord()
            self.anomalies.append(Anomaly(category="first-of-its-kind", conn=entry))
        self.records[key].add(entry)

    def update(self):
        print("aud.py:update()")
        self.last_updated = int(time.time())

        for key in self.records.keys():
            print(str(key))
            self.records[key].calc_aggregate()


    def anomaly_wrapper(self):
        return [anomaly.as_dict() for anomaly in self.anomalies]

    def anomaly_iterator(self):
        for anomaly in self.anomalies:
            yield anomaly.as_dict()

    def evaluate(self, conn):
        print(" *** Evaluate: "+str(conn)+" ***")
