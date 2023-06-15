import os, time, uuid
import math, statistics
import requests
import logging
import itertools

from datetime import datetime
from collections import Counter, deque
from typing import NamedTuple
from enum import Enum

# Local imports
import aud_conn

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

class Direction(Enum):
    FWD = 0
    REV = 1

class Category(Enum):
    Undefined = 1
    NovelFlow = 2
    FrequentFlow = 3
    PacketExchangeMimatch = 4

class Severity(Enum):
    Unknown = 1
    Benign = 2
    Suspicious = 3
    Alarming = 4

class Anomaly():
    def __init__(self, category=Category.Undefined, conn=None):
        self.time = datetime.now().replace(microsecond=0)
        self.uuid = uuid.uuid4()
        self.conn = conn

        self.category = category
        self.severity = Severity.Unknown
        self.score = 0.0

        self.post_to_dht()

    def as_dict(self):
        acl_key = self.conn.get_acl_key()

        return {
            "uuid": str(self.uuid),
            "time": str(self.time),
            "category": str(self.category.name),
            "severity": str(self.severity.name),
            "score": str(round(self.score, 3)),
            "details": {
                "direction": str(acl_key.direction),
                "proto": l4proto[acl_key.proto]+":"+str(acl_key.svc_port),
                "addr": str(acl_key.addr),
                "ip_ver": acl_key.ip_ver,
            }
        }

    def post_to_dht(self):
        payload = {
            "RequestPostTopicUUID": {
                "topic_name": "TestTopic",
                "topic_uuid": "FIXTHIS",
                "value": {
                    "description": "AUD Anomaly",
                    "acl_key": str(self.conn.get_acl_key()),
                    # To be populated
                }
            }
        }

        try:
            post_response = requests.post("http://localhost:3000/pub", json=payload)
            res = post_response.json()
        except Exception as e:
            logging.debug("post_to_dht() failed. Reason: %s", str(type(e).__name__))
            res = {"exception": str(type(e).__name__)}

        return res


class Bucket():
    def __init__(self):
        self.values = [[],  # FWD
                       []]  # REV

    def add(self, plen, direction):
        self.values[direction].append(plen)

    def get_mean(self, direction):
        # Needs a redesign after input changed
        #return statistics.mean(self.values[direction])
        return 1

    def get_mean_stdev(self, direction):
        mean = self.get_mean(direction)
        stdev = statistics.stdev(self.values[direction], mean)
        return (mean, stdev)


class TimeSeries():
    def __init__(self, t0):
        self.created = t0

        self.time = []
        self.value = []
        self.direction = []

        self.bucket_tspan = 60 * 1000000000
        self.buckets = [Bucket()]

    def __len__(self):
        assert len(self.time) == len(self.value) == len(self.direction)
        return len(self.time)

    def __str__(self):
        output = ""
        for t, v, d in zip(self.time, self.value, self.direction):
            output += "d: "+str(d)+"  |  t: "+str(t).rjust(10)+"  |  v: "+str(v).rjust(6)+"\n"
        return output.rstrip()

    def add(self, t, val, direction):
        t -= self.created

        if len(self) < 20:
            self.time.append(t)
            self.value.append(val)
            self.direction.append(direction)

        if t > (len(self.buckets) * self.bucket_tspan):
            self.buckets.append(Bucket())

        self.buckets[-1].add(val, direction)

    def total_bytes(self):
        fwd_bytes = []
        rev_bytes = []

        for d, val in zip(self.direction, self.value):
            fwd_bytes.append(val) if d == Direction.FWD.value else rev_bytes.append(val)

        #logging.debug("fwd_bytes %d, rev_bytes %d", sum(fwd_bytes), sum(rev_bytes))
        return (sum(fwd_bytes), sum(rev_bytes))

    def pep(self):
        return "".join(map(str, self.direction))


class TimeSeriesAggregator():
    def __init__(self):
        self.samples = 0
        #self.timeseries = []

        self.fwd_totals = list()
        self.rev_totals = list()

        self.buckets = []
        #self.pep_dist = Counter()
        self.peps = [] # Packet Exchange Patterns

    def __len__(self):
        return self.samples

    def as_dict(self):
        res = {
            "samples": self.samples,
            #"buckets": str(self.buckets),
            "pep_dist": self.pep_distribution(),
            "total_bytes": {
                "fwd": str(self.fwd_totals),
                "rev": str(self.rev_totals),
            }
        }
        return res

    def add(self, data): # data is of type TimeSeries
        print("*****")
        print("lengths before: "+str(len(self.buckets))+" / "+str(len(data.buckets)))

        if len(self.buckets) < len(data.buckets):
            self.buckets.extend([Bucket() for _ in range(len(data.buckets)-len(self.buckets))])

        print("lengths after:  "+str(len(self.buckets))+" / "+str(len(data.buckets)))


        for i, bucket in enumerate(data.buckets):
            print(str(i)+": "+str(bucket.get_mean(0)))

        pass

    def add_total_bytes(self, bytes_tuple):
        fwd_bytes, rev_bytes = bytes_tuple
        self.fwd_totals.append(fwd_bytes)
        self.rev_totals.append(rev_bytes)

    def add_pep(self, pep):
        self.peps.append(pep)

    def stats_update(self):
        pass

    def pep_distribution(self):
        return Counter(self.peps)


class AUDRecord:
    def __init__(self, aud_handle):
        self.aud = aud_handle
        self.last_updated = 0
        self.remote_as = None
        self.aggregator = TimeSeriesAggregator()


    def as_dict(self):
        return {
            "last_updated": self.last_updated,
            "remote_as": str(self.remote_as),
            "aggregator": self.aggregator.as_dict()
        }

    def process(self, connlist):
        for conn in connlist:
            #logging.debug("  %s", str(conn))

            if self.remote_as is None:
                self.aud.anomalies.append(Anomaly(category=Category.NovelFlow, conn=conn))
                ### TODO: Resolve remote AS based on acl_key.addr
                self.remote_as = "Unresolved/FIXTHIS"

            # AS score and evaluation TODO

            if conn.active():
                # Do not aggregate stats over partial flow records
                continue

            # Do processing / bookkeping here
            self.aggregator.add_total_bytes(conn.data.total_bytes())
            self.aggregator.add_pep(conn.data.pep())

            self.last_updated = time.time()

            # Finally:
            conn.marked_for_deletion = True


    def evaluate(self, category, conn):
        logging.debug("evaluation")


class AUD:
    def __init__(self):
        self.global_conn_counter = 0
        self.last_updated = 0
        self.records = dict()
        self.anomalies = deque()


    def as_dict(self):
        res = {
            "global_conn_counter": str(self.global_conn_counter),
            "aud_records": [{"acl_key": str(key), "data": self.records[key].as_dict()} for key in self.records.keys()],
        }
        return res


    def update(self, connlist):

        acl_keys = connlist.aggregate_acl_keys()

        for key in acl_keys:
            logging.debug("%s", str(key))
            if key not in self.records:
                self.records[key] = AUDRecord(self)

            self.records[key].process(connlist.conns_by_acl_key(key))

    def anomaly_wrapper(self):
        return [anomaly.as_dict() for anomaly in self.anomalies]

    def anomaly_iterator(self):
        for anomaly in self.anomalies:
            yield anomaly.as_dict()
