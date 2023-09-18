import os, time, uuid
import math, statistics
import logging
import websocket
import json
import itertools

from datetime import datetime, timezone
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

class FreqKey(NamedTuple):
    ip_ver: int
    direction: str
    proto: int
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
    def __init__(self, category=Category.Undefined, conn=None, score=0.0):
        self.time = datetime.now(timezone.utc).replace(microsecond=0)
        self.uuid = uuid.uuid4()
        self.conn = conn

        self.topic_name = "SIFIS:AUD_Manager_Results"

        # Topic UUID has not been specified in detail.
        # This is an educated guess of what it potentially could contain.
        self.topic_uuid = uuid.uuid3(uuid.NAMESPACE_OID, self.topic_name)

        self.category = category
        self.severity = Severity.Unknown
        self.score = score

        self.post_to_dht()

    def as_dict(self):
        acl_key = self.conn.get_acl_key()

        if acl_key.proto == 1:
            svc_port = None
        else:
            svc_port = acl_key.svc_port

        details = {
            "direction": str(acl_key.direction),
            "proto": l4proto[acl_key.proto],
            "svc_port": str(svc_port),
            "addr": str(acl_key.addr),
            "ip_ver": acl_key.ip_ver,
        }

        return {
            "anomaly_uuid": str(self.uuid),
            "time": str(self.time),
            "category": str(self.category.name),
            "severity": str(self.severity.name),
            "score": str(round(self.score, 3)),
            "details": details
        }

    def post_to_dht(self):
        payload = {
            "RequestPostTopicUUID": {
                "topic_name": self.topic_name,
                "topic_uuid": str(self.topic_uuid),
                "value": {
                    "description": "AUD Anomaly",
                    "subject_ip": str(self.conn.local_ip),
                    "anomaly": str(self.as_dict()),
                }
            }
        }

        try:
            logging.debug("post_to_dht() payload: %s", str(json.dumps(payload)))
            ws = websocket.create_connection("ws://localhost:3000/ws")
            ws.send(json.dumps(payload))
            ws.close()

        except Exception as e:
            logging.debug("post_to_dht() failed. Reason: %s", str(type(e).__name__))

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

class FrequencyCounter:
    def __init__(self, ws, thresh):
        self.winsize = ws * 1000000000
        self.threshold = thresh
        self.counters = dict()
        self.connref = dict()

    def __str__(self):
        return str(self.counters)

    def add(self, conn):
        key = conn.get_freq_key()
        if key not in self.counters:
            self.counters[key] = []
            self.connref[key] = conn

        self.counters[key].append(conn.created_ns)

    def evaluate(self):
        now = time.time_ns()

        for counter, timestamps in self.counters.items():
            timestamps[:] = [ts for ts in timestamps if ts > (now - self.winsize)]
            if len(timestamps) > self.threshold:
                ratio = round((len(timestamps) / self.threshold), 3)
                yield Anomaly(category=Category.FrequentFlow, conn=self.connref[counter], score=ratio)


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
            if self.remote_as is None:
                #self.aud.anomalies.append(Anomaly(category=Category.NovelFlow, conn=conn))
                ### TODO: Resolve remote AS based on acl_key.addr
                self.remote_as = "Unresolved/FIXTHIS"

            if conn.new:
                self.aud.freq_counter.add(conn)
                conn.new = False

            if conn.active():
                # Do not aggregate stats over partial flow records
                continue

            # Do processing / bookkeping here
            self.aggregator.add_total_bytes(conn.data.total_bytes())
            self.aggregator.add_pep(conn.data.pep())

            self.last_updated = time.time()

            # Finally:
            conn.marked_for_deletion = True


    def evaluate(self):
        pass


class AUD:
    def __init__(self):
        self.global_conn_counter = 0
        self.last_updated = 0
        self.records = dict()
        self.freq_counter = FrequencyCounter(30, 30)
        self.anomalies = deque(maxlen=100)


    def as_dict(self):
        res = {
            "global_conn_counter": str(self.global_conn_counter),
            "aud_records": [{"acl_key": str(key), "data": self.records[key].as_dict()} for key in self.records.keys()],
        }
        return res


    def update(self, connlist):

        acl_keys = connlist.aggregate_acl_keys()
        logging.debug("Total ACL keys: %d", len(acl_keys))
        for key in acl_keys:
            #logging.debug("%s", str(key))
            if key not in self.records:
                self.records[key] = AUDRecord(self)

            self.records[key].process(connlist.conns_by_acl_key(key))

    def evaluate(self):
        count = 0
        for record in self.records.values():
            record.evaluate()

        for result in self.freq_counter.evaluate():
            self.anomalies.append(result)
            count += 1

        return count

    def mark_benign(self, input_uuid_string):
        if input_uuid_string == "all":
            self.anomalies.clear()
            return "OK"

        try:
            needle = uuid.UUID(input_uuid_string)
        except ValueError as ve:
            return str(type(ve).__name__)

        for anomaly in self.anomalies:
            if needle == anomaly.uuid:
                self.anomalies.remove(anomaly)
                return "OK"
        return "anomaly UUID not found"

    def anomaly_wrapper(self):
        return [anomaly.as_dict() for anomaly in self.anomalies]

    def anomaly_iterator(self):
        for anomaly in self.anomalies:
            yield anomaly.as_dict()
