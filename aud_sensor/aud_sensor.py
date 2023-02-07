#!/usr/bin/python3
import sys, threading, signal
import time, math, queue

from collections import deque
from datetime import datetime, timedelta
from flask import Flask, request

# Local imports
import aud_conn
import aud

sys.path.append("../modules/")
import nflog_connector as nfc

l4proto = {1: "ICMP",
           2: "IGMP",
           6: "TCP",
           17: "UDP"}

class AUDSensor(threading.Thread):
    """Main thread for running AUD Sensor."""

    def __init__(self):
        threading.Thread.__init__(self)

        self.running = False
        self.learning = False
        self.start_t = None
        self.sigterm = threading.Event()
        self.log = list()

        self.local_net = "192.168.80.0/24" # TODO: read this from args or config file
        self.local_ips = set()
        self.acl_from = list()
        self.acl_to = list()

        #self.ep_pool = aud_endpoint.EndpointPool(self)
        self.aud_update_interval = 10 # seconds
        self.connlist = aud_conn.ConnList(self)
        self.anomalies = deque()
        self.raw_buf = deque()
        self.reader = nfc.NflogConnector(self.raw_buf)

    def __str__(self):
        out = "*** AUD sensor ***\n"
        out += "    running: "+str(self.running)+"\n"
        out += "    learning: "+str(self.learning)+"\n"
        if self.running:
            out += "    running since: "+str(self.start_t.strftime("%d-%m-%Y %H:%M:%S"))+"\n"
            uptime = datetime.now().replace(microsecond=0) - self.start_t.replace(microsecond=0)
            out += "    uptime: "+str(uptime)+"\n"
        out += "    local net: "+str(self.local_net)+"\n"
        out += "    my IPs: "+str(self.local_ips)+"\n"
        out += "    connlist length: "+str(len(self.connlist.connlist))+"\n"
        out += "    ACL:\n"
        out += "      from:\n"
        for k in self.acl_from:
            out += "        "+str(k)+"\n"
        out += "      to:\n"
        for k in self.acl_to:
            out += "        "+str(k)+"\n"
        return out

    def ingress(self, row):

        my_ip = row["dst_addr"] if int(row["dir"]) == 0 else row["src_addr"]
        self.local_ips.add(my_ip)

        try:
            sport, dport = int(row["src_port"]), int(row["dst_port"])
        except KeyError:
            # Protocols without ports, e.g., ICMP
            sport, dport = -1, -1

        try:
            flags = row["flags"].rstrip(",").split(",")
        except KeyError:
            flags = []

        self.connlist.add(int(row["t"]), int(row["dir"]), int(row["len"]),
                          row["src_addr"], row["dst_addr"], int(row["proto"]),
                          sport, dport, flags)

    def run(self):
        self.running = True
        self.learning = True
        self.reader.start()

        self.start_t = datetime.now()
        self.log_notify("AUD sensor started")

        # Clear buffer to avoid surge of packets at startup
        self.raw_buf.clear()

        aud_update_t = time.time() + self.aud_update_interval

        while self.running:
            for i in range(len(self.raw_buf)):
                self.ingress(self.raw_buf.popleft())

            self.connlist.cleanup()

            if aud_update_t < time.time():
                self.aud_update()
                aud_update_t = time.time() + self.aud_update_interval

            time.sleep(1)

        self.reader.stop()
        self.reader.join()

    def stop(self):
        self.running = False
        self.learning = False
        self.log_notify("AUD sensor stopped")

    def terminate(self):
        self.sigterm.set()
        self.stop()

    def log_notify(self, message):
        self.log.append(str(datetime.now().strftime("[%d/%b/%Y %H:%M:%S] "))+message)

    def log_anomaly(self, direction, addr, port, proto):
        a, b = "from", "to"
        if direction == "to": a, b = b, a

        out = "Unknown flow "+a.upper()+" device "+b+" "+addr
        out += ", svc_port="+str(port)+", protocol="+l4proto[int(proto)]
        out += " --> Queued for anomaly verdict"
        self.log_notify(out)

    def stop_learning(self, msg):
        self.learning = False
        self.log_notify("AUD learning ended ("+msg+")")
        return "OK\n"

    def aud_update(self):
        acl_from, acl_to = self.connlist.aggregate()

        for entry in acl_from:
            if entry not in self.acl_from:
                if self.learning:
                    self.acl_from.append(entry)
                elif entry not in self.anomalies:
                    self.anomalies.append(entry)
                    self.log_anomaly(entry.direction, entry.addr, entry.svc_port, entry.proto)

        for entry in acl_to:
            if entry not in self.acl_to:
                if self.learning:
                    self.acl_to.append(entry)
                elif entry not in self.anomalies:
                    self.anomalies.append(entry)
                    self.log_anomaly(entry.direction, entry.addr, entry.svc_port, entry.proto)


aud_sensor = AUDSensor()
app = Flask(__name__)


@app.route("/start")
def apicall_aud_sensor_start():
    if aud_sensor.running:
        return "Already running. Doing nothing.\n"
    if aud_sensor.start_t is not None:
        return "Cannot stop-start old thread. Re-run the parent program.\n"
    aud_sensor.start()
    return "OK\n"

@app.route("/stop")
def apicall_aud_sensor_stop():
    aud_sensor.stop()
    return "OK\n"

@app.route("/status")
def apicall_aud_sensor_status():
    return str(aud_sensor)

@app.route("/log")
def apicall_aud_log():
    return "\n".join(aud_sensor.log)+"\n"

# API endpoints for developer use
@app.route("/dev/aud-update")
def apicall_aud_update():
    return str(aud_sensor.aud_update())

@app.route("/dev/connlist")
def apicall_dump_connlist():
    return str(aud_sensor.connlist)

@app.route("/dev/force-stop-learning")
def apicall_aud_stop_learning():
    return str(aud_sensor.stop_learning("via "+request.path))


def terminate(sig, frame):
    aud_sensor.terminate()
    aud_sensor.join()
    sys.exit(0)


signal.signal(signal.SIGINT, terminate)
signal.signal(signal.SIGTERM, terminate)


app.run(host="0.0.0.0", port=5050)
