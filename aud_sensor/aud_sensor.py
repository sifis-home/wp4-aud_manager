#!/usr/bin/python3
import sys, threading, signal
import time, math, queue
import json

from collections import deque
from datetime import datetime, timedelta
from flask import Flask, request

# Local imports
import aud
import aud_conn
import packetreader as pr


class AUDSensor(threading.Thread):
    """Main thread for running AUD Sensor."""

    def __init__(self):
        threading.Thread.__init__(self)

        self.running = False
        self.learning = False
        self.start_t = None
        self.sigterm = threading.Event()
        self.log = list()
        self.local_ips = set()

        self.aud = aud.AUD()
        self.aud_update_interval = 10 # seconds
        self.connlist = aud_conn.ConnList(self)

        self.raw_buf = deque()
        self.reader = pr.PacketReader(self.raw_buf)

    def __str__(self):
        pad = "  "
        out = "*** AUD sensor ***\n"
        out += pad+"running: "+str(self.running)+"\n"
        out += pad+"learning: "+str(self.learning)+"\n"
        if self.running:
            out += pad+"running since: "+str(self.start_t.strftime("%d-%m-%Y %H:%M:%S"))+"\n"
            uptime = datetime.now().replace(microsecond=0) - self.start_t.replace(microsecond=0)
            out += pad+"uptime: "+str(uptime)+"\n"

        out += pad+"my IPs: "+str(self.local_ips)+"\n"
        out += pad+"connlist length: "+str(len(self.connlist.conns))+"\n"
        #out += str(self.aud)

        return out

    def status(self):
        res = {
            "RequestPostTopicUUID": {
                "topic_name": "SIFIS:AUD_Manager_Results",
                "topic_uuid": "FIXTHIS",
                "value": {
                    "description": "aud_sensor",
                },
                "local_ip": [str(ip) for ip in self.local_ips],
                "anomalies": self.aud.anomaly_wrapper(),

            }
        }
        return json.dumps(res)

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
                self.connlist.record(self.raw_buf.popleft())

            self.connlist.cleanup()

            if aud_update_t < time.time():
                self.aud_update()
                aud_update_t = time.time() + self.aud_update_interval

            time.sleep(0.1)

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
        self.log.append(str(datetime.now().strftime("[%d/%b/%Y %H:%M:%S] "))+str(message))

    def log_anomaly(self, direction, addr, port, proto):
        a, b = "from", "to"
        if direction == "to": a, b = b, a

        out = "Unknown flow "+a.upper()+" device "+b+" "+addr
        out += ", svc_port="+str(port)+", protocol="+aud.l4proto[int(proto)]
        out += " --> Queued for anomaly verdict"
        self.log_notify(out)

    def stop_learning(self, msg):
        self.learning = False
        self.log_notify("AUD learning ended ("+msg+")")
        return "OK\n"

    def aud_update(self):
        acl_keys = self.connlist.aggregate()

        for key in acl_keys:
            if key not in self.aud.records:
                self.aud.records[key] = list()

        self.aud.update()

    def response(self, res):
        return json.dumps({"response": str(res)})


aud_sensor = AUDSensor()
app = Flask(__name__)


@app.route("/start")
def apicall_aud_sensor_start():
    if aud_sensor.running:
        return aud_sensor.response("Already running. Doing nothing.")
    if aud_sensor.start_t is not None:
        return aud_sensor.response("Cannot stop-start old thread. Re-run the parent program.")
    aud_sensor.start()
    return aud_sensor.response("OK")

@app.route("/stop")
def apicall_aud_sensor_stop():
    aud_sensor.stop()
    return aud_sensor.response("OK")

@app.route("/status")
def apicall_aud_sensor_status():
    return str(aud_sensor.status())

@app.route("/log")
def apicall_aud_sensor_log():
    return "\n".join(aud_sensor.log)+"\n"

# API endpoints for developer use
@app.route("/dev/diag")
def apicall_aud_dev_diag_status():
    return str(aud_sensor)

@app.route("/dev/aud-update")
def apicall_aud_dev_update():
    return str(aud_sensor.aud_update())

@app.route("/dev/connlist")
def apicall_aud_dev_connlist():
    return str(aud_sensor.connlist)

@app.route("/dev/force-stop-learning")
def apicall_aud_dev_stop_learning():
    return str(aud_sensor.stop_learning("via "+request.path))


def terminate(sig, frame):
    if aud_sensor.running:
        aud_sensor.terminate()
        aud_sensor.join()
    sys.exit(0)


signal.signal(signal.SIGINT, terminate)
signal.signal(signal.SIGTERM, terminate)


app.run(host="0.0.0.0", port=6060)
