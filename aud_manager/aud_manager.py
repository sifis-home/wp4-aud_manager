#!/usr/bin/python3
import sys, os, threading, signal
import time, uuid, math, queue
import json
import logging

from collections import deque
from datetime import datetime, timedelta, timezone
from flask import Flask, request

# Local imports
import aud
import aud_conn
import packetreader as pr

log_path = "/tmp/aud_manager.log"

class AUDManager(threading.Thread):
    """Main thread for running AUD Manager."""

    def __init__(self):
        threading.Thread.__init__(self)
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(asctime)s %(levelname)-8s [%(filename)s]: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
            handlers=[
                logging.FileHandler(log_path),
                logging.StreamHandler()
            ]
        )

        self.running = True
        self.start_t = datetime.now(timezone.utc).replace(microsecond=0)
        self.sigterm = threading.Event()
        self.local_ips = set()

        self.aud = aud.AUD()
        self.aud_update_interval = 10 # seconds
        self.connlist = aud_conn.ConnList(self)

        self.raw_buf = deque()

        self.reader = pr.PacketReader(self.raw_buf)
        self.local_ips.add(self.reader.get_local_ip_addr())

        self.start()

    def as_dict(self):
        return {
            "started": str(self.start_t),
            "local_ips": [str(ip) for ip in self.local_ips],
            "connlist": self.connlist.as_dict(),
            "aud": self.aud.as_dict(),
        }

    def status(self):
        topic_name = "SIFIS:AUD_Manager_Status"
        topic_uuid = uuid.uuid3(uuid.NAMESPACE_OID, topic_name)
        res = {
            "RequestPostTopicUUID": {
                "topic_name": topic_name,
                "topic_uuid": str(topic_uuid),
                "AnalyticStarted": str(self.start_t), #.strftime("%d-%m-%Y %H:%M:%S")),
                "value": {
                    "description": "aud_manager",
                },
                "local_ips": [str(ip) for ip in self.local_ips],
                "anomalies": self.aud.anomaly_wrapper(),

            }
        }
        return json.dumps(res)

    def run(self):
        self.running = True
        self.reader.start()

        logging.info("AUD manager started")

        # Clear buffer to avoid surge of packets at startup
        self.raw_buf.clear()

        aud_update_t = time.time() + self.aud_update_interval

        while self.running:
            for i in range(len(self.raw_buf)):
                self.connlist.record(self.raw_buf.popleft())

            if aud_update_t < time.time():
                self.aud_update()
                self.connlist.trim()
                aud_update_t = time.time() + self.aud_update_interval

            time.sleep(0.1)

        self.reader.stop()
        self.reader.join()

    def stop(self):
        self.running = False
        logging.info("AUD manager stopped")

    def terminate(self):
        self.sigterm.set()
        self.stop()

    def stop_learning(self, msg):
        self.learning = False
        logging.debug("AUD learning ended, %s", str(msg))
        return "OK\n"

    def aud_update(self):
        start_t = time.time()
        self.aud.update(self.connlist)
        logging.debug("aud_update() finished in %f seconds.", round((time.time() - start_t), 3))

    def response(self, res):
        return json.dumps({"response": str(res)})


aud_manager = AUDManager()
app = Flask(__name__)

flasklog = logging.getLogger("werkzeug")
flasklog.disabled = True


@app.route("/status")
def apicall_aud_manager_status():
    return str(aud_manager.status())

@app.route("/log")
def apicall_aud_manager_log():
    with open(log_path, "r") as f:
        content = f.read()
    return content

@app.route("/mark-benign/<uuid>")
def apicall_aud_manager_mark_benign(uuid):
    res = aud_manager.aud.mark_benign(uuid)
    return aud_manager.response(res)

# API endpoints for developer use
@app.route("/dev/diag")
def apicall_aud_dev_diag():
    return json.dumps(aud_manager.as_dict())

@app.route("/dev/aud-update")
def apicall_aud_dev_update():
    logging.debug("Manually triggered aud_update()")
    aud_manager.aud_update()
    return aud_manager.response("OK")

@app.route("/dev/connlist")
def apicall_aud_dev_connlist():
    return json.dumps(aud_manager.connlist.as_dict())

@app.route("/dev/force-stop-learning")
def apicall_aud_dev_stop_learning():
    return str(aud_manager.stop_learning("via "+request.path))


def terminate(sig, frame):
    if aud_manager.running:
        aud_manager.terminate()
        aud_manager.join()
    logging.info("Bye.")
    sys.exit(0)


signal.signal(signal.SIGINT, terminate)
signal.signal(signal.SIGTERM, terminate)


app.run(host="0.0.0.0", port=5050)
