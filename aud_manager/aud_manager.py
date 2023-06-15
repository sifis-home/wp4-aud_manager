#!/usr/bin/python3
import sys, os, threading, signal
import time, math, queue
import json
import logging

from collections import deque
from datetime import datetime, timedelta
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
        self.start_t = datetime.now()
        self.sigterm = threading.Event()
        self.local_ips = set()

        self.aud = aud.AUD()
        self.aud_update_interval = 10 # seconds
        self.connlist = aud_conn.ConnList(self)

        self.raw_buf = deque()

        self.reader = pr.PacketReader(self.raw_buf)
        self.local_ips.add(self.reader.get_local_ip_addr())

        self.start()

    def __str__(self):
        pad = "  "
        out = "*** AUD manager ***\n"
        out += pad+"running: "+str(self.running)+"\n"
        out += pad+"learning: "+str(self.learning)+"\n"
        if self.running:
            out += pad+"running since: "+str(self.start_t.strftime("%d-%m-%Y %H:%M:%S"))+"\n"
            uptime = datetime.now().replace(microsecond=0) - self.start_t.replace(microsecond=0)
            out += pad+"uptime: "+str(uptime)+"\n"

        out += pad+"my IPs: "+str(self.local_ips)+"\n"
        #out += pad+"connlist length: "+str(len(self.connlist.conns))+"\n"
        #out += str(self.aud)

        return out

    def as_dict(self):
        return {
            "connlist": self.connlist.as_dict(),
            "aud": self.aud.as_dict(),
        }

    def status(self):
        res = {
            "RequestPostTopicUUID": {
                "topic_name": "SIFIS:AUD_Manager_Results",
                "topic_uuid": "FIXTHIS",
                "AnalyticStarted": str(self.start_t.strftime("%d-%m-%Y %H:%M:%S")),
                "value": {
                    "description": "aud_manager",
                },
                "local_ip": [str(ip) for ip in self.local_ips],
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
                #logging.debug("connlist len before update: %d", len(self.connlist))
                self.aud_update()
                self.connlist.trim()
                aud_update_t = time.time() + self.aud_update_interval
                #logging.debug("connlist len after update: %d", len(self.connlist))

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
        logging.debug("aud_update() started")
        start_t = time.time()
        self.aud.update(self.connlist)
        end_t = time.time()
        logging.debug("aud_update() finished in %f seconds.", round((end_t - start_t), 3))

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

# API endpoints for developer use
@app.route("/dev/diag")
def apicall_aud_dev_diag_status():
    return json.dumps(aud_manager.as_dict())

@app.route("/dev/aud-update")
def apicall_aud_dev_update():
    return str(aud_manager.aud_update())

@app.route("/dev/connlist")
def apicall_aud_dev_connlist():
    return str(aud_manager.connlist)

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


app.run(host="0.0.0.0", port=6060)
