#!/usr/bin/python3
import sys, threading, signal
import time, math, queue

from collections import deque
from datetime import datetime, timedelta
from flask import Flask

# Local imports
import aud_endpoint
import aud_conn
import aud

sys.path.append("data_intake_modules/")
import nflog_connector as nfc


class AUDManager(threading.Thread):
    """Main thread for running AUD Manager."""

    def __init__(self):
        threading.Thread.__init__(self)
        self.running = False
        self.start_e = threading.Event()
        self.start_t = None

        self.aud_update_interval = 30 # seconds

        self.local_net = "172.18.10.0/24" # TODO: read this from args or config file

        self.ep_pool = aud_endpoint.EndpointPool(self)
        self.connlist = aud_conn.ConnList()

        self.raw_buf = deque()
        self.reader = nfc.NflogConnector(self.raw_buf)


    def __str__(self):
        out = "*** AUD manager ***\n"
        out += "    running: "+str(self.running)+"\n"
        if self.start_t:
            out += "    running since: "+str(self.start_t)+"\n"
            uptime = datetime.now().replace(microsecond=0) - self.start_t.replace(microsecond=0)
            out += "    uptime: "+str(uptime)+"\n"
        out += "    local net: "+str(self.local_net)+"\n"
        out += "    ep devices:\n"
        for ep, _  in self.ep_pool.ep_device.items():
            out += "        "+str(ep)+"\n"
        out += "    ep as'es:\n"
        for ep, _  in self.ep_pool.ep_as.items():
            out += "        "+str(ep)+"\n"
        out += "    connlist length: "+str(len(self.connlist.conns))+"\n"

        return out

    def ingress(self, row):

        src = self.ep_pool.lookup(row["src_addr"])
        dst = self.ep_pool.lookup(row["dst_addr"])

        if not (src and dst):
            return

        try:
            sport, dport = int(row["src_port"]), int(row["dst_port"])
        except KeyError:
            # Protocols without ports, e.g., ICMP
            sport, dport = -1, -1

        try:
            flags = row["flags"].rstrip(",").split(",")
        except KeyError:
            flags = []

        self.connlist.add(src, dst, int(row["proto"]),
                          sport, dport, flags,
                          int(row["len"]), int(row["t"]))


    def run(self):
        self.reader.start()

        while True:
            self.start_e.wait()
            self.start_e.clear()
            self.start_t = datetime.now()
            self.running = True

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

            self.start_t = None

        self.reader.stop()
        self.reader.join()

    def stop(self):
        self.running = False

    def aud_update(self):
        for _, ep in self.ep_pool.ep_device.items():
            ep.update_aud_records()


    def generate_aud_file(self, dev_addr):
        ep = self.ep_pool.find_ep_by_ip(dev_addr)
        return ep.aud.export_aud_file()



aud_manager = AUDManager()
app = Flask(__name__)



@app.route("/start")
def apicall_aud_manager_start():
    aud_manager.start_e.set()
    return "OK\n"

@app.route("/stop")
def apicall_aud_manager_stop():
    aud_manager.stop()
    return "OK\n"

@app.route("/status")
def apicall_aud_manager_status():
    return str(aud_manager)

@app.route("/connlist")
def apicall_dump_connlist():
    return str(aud_manager.connlist)

@app.route("/endpoints")
def apicall_dump_endpoints():
    return str(aud_manager.ep_pool)

@app.route("/aud-file/<ip>")
def apicall_generate_aud_file(ip):
    return aud_manager.generate_aud_file(ip)



def terminate(sig, frame):
    print("terminate")
    global aud_manager
    aud_manager.running = False
    aud_manager.join()
    sys.exit(0)


signal.signal(signal.SIGINT, terminate)
signal.signal(signal.SIGTERM, terminate)



if __name__ == "__main__":

    aud_manager.start()
    app.run(host="0.0.0.0")
