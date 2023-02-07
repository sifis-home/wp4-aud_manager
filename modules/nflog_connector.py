import sys, time
import threading
import os, socket

class NflogConnector(threading.Thread):
    def __init__(self, buf):
        threading.Thread.__init__(self)
        self.buf = buf
        self.running = True
        self.sock = None
        self.srv_addr = b"/tmp/aud/nflog_emit.sock"
        self.cli_addr = b"/tmp/aud/nflog_sink.sock"


    def run(self):
        for line in self.socket_comm():
            # Parse and tokenize lines here.
            self.buf.append(dict(x.split('=') for x in line.split()))


    def socket_comm(self):

        try:
            os.unlink(self.cli_addr)
        except:
            pass

        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.sock.bind(self.cli_addr)

        try:
            hello = "hello"

            self.sock.sendto(hello.encode("utf-8"), self.srv_addr)

            while self.running:
                response, address = self.sock.recvfrom(512)
                yield response.decode("utf-8")

        except socket.error as e:
            print(e)

        except BrokenPipeError as e:
            print(e)

        self.sock.close()
        print("socket_comm(): bye!")


    def stop(self):
        self.running = False
        #raise BrokenPipeError
