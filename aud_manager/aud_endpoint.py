import time, math
import ipaddress, ipwhois
from collections import deque, OrderedDict

from ipwhois.net import Net
from ipwhois.asn import IPASN

import aud

class LookupCache():
    def __init__(self, maxsize=512):
        self.cache = OrderedDict()
        self.maxsize = maxsize


    def put(self, ip, endpoint):
        if ip not in self.cache:
            self.cache[ip] = endpoint

        if len(self.cache) > self.maxsize:
            self.cache.popitem(0)


    def get(self, ip):
        try:
            return self.cache[ip]
        except:
            return False


class EndpointPool:
    def __init__(self, aud_handle):
        self.ah = aud_handle
        self.local_net = ipaddress.ip_network(self.ah.local_net)
        self.lookup_cache = LookupCache()

        self.ep_device = dict()
        self.ep_as = dict()


    def __str__(self):
        out = ""
        for d in [self.ep_as, self.ep_device]:
            for k, v in d.items():
                out += "Endpoint: "+str(k)+"\n"
                out += "    type: "+str(type(v))+"\n"
                out += str(v)+"\n"
        return out


    def lookup(self, ip):
        hw_addr = "TBD"
        res = self.lookup_cache.get(ip)
        if res:
            # Cache hit
            return res

        ip_addr = ipaddress.ip_address(ip)

        if ip_addr in self.local_net:
            for _, ep in self.ep_device.items():
                if ip_addr == ep.ip_addr:
                    return ep

            ep_addr = ip_addr
            ep = Device(ep_addr, self,
                        ip_addr.version,
                        ip_addr, hw_addr)

            self.lookup_cache.put(ip, ep)
            self.ep_device[str(ep_addr)] = ep
            return ep


        else:
            for _, ep in self.ep_as.items():
                if ip_addr in ipaddress.ip_network(ep.asn_cidr):
                    return ep
            try:
                obj = IPASN(Net(ip))
                res = obj.lookup()

                ep_addr = res["asn_cidr"]
                ep = AS(ep_addr, self,
                        ip_addr.version,
                        res["asn_cidr"], res["asn"])
                self.lookup_cache.put(ip, ep)
                self.ep_as[str(ep_addr)] = ep
                return ep

            except ipwhois.exceptions.IPDefinedError:
                # TODO: other ip classes (broadcast, reserved address, etc.)
                pass

        return False


    def find_ep_by_ip(self, dev_ipaddr):
        dev_uuid = self.find_device_by_ip(dev_ipaddr)
        return self.find_ep_by_uuid(dev_uuid)


    def find_ep_by_uuid(self, dev_uuid):
        if dev_uuid in self.ep_device:
            return self.ep_device[dev_uuid]
        elif dev_uuid in self.ep_as:
            return self.ep_as[dev_uuid]
        else:
            return None


    def find_device_by_ip(self, ip):
        ip_addr = ipaddress.ip_address(ip)
        if ip_addr not in self.local_net:
            return False

        for key, device in self.ep_device.items():
            if device.ip_addr == ip_addr:
                return key

        return False



class Endpoint(object):
    def __init__(self, handle, ip_ver, ep_pool):
        self.handle = str(handle)
        self.ip_ver = ip_ver
        self.ep_pool = ep_pool


    def get_handle(self):
        return self.handle


    def pool(self):
        return self.ep_pool



class AS(Endpoint):
    def __init__(self, handle, ep_pool, ip_ver, asn_cidr, asn):
        super().__init__(handle, ip_ver, ep_pool)
        self.asn_cidr = asn_cidr
        self.asn = asn


    def __str__(self):
        output = "    ipv"+str(self.ip_ver)+"_cidr: "+str(self.asn_cidr)+"\n"
        output += "    asn:  "+str(self.asn)+"\n"
        return output


    def get_addr(self):
        return (self.asn_cidr, self.ip_ver)


    def add_conn(self, conn):
        if self.asn_cidr == conn.key.dst_addr:
            conn.dst_proc = True
        elif self.asn_cidr == conn.key.src_addr:
            conn.src_proc = True


class Device(Endpoint):
    def __init__(self, handle, ep_pool, ip_ver, ip_addr, hw_addr):
        super().__init__(handle, ip_ver, ep_pool)
        self.ip_addr = ip_addr
        self.hw_addr = {hw_addr}
        self.created = int(time.time())
        self.conns = dict()
        self.aud = aud.AUD(self, ip_addr)


    def __str__(self):
        out = "    ipv"+str(self.ip_ver)+"_addr: "+str(self.ip_addr)+"\n"
        out += "    hw_addr: "+str(self.hw_addr)+"\n"
        out += "    created: "+str(self.created)+"\n"
        out += "    conns:\n"
        for key, conns in self.conns.items():
            out += "        "+str(key)+", conn samples = "+str(len(conns))+"\n"
            out += "        "+str(conns)+"\n"
        out += str(self.aud)
        return out


    def get_addr(self):
        return (str(self.ip_addr), self.ip_ver)


    def add_conn(self, conn):

        if str(self.ip_addr) == conn.key.src_addr:
            key = aud.ACLKey(conn.ip_ver, "from", conn.key.proto, conn.key.dst_addr, conn.key.dst_port)
        else:
            key = aud.ACLKey(conn.ip_ver, "to", conn.key.proto, conn.key.src_addr, conn.key.dst_port)

        if key not in self.conns:
            self.conns[key] = list()

        self.conns[key].append(conn)


    def update_aud_records(self):
        for key, conns in self.conns.items():
            self.aud.update_records(key, conns)
