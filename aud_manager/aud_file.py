import os
import socket
import json

from collections import OrderedDict
from datetime import datetime, date


class AUDFile:
    def __init__(self, device_name):
        self.mud = OrderedDict()
        self.device_name = device_name

        self.aces = {}
        self.aces[("ipv4", "from")] = []
        self.aces[("ipv4", "to")] = []
        self.aces[("ipv6", "from")] = []
        self.aces[("ipv6", "to")] = []

        self.proto_lookup = {i:name[8:] for name,i in vars(socket).items() if name.startswith("IPPROTO")}


    def assemble_mud(self):
        root = "ietf-mud:mud"
        ietf_acls = "ietf-access-control-list:acls"
        # Schema for MUD can be found in RFC 8520, section 2.1
        self.mud = {root: {}}
        self.mud[root]["mud-version"] = "0.01-alpha" # Schema expects version number to be uint8
        self.mud[root]["mud-url"] = "N/A"
        self.mud[root]["last-update"] = datetime.now().astimezone().replace(microsecond=0).isoformat()
        self.mud[root]["is-supported"] = True
        self.mud[root]["mode-name"] = self.device_name

        acls = []
        access_list_from = []
        access_list_to = []

        for ipv, direction in self.aces:

            if len(self.aces[(ipv, direction)]) == 0:
                continue

            name = "-".join(["mud", self.device_name, ipv, direction])
            ace = []
            for a in self.aces[(ipv, direction)]:
                ace.append(a)

            if direction == "from":
                access_list_from.append({"name": name})
            else:
                access_list_to.append({"name": name})

            acls.append({"name": name,
                         "type": ipv+"-acl-type",
                         "aces": {"ace": ace}})

        self.mud[root]["to-device-policy"] = {"access-lists":
                                              {"access_list": access_list_to}}
        self.mud[root]["from-device-policy"] = {"access-lists":
                                                {"access_list": access_list_from}}
        self.mud[ietf_acls] = {"acl": acls}

        return json.dumps(self.mud)



    def add_aces(self, aces):
        for acl_key, acl in aces.items():
            ipver, direction = acl_key

            for ace in acl:
                proto, addr, port = ace

                if direction == "from":
                    self.add_ace_from_device(ipver, direction, proto, addr, port)
                elif direction == "to":
                    self.add_ace_to_device(ipver, direction, proto, addr, port)



    def add_ace_from_device(self, ipver, direction, proto, addr, port):
        ipproto = self.proto_lookup[proto].lower()
        idx = len(self.aces[(ipver, direction)])
        name = "-".join(["cl", str(idx), direction, "dev"])
        matches = {ipver: {
            "protocol": str(proto),
            "destination-"+ipver+"-network": addr},
                   ipproto: {
                       "destination-port": {
                           # TODO: direction-initiated for TCP
                           "operator": "eq",
                           "port": str(port)
                       }
                   }
        }

        actions = {"forwarding": "accept"}

        ace = {
            "name": name,
            "matches": matches,
            "actions": actions
        }

        self.aces[(ipver, direction)].append(ace)



    def add_ace_to_device(self, ipver, direction, proto, addr, port):
        ipproto = self.proto_lookup[proto].lower()
        idx = len(self.aces[(ipver, direction)])
        name = "-".join(["cl", str(idx), direction, "dev"])
        matches = {ipver: {
            "protocol": str(proto),
            "source-"+ipver+"-network": addr},
                   ipproto: {
                       "source-port": {
                           # TODO: direction-initiated for TCP
                           "operator": "eq",
                           "port": str(port)
                       }
                   }
        }

        actions = {"forwarding": "accept"}

        ace = {
            "name": name,
            "matches": matches,
            "actions": actions
        }

        self.aces[(ipver, direction)].append(ace)


    def json(self):
        return json.dumps(self.mud)
