#!/bin/sh

CONNBYTES=""
NFLOG_OPTS="--nflog-group 1 --nflog-threshold 1"

iptables -t mangle -A PREROUTING $CONNBYTES -j NFLOG $NFLOG_OPTS
iptables -t mangle -A POSTROUTING $CONNBYTES -j NFLOG $NFLOG_OPTS
