GCC=gcc
CFLAGS=-Wall
LDFLAGS=-lnfnetlink -lnetfilter_log
.PHONY: all

all: nflog

.PHONY: clean
clean:
	$(RM) *~ *.o nflog

nflog:
	$(GCC) $(CFLAGS) nflog.c -o nflog $(LDFLAGS)
