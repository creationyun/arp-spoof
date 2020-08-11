LDLIBS=-lpcap

all: arp-spoof

arp-spoof: net-address.o protocol-hdr.o main.o
	$(LINK.cc) $^ $(LDLIBS) -o $@

clean:
	rm -f arp-spoof *.o
