LDLIBS=-lpcap

all: arp-spoof


arp-spoof: main.o arphdr.o ethhdr.o ip.o mac.o get_address.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f arp-spoof *.o
	rm -f send-arp-test *.o