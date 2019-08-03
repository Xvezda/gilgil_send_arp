CC=g++
CPP=g++
TARGET=send_arp
LDLIBS=-lpcap
CPPFLAGS=-Wall -std=c++11

all: $(TARGET)

$(TARGET): main.o send_arp.o

main.o: main.cpp send_arp.h

send_arp.o: send_arp.cpp send_arp.h

clean:
	rm -f *.o
	rm -f core
	rm -f $(TARGET)
