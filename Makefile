CPP=g++
TARGET=send_arp

all: $(TARGET)

$(TARGET): send_arp.o

send_arp.o: send_arp.cpp send_arp.h
	g++ -c -o send_arp.o send_arg.cpp

clean:
	rm -f *.o
	rm -f core
	rm -f $(TARGET)
