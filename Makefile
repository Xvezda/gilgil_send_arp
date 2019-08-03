CPP=g++
TARGET=send_arp

all: $(TARGET)

$(TARGET): main.o send_arp.o
	$(CPP) -o $(TARGET) main.o send_arp.o

main.o: main.cpp send_arp.h
	$(CPP) -c -o main.o main.cpp

send_arp.o: send_arp.cpp send_arp.h
	$(CPP) -c -o send_arp.o send_arp.cpp

clean:
	rm -f *.o
	rm -f core
	rm -f $(TARGET)
