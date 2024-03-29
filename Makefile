CC=g++
CPP=g++
LDLIBS=-lpcap
CPPFLAGS=-Wall -std=c++11

TARGET=send_arp
SOURCES=$(wildcard *.cpp)
OBJECTS=$(SOURCES:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJECTS)

clean:
	rm -f *.o
	rm -f core
	rm -f $(TARGET)
