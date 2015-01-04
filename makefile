CC=gcc
LDLIBS=-lpcap
TARGET=pppoe-terminator

all: $(TARGET)

$(TARGET):
	$(CC) -o $@ pppoe-terminator.c $(LDLIBS)

clean:
	rm -rf *o $(TARGET)
