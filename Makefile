CC=gcc

CFLAGS=-I. --std=gnu99 -I./include -I/usr/include/postgresql

DEPS=scrape.h

SCRAPE_OBJ=src/scrape.o
BEN_OBJ=src/bencode.o

LDFLAGS=-L/usr/local/lib -L/usr/lib/x86_64-linux-gnu
LDLIBS=-lcurl -lpthread -ldl -lpq


scrape: $(SCRAPE_OBJ) $(BEN_OBJ)
	$(CC) -o $@ $(BEN_OBJ) $(SCRAPE_OBJ) $(CFLAGS) $(LDFLAGS) $(LDLIBS)
	rm -f src/scrape.o

all: scrape

clean:
	rm -f src/*.o scrape
