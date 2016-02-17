CC=gcc

CFLAGS=-I. --std=gnu99 -I./include -I/usr/include/postgresql

DEPS=scrape.h


SCRAPE_OBJ=src/scrape.o
BEN_OBJ=src/bencode.o

FIVE0_OBJ=src/five0.o

LDFLAGS=-L/usr/local/lib -L/usr/lib/x86_64-linux-gnu
LDLIBS=-lpthread -ldl -lpq


scrape: $(SCRAPE_OBJ) $(BEN_OBJ)
	$(CC) -o $@ $(BEN_OBJ) $(SCRAPE_OBJ) $(CFLAGS) $(LDFLAGS) $(LDLIBS)
	rm -f src/scrape.o
	rm -f src/bencode.o

five0: $(FIVE0_OBJ)
	$(CC) -o $@ $(FIVE0_OBJ) $(CFLAGS) -lpthread -ldl
	rm -f src/five0.o

all: scrape five0

clean:
	rm -f src/*.o scrape five0
