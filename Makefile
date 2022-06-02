CC=gcc
CFLAGS= -g -Wall
NOPIE= -no-pie
TARGET=hw4
SOURCE=310552022_hw4.c

.PHONY: all clean

all: $(TARGET) test

$(TARGET): $(SOURCE)
	$(CC) -o $@ $(CFLAGS) $< 

test: test.c
	$(CC) -o $@ $(CFLAGS) $(NOPIE) $<

clean:
	rm -f $(TARGET)
	rm -f test 
	rm -f core