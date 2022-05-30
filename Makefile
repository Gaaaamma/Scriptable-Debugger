CC=gcc
CFLAGS= -g -Wall
TARGET=hw4
SOURCE=310552022_hw4.c

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) -o $@ $(CFLAGS) $< 

clean:
	rm -f $(TARGET)
