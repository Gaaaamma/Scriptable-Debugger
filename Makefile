CC=gcc
CFLAGS= -g -Wall
NOPIE= -no-pie
TARGET=hw4
LIBNAME=capstone
SOURCE=310552022_hw4.o

.PHONY: all clean

all: $(TARGET) 

$(TARGET): $(SOURCE)
	$(CC) $< $(CFLAGS) -l$(LIBNAME)  -o $@ 

test: test.o
	$(CC) $< $(CFLAGS) -l$(LIBNAME) -o $@

%.o: %.c
	$(CC) -c $< -o $@

clean:
	rm -f $(TARGET)
	rm -f test 
	rm -f core
	rm *.o