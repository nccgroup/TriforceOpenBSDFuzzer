CFLAGS= -g -Wall

all : testAfl

testAfl : testAfl.o
	$(CC) $(CFLAGS) -o $@ testAfl.o

clean:
	rm -f testAfl.o

