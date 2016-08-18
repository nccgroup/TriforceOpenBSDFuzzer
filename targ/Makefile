CFLAGS= -g -Wall

# driver builds on openbsd
all : driver 

OBJS= aflCall.o driver.o parse.o sysc.o argfd.o
driver: $(OBJS)
	$(CC) $(CFLAGS) -static -o $@ $(OBJS)

# testAfl builds on linux (fuzzer box)
testAfl : testAfl.o
	$(CC) $(CFLAGS) -o $@ testAfl.o

argfd.c : argfd.c.tmpl numTempl.py
	./numTempl.py < argfd.c.tmpl > argfd.c

# gen happens on fuzzer box
inputs : gen.py
	test -d inputs || mkdir inputs
	./gen.py

clean:
	rm -f $(OBJS) testAfl.o

