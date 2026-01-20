# fill in the path to your musl-gcc
CC = musl-gcc

.PHONY: all clean

all: test.out libtester.so
clean:
	rm -f libtester.so test.out

libtester.so: libtester.c libtester.h
	${CC} -g -shared -fPIC -fno-stack-protector -o libtester.so libtester.c

# fill in the path to your musl ld.so
MUSL_LD_SO = /usr/lib/ld-musl-x86_64.so.1

MY_LD_SO = $(shell cd ..; pwd)/ld.my.so

test.out: test.c libtester.so
	${CC} -g -no-pie -fno-stack-protector \
		-Wl,--enable-new-dtags \
	    -Wl,-rpath,$(shell pwd) \
	    -Wl,-dynamic-linker,$(MY_LD_SO) \
	    -L. -ltester -o test.out test.c
