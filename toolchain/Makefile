# CC = ccomp -finline-asm
CC = gcc -nostdlib -static -g -fno-stack-protector -fno-omit-frame-pointer -mno-red-zone
SOURCES := main.c $(filter-out main.c,$(wildcard *.c))


.PHONY: all clean
all: ld.my.so
	cd tests && make all

ld.my.so: ${SOURCES}
	${CC} -c $?
	ld -shared -pie --no-dynamic-linker --entry _start -o ld.my.so $(?:.c=.o)

clean:
	rm -rf ld.my.so *.o
	cd tests && make clean
