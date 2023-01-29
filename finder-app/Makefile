.PHONY : all

all: writer

writer: writer_o
	gcc writer.o -o writer

writer_o:
	gcc -c writer.c -o writer.o

CROSS_COMPILE: writer_aarch64_o

writer_aarch64_o: writer_aarch64
	aarch64-none-linux-gnu-gcc -o writer writer.o

writer_aarch64:
	aarch64-none-linux-gnu-gcc -c writer.c -o writer.o

.PHONY : clean
clean : 
	rm -f *.o writer

