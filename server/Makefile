# Makefile to compile and link the source files of the project and generate the required executable file 
# Author : Vignesh Vadivel
# email  : viva9969@colorado.edu
# Course : Advanced Embedded Software Development

 # Use CROSS_COMPILE=aarch64-none-linux-gnu- to use ARM toolchain (default is gcc)
CC ?= $(CROSS_COMPILE)gcc
 # Flags to treat all the errors as warnings
FLAGS=-Wall -Werror

# writer recipe
.PHONY : all
all: aesdsocket

# Linking all the compiled object files
aesdsocket: aesdsocket_o
	$(CC) $(FLAGS)  aesdsocket.o -o aesdsocket

# Compiling the source files to generate object files
aesdsocket_o:
	$(CC) $(FLAGS) -c aesdsocket.c -o aesdsocket.o

# Clean the working directory
.PHONY: clean
clean:
	rm -f *.o aesdsocket

