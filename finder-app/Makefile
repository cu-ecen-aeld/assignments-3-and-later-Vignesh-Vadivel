# Makefile to compile and link the source files of the project and generate the required executable file 
# Author : Vignesh Vadivel
# email  : viva9969@colorado.edu
# Course : Advanced Embedded Software Development

 # Use CROSS_COMPILE=aarch64-none-linux-gnu- to use ARM toolchain (default is gcc)
COMPILER ?= $(CROSS_COMPILE)gcc
 # Flags to treat all the errors as warnings
FLAGS=-Wall -Werror

# writer recipe
.PHONY : all
all: writer

# Linking all the compiled object files
writer: writer_o
	$(COMPILER) $(FLAGS)  writer.o -o writer

# Compiling the source files to generate object files
writer_o:
	$(COMPILER) $(FLAGS) -c writer.c -o writer.o

# Clean the working directory
.PHONY: clean
clean:
	rm -f *.o writer

