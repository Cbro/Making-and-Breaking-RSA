# Compiler
CC = gcc

# Compiler flags
# CFLAGS = -g -Wall -Wmissing-prototypes -Werror -std=gnu99 -pedantic

# Compiler optimisation level
CCOPT = -O3 -Fast
# Linker flags
LDFLAGS = -lgmp -lm -lglib-2.0
# Include flags
IFLAGS = -I/usr/include/glib-2.0 -I/usr/lib/glib-2.0/include

# *********************************************************
#  Folders & files variable
# *********************************************************

# executable name
EXEC = rsa
# $(BIN)ary folder
BIN = .
# $(SRC) folder
SRC = .
# objects need by everyone
OBJECTS = $(BIN)/prime.o rsa.o
# objects for executable
EXEC_OBJECTS = $(BIN)/main.o $(OBJECTS)

# *********************************************************
#  Now, the command
# *********************************************************

all : $(BIN)/$(EXEC)
	@echo "Compilation done."

$(BIN)/$(EXEC) : $(EXEC_OBJECTS)
	$(CC) $^ -o $@ $(LDFLAGS)

$(BIN)/%.o : $(SRC)/%.c
	$(CC) $(CCOPT) $(IFLAGS) -c $< -o $@ 

# $(CFLAGS)

indent :
	indent -orig -nut main.c
	indent -orig -nut rsa.c
	indent -orig -nut rsa.h
	indent -orig -nut prime.c
	indent -orig -nut prime.h

clean :
	rm -rf $(BIN)/$(EXEC) $(BIN)/*.o
