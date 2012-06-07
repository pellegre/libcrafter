DIR_INCLUDE = ./
DIR_SRC = ./
DIR_FIELDS = ../Fields
DIR_BIN = ./
DIR_LIB = ./

TARBALL=fields

AR = ar
AR_FLAGS = rs

CC = g++
CC_FLAGS = -g -O0 -Wall -I $(DIR_INCLUDE) -L $(DIR_LIB) 

OBJ_PROTO = $(DIR_SRC)/Proto.o $(DIR_SRC)/FieldType.o 
OBJ_PROTO_HDR = $(DIR_SRC)/Proto.h $(DIR_SRC)/FieldType.h 
OBJ_PROTO_SRC = $(DIR_SRC)/Proto.cpp $(DIR_SRC)/FieldType.cpp

PROGRAM = $(DIR_BIN)/protogen
OBJ_PROG = Main.o
OBJ_PROG_SRC = $(DIR_SRC)/Main.cpp

MAKEFILE=Makefile
LIB_LINK = -lgomp

$(PROGRAM):$(OBJ_PROG) $(OBJ_LIB) $(OBJ_PROTO)
	$(CC) $(CC_FLAGS) $(OBJ_PROG) $(OBJ_LIB) $(OBJ_PROTO) $(LIB_LINK) -o $(PROGRAM)

$(OBJ_PROTO):$(OBJ_PROTO_SRC) $(OBJ_PROTO_HDR) $(MAKEFILE)  
	$(CC) -c $(OBJ_PROTO_SRC) $(CC_FLAGS)
	
$(OBJ_LIB):$(OBJ_LIB_SRC) $(OBJ_LIB_HDR) $(MAKEFILE)  
	$(CC) -c $(OBJ_LIB_SRC) $(CC_FLAGS)

clean:
	rm -rf $(OBJ_LIB) $(OBJ_PROG) $(PROGRAM) $(TARBALL).tar.gz

tarball:
	mkdir $(TARBALL)
	cp $(MAKEFILE) $(OBJ_LIB_HDR) $(OBJ_LIB_SRC) $(OBJ_PROG_SRC) $(TARBALL)/
	tar cfvz $(TARBALL).tar.gz $(TARBALL) 
	rm -rf $(TARBALL)
