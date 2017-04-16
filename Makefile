CC = cc
#CC = gcc48
CFLAGS  = -g  -O0 -Wall 
INCLUDES=-I./include
LDFLAGS=

LOCAL_LIB_SRC+=src/chacha.c src/poly1305.c src/chachapoly.c 

LOCAL_LIB_OBJ=$(LOCAL_LIB_SRC:.c=.o)

BIN_SRC=bin/chachapoly-test.c
BIN_OBJ=$(BIN_SRC:.c=.o)

BIN_EXEC=$(BIN_SRC:.c=)

all:  $(BIN_OBJ) $(LOCAL_LIB_OBJ) $(BIN_EXEC)

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS) $(INCLUDES) $(DEFS)

%: %.o $(LOCAL_LIB_OBJ) 
	$(CC) $(LDFLAGS) $(LIBS) $(DEFS) -o $@ $^

clean:
	rm -f $(BIN_EXEC) $(BIN_OBJ) $(LOCAL_LIB_OBJ)

