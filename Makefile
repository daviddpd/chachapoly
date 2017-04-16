CC = cc
#CC = gcc48
CFLAGS  = -g  -O0 -Wall 
INCLUDES=-I.
LDFLAGS=

LOCAL_LIB_SRC+=chacha.c poly1305.c chachapoly.c 

LOCAL_LIB_OBJ=$(LOCAL_LIB_SRC:.c=.o)

BIN_SRC=chachapoly-test.c
BIN_OBJ=$(BIN_SRC:.c=.o)

BIN_EXEC=$(BIN_SRC:.c=)

all:  $(BIN_OBJ) $(LOCAL_LIB_OBJ) $(BIN_EXEC)

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS) $(INCLUDES) $(DEFS)

%: %.o $(LOCAL_LIB_OBJ) 
	$(CC) $(LDFLAGS) $(LIBS) $(DEFS) -o $@ $^

clean:
	rm -f $(BIN_EXEC) $(BIN_OBJ) $(LOCAL_LIB_OBJ)

