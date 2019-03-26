.PHONY: clean
CC = gcc
CFLAG = -g
DEBUGFLAG= -DDEBUG
SRC = main.c
TARGET = netstat-like

ELF: out
	$(CC) -o $(TARGET) *.o

out: $(SRC)
	@$(CC) -c $^ -o main.o

clean:
	rm netstat-like
