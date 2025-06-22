# Makefile do kompilacji serwera i klienta komunikatora

CC = gcc
CFLAGS = -Wall -Wextra -g -pthread
LDFLAGS = -pthread

# Pliki źródłowe
SERVER_SRCS = server.c utils.c user_management.c history_management.c tlv.c
CLIENT_SRCS = client.c utils.c tlv.c

# Pliki obiektowe
SERVER_OBJS = $(SERVER_SRCS:.c=.o)
CLIENT_OBJS = $(CLIENT_SRCS:.c=.o)

# Pliki wykonywalne
SERVER_EXEC = server
CLIENT_EXEC = client

# Domyślny cel
all: $(SERVER_EXEC) $(CLIENT_EXEC)

# Reguły budowania
$(SERVER_EXEC): $(SERVER_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(CLIENT_EXEC): $(CLIENT_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Reguła wzorcowa dla plików .o
%.o: %.c *.h
	$(CC) $(CFLAGS) -c $< -o $@

# Reguła czyszczenia
clean:
	rm -f $(SERVER_OBJS) $(CLIENT_OBJS) $(SERVER_EXEC) $(CLIENT_EXEC) *~ core

.PHONY: all clean