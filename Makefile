CC = gcc
# Zmieniono CFLAGS na bardziej sensowne. -pthread dla wątków.
CFLAGS = -Wall -g -D_DEFAULT_SOURCE -D_POSIX_C_SOURCE=200809L -lpthread
LDFLAGS = -pthread # Dodano linkowanie biblioteki wątków

SERVER_OBJS = server.o tlv.o user_management.o history_management.o utils.o
CLIENT_OBJS = client.o tlv.o utils.o

all: server client

server: $(SERVER_OBJS)
	$(CC) $(CFLAGS) -o server $(SERVER_OBJS) $(LDFLAGS)

client: $(CLIENT_OBJS)
	$(CC) $(CFLAGS) -o client $(CLIENT_OBJS) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o server client users.dat
	rm -rf chat_history/