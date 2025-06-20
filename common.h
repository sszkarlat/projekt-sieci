#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <signal.h>
#include <sys/wait.h>
#include <netdb.h>    // Dla getaddrinfo
#include <fcntl.h>    // Dla flock
#include <sys/file.h> // Dla flock
#include <errno.h>
#include <pthread.h> // Dla wielowątkowości po stronie klienta

// Porty
#define SERVER_TCP_PORT 12345
#define DISCOVERY_UDP_PORT 12346
#define CHAT_UDP_PORT 12347                   // Nowy port dla czatu multicast
#define MULTICAST_GROUP_DISCOVERY "239.0.0.1" // IPv4 Multicast dla discovery
#define MULTICAST_GROUP_CHAT "239.0.0.2"      // IPv4 Multicast dla czatu

// Rozmiary buforów
#define MAX_MSG_LEN 1024
#define MAX_USERNAME_LEN 32
#define MAX_PASSWORD_LEN 32
#define TLV_BUFFER_SIZE (sizeof(TLVHeader) + MAX_MSG_LEN + MAX_USERNAME_LEN * 2) // Większy bufor dla wiadomości

// Typy komunikatów TLV
typedef enum
{
    MSG_TYPE_DISCOVERY_PING = 1,
    MSG_TYPE_DISCOVERY_PONG,
    MSG_TYPE_REGISTER_REQ,
    MSG_TYPE_REGISTER_RESP,
    MSG_TYPE_LOGIN_REQ,
    MSG_TYPE_LOGIN_RESP,
    MSG_TYPE_SEND_MSG_REQ,  // Wiadomość wysyłana do serwera (z TCP)
    MSG_TYPE_REALTIME_CHAT, // Wiadomość rozgłaszana przez serwer (do multicast UDP)
    MSG_TYPE_GET_HISTORY_REQ,
    MSG_TYPE_HISTORY_RESP_CHUNK,
    MSG_TYPE_HISTORY_RESP_END,
    MSG_TYPE_ERROR_RESP,
    MSG_TYPE_LOGOUT_REQ
    // ... inne typy
} MessageType;

// Struktura nagłówka TLV
typedef struct __attribute__((packed))
{ // packed - aby nie było paddingu
    MessageType type;
    uint16_t length; // Długość danych w 'value'
} TLVHeader;

// Struktury dla payloadów (uwaga na kolejność bajtów przy przesyłaniu)
typedef struct __attribute__((packed))
{
    char username[MAX_USERNAME_LEN];
    char password[MAX_PASSWORD_LEN]; // W rzeczywistości przesyłany hash lub token
} AuthPayload;

typedef struct __attribute__((packed))
{
    char sender[MAX_USERNAME_LEN];
    char recipient[MAX_USERNAME_LEN]; // Może być pusty, jeśli to czat grupowy
    char message[MAX_MSG_LEN];
} MessagePayload;

typedef struct __attribute__((packed))
{
    uint8_t success;           // 1 = success, 0 = failure
    char message[MAX_MSG_LEN]; // Komunikat błędu lub sukcesu
} ResponsePayload;

// Funkcje pomocnicze dla TLV (deklaracje)
// Zmienione, aby korzystały z read_n/write_n z utils.c
int send_tlv(int sockfd, MessageType type, const void *value, uint16_t length);
int receive_tlv(int sockfd, TLVHeader *header, char *value_buffer, uint16_t max_value_len);

#endif // COMMON_H