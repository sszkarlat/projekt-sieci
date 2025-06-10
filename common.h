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

// Porty
#define SERVER_TCP_PORT 12345
#define DISCOVERY_UDP_PORT 12346
#define MULTICAST_GROUP "239.0.0.1" // Przykładowy adres multicast

// Rozmiary buforów
#define MAX_MSG_LEN 1024
#define MAX_USERNAME_LEN 32
#define MAX_PASSWORD_LEN 32
#define TLV_BUFFER_SIZE (sizeof(TLVHeader) + MAX_MSG_LEN) // Maksymalny rozmiar komunikatu TLV

// Typy komunikatów TLV
typedef enum
{
    MSG_TYPE_DISCOVERY_PING = 1,
    MSG_TYPE_DISCOVERY_PONG,
    MSG_TYPE_REGISTER_REQ,
    MSG_TYPE_REGISTER_RESP,
    MSG_TYPE_LOGIN_REQ,
    MSG_TYPE_LOGIN_RESP,
    MSG_TYPE_SEND_MSG_REQ,
    MSG_TYPE_INCOMING_MSG, // Wiadomość od innego użytkownika
    MSG_TYPE_GET_HISTORY_REQ,
    MSG_TYPE_HISTORY_RESP_CHUNK, // fragment historii
    MSG_TYPE_HISTORY_RESP_END,   // koniec historii
    MSG_TYPE_ERROR_RESP,
    MSG_TYPE_LOGOUT_REQ
    // ... inne typy
} MessageType;

// Struktura nagłówka TLV
typedef struct
{
    MessageType type;
    uint16_t length; // Długość danych w 'value'
} TLVHeader;

// Przykładowe struktury dla payloadów (muszą być serializowane/deserializowane)
typedef struct
{
    char username[MAX_USERNAME_LEN];
    char password[MAX_PASSWORD_LEN];
} AuthPayload;

typedef struct
{
    char sender[MAX_USERNAME_LEN];    // Potrzebne dla INCOMING_MSG
    char recipient[MAX_USERNAME_LEN]; // Dla SEND_MSG_REQ
    char message[MAX_MSG_LEN];
} MessagePayload;

typedef struct
{
    uint8_t success;           // 1 = success, 0 = failure
    char message[MAX_MSG_LEN]; // Komunikat błędu lub sukcesu
} ResponsePayload;

// Funkcje pomocnicze dla TLV (deklaracje)
int send_tlv(int sockfd, MessageType type, const void *value, uint16_t length);
int receive_tlv(int sockfd, TLVHeader *header, char *value_buffer, uint16_t max_value_len);

#endif // COMMON_H