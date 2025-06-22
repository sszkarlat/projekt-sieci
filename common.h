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
#include <netdb.h>
#include <fcntl.h>
#include <sys/file.h>
#include <errno.h>
#include <pthread.h> // Dodano dla pthread w kliencie

// === Konfiguracja sieci ===
#define SERVER_TCP_PORT 12345
#define DISCOVERY_UDP_PORT 12346
#define CHAT_UDP_PORT 12347

#define MULTICAST_GROUP_DISCOVERY "239.0.0.1"
#define MULTICAST_GROUP_CHAT "239.0.0.2"

// === Rozmiary buforów i limity ===
#define MAX_MSG_LEN 1024
#define MAX_USERNAME_LEN 32
#define MAX_PASSWORD_LEN 32
#define TLV_BUFFER_SIZE (sizeof(TLVHeader) + MAX_MSG_LEN + sizeof(MessagePayload)) // Bezpieczny rozmiar

// === Typy komunikatów TLV ===
typedef enum
{
    MSG_TYPE_DISCOVERY_PING = 1,
    MSG_TYPE_DISCOVERY_PONG,
    MSG_TYPE_REGISTER_REQ,
    MSG_TYPE_REGISTER_RESP,
    MSG_TYPE_LOGIN_REQ,
    MSG_TYPE_LOGIN_RESP,
    MSG_TYPE_SEND_MSG_REQ,
    MSG_TYPE_SEND_MSG_RESP,      // Odpowiedź na SEND_MSG_REQ (zamiast ERROR_RESP)
    MSG_TYPE_REALTIME_CHAT,      // Wiadomość multicast czatu
    MSG_TYPE_GET_HISTORY_REQ,
    MSG_TYPE_HISTORY_RESP_CHUNK,
    MSG_TYPE_HISTORY_RESP_END,
    MSG_TYPE_ERROR_RESP,
    MSG_TYPE_LOGOUT_REQ
} MessageType;

#pragma pack(push, 1) // Zapewnia ścisłe upakowanie struktur

// Struktura nagłówka TLV
typedef struct
{
    uint32_t type;   // Zmienione na uint32_t dla spójności z htonl
    uint16_t length; // Długość danych w 'value'
} TLVHeader;

// Struktury dla payloadów
typedef struct
{
    char username[MAX_USERNAME_LEN];
    char password[MAX_PASSWORD_LEN];
} AuthPayload;

typedef struct
{
    char sender[MAX_USERNAME_LEN];
    char recipient[MAX_USERNAME_LEN];
    char message[MAX_MSG_LEN];
} MessagePayload;

typedef struct
{
    uint8_t success;
    char message[MAX_MSG_LEN];
} ResponsePayload;

#pragma pack(pop) // Przywraca domyślne upakowanie

// Funkcje pomocnicze dla TLV (deklaracje)
int send_tlv(int sockfd, MessageType type, const void *value, uint16_t length);
int receive_tlv(int sockfd, TLVHeader *header, char *value_buffer, uint16_t max_value_len);

#endif // COMMON_H