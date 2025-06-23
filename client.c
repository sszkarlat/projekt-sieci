#include "common.h"
#include "utils.h"

typedef struct
{
    int chat_sock;
    pthread_mutex_t *print_mutex;
    char *logged_username;
} ChatReceiverArgs;

void *chat_receiver_thread(void *arg)
{
    ChatReceiverArgs *args = (ChatReceiverArgs *)arg;
    int chat_sock = args->chat_sock;
    pthread_mutex_t *print_mutex = args->print_mutex;
    char *logged_username = args->logged_username;  
    char buffer[TLV_BUFFER_SIZE];

    log_message(LOG_INFO, "Chat receiver thread started.");

    while (1)
    {
        ssize_t bytes_received = recvfrom(chat_sock, buffer, sizeof(buffer), 0, NULL, NULL);

        if (bytes_received < 0)
        {
            if (errno == EINTR) continue;
            perror("chat_receiver_thread: recvfrom failed");
            break;
        }
        else if (bytes_received == 0)
        {
            log_message(LOG_INFO, "Chat receiver thread: Multicast socket closed.");
            break;
        }

        if (bytes_received >= (ssize_t)sizeof(TLVHeader))
        {
            TLVHeader *header = (TLVHeader *)buffer;
            uint32_t type = ntohl(header->type);
            uint16_t length = ntohs(header->length);

            if (type == MSG_TYPE_REALTIME_CHAT && length == sizeof(MessagePayload))
            {
                MessagePayload *payload = (MessagePayload *)(buffer + sizeof(TLVHeader));
                
                // MODYFIKACJA: Sprawdź czy zalogowany użytkownik jest adresatem
                pthread_mutex_lock(print_mutex);
                if (logged_username != NULL && strlen(logged_username) > 0 && 
                    strcmp(payload->recipient, logged_username) == 0)
                {
                    printf("\n[%s]: %s\n> ", payload->sender, payload->message);
                    fflush(stdout);
                }
                else if (logged_username == NULL || strlen(logged_username) == 0)
                {
                    // Jeśli nie jesteś zalogowany, nie wyświetlaj wiadomości
                    printf("\n[INFO]: Otrzymano wiadomość, ale nie jesteś zalogowany.\n> ");
                    fflush(stdout);
                }
                pthread_mutex_unlock(print_mutex);
            }
            else
            {
                pthread_mutex_lock(print_mutex);
                printf("\n[CHAT]: Received unknown/malformed multicast message (type: %u, len: %u).\n> ", type, length);
                fflush(stdout);
                pthread_mutex_unlock(print_mutex);
            }
        }
    }
    close(chat_sock);
    log_message(LOG_INFO, "Chat receiver thread terminated.");
    return NULL;
}

void discover_server(struct sockaddr_in *server_addr_out)
{
    int sock_udp;
    struct sockaddr_in multicast_addr, server_resp_addr;
    socklen_t server_resp_addr_len = sizeof(server_resp_addr);
    char buffer[TLV_BUFFER_SIZE];

    sock_udp = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_udp < 0)
    {
        perror("discover_server: socket failed");
        return;
    }

    struct timeval tv = {.tv_sec = 2, .tv_usec = 0};
    setsockopt(sock_udp, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    memset(&multicast_addr, 0, sizeof(multicast_addr));
    multicast_addr.sin_family = AF_INET;
    multicast_addr.sin_port = htons(DISCOVERY_UDP_PORT);
    if (inet_pton(AF_INET, MULTICAST_GROUP_DISCOVERY, &multicast_addr.sin_addr) <= 0)
    {
        perror("discover_server: inet_pton failed for multicast group");
        close(sock_udp);
        return;
    }

    printf("Sending discovery ping to %s:%d\n", MULTICAST_GROUP_DISCOVERY, DISCOVERY_UDP_PORT);

    TLVHeader header;
    header.type = htonl(MSG_TYPE_DISCOVERY_PING);
    header.length = htons(0);
    if (sendto(sock_udp, &header, sizeof(TLVHeader), 0, (struct sockaddr *)&multicast_addr, sizeof(multicast_addr)) < 0)
    {
        perror("sendto multicast ping failed");
        close(sock_udp);
        return;
    }

    printf("Waiting for discovery pong...\n");
    ssize_t len = recvfrom(sock_udp, buffer, sizeof(buffer), 0, (struct sockaddr *)&server_resp_addr, &server_resp_addr_len);

    if (len < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            printf("Discovery timeout, no server responded.\n");
        }
        else
        {
            perror("recvfrom discovery pong failed");
        }
        close(sock_udp);
        return;
    }

    if (len >= (ssize_t)(sizeof(TLVHeader) + sizeof(uint16_t)))
    {
        TLVHeader *pong_header = (TLVHeader *)buffer;
        if (ntohl(pong_header->type) == MSG_TYPE_DISCOVERY_PONG && ntohs(pong_header->length) == sizeof(uint16_t))
        {
            uint16_t server_tcp_port_net;
            memcpy(&server_tcp_port_net, buffer + sizeof(TLVHeader), sizeof(uint16_t));
            memcpy(server_addr_out, &server_resp_addr, sizeof(struct sockaddr_in));
            server_addr_out->sin_port = server_tcp_port_net;

            char server_ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &server_resp_addr.sin_addr, server_ip_str, INET_ADDRSTRLEN);
            printf("Server discovered at %s (TCP service on port %d)\n", server_ip_str, ntohs(server_addr_out->sin_port));
        }
        else
        {
            printf("Received invalid discovery pong.\n");
        }
    }
    close(sock_udp);
}

int main(int argc, char *argv[])
{
    int sock_tcp, chat_sock_udp;
    pthread_t chat_thread;
    pthread_mutex_t print_mutex;
    ChatReceiverArgs chat_args;
    struct sockaddr_in server_addr_tcp;
    memset(&server_addr_tcp, 0, sizeof(server_addr_tcp));

    pthread_mutex_init(&print_mutex, NULL);
    openlog("KomunikatorKlient", LOG_PID, LOG_USER);

    char server_hostname[256] = "127.0.0.1";
    int use_discovery = 0;

    if (argc > 1)
    {
        if (strcmp(argv[1], "-discover") == 0) use_discovery = 1;
        else strncpy(server_hostname, argv[1], sizeof(server_hostname) - 1);
    }
    else
    {
        printf("Usage: %s [-discover | <server_address>]\n", argv[0]);
    }

    if (use_discovery)
    {
        discover_server(&server_addr_tcp);
        if (server_addr_tcp.sin_family != AF_INET)
        {
            fprintf(stderr, "Discovery failed. Exiting.\n");
            return 1;
        }
    }
    else
    {
        printf("Connecting to default/specified server %s:%d\n", server_hostname, SERVER_TCP_PORT);
        struct addrinfo hints, *res;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        char port_str[10];
        snprintf(port_str, sizeof(port_str), "%d", SERVER_TCP_PORT);
        if (getaddrinfo(server_hostname, port_str, &hints, &res) != 0)
        {
            perror("getaddrinfo failed");
            return 1;
        }
        memcpy(&server_addr_tcp, res->ai_addr, sizeof(struct sockaddr_in));
        freeaddrinfo(res);
    }

    sock_tcp = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_tcp < 0)
    {
        perror("socket failed");
        return 1;
    }
    if (connect(sock_tcp, (struct sockaddr *)&server_addr_tcp, sizeof(server_addr_tcp)) < 0)
    {
        perror("connect failed");
        close(sock_tcp);
        return 1;
    }
    printf("Connected to server.\n");

    chat_sock_udp = socket(AF_INET, SOCK_DGRAM, 0);
    if (chat_sock_udp < 0)
    {
        perror("chat_sock_udp socket failed");
        close(sock_tcp);
        return 1;
    }

    int optval = 1;
    if (setsockopt(chat_sock_udp, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0)
    {
        perror("setsockopt SO_REUSEADDR for chat_sock_udp failed");
        close(chat_sock_udp);
        close(sock_tcp);
        return 1;
    }

    struct sockaddr_in chat_bind_addr;
    memset(&chat_bind_addr, 0, sizeof(chat_bind_addr));
    chat_bind_addr.sin_family = AF_INET;
    chat_bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    chat_bind_addr.sin_port = htons(CHAT_UDP_PORT);
    if (bind(chat_sock_udp, (struct sockaddr *)&chat_bind_addr, sizeof(chat_bind_addr)) < 0)
    {
        perror("chat_sock_udp bind failed");
        close(chat_sock_udp);
        close(sock_tcp);
        return 1;
    }

    struct ip_mreq group_chat;
    group_chat.imr_multiaddr.s_addr = inet_addr(MULTICAST_GROUP_CHAT);
    group_chat.imr_interface.s_addr = htonl(INADDR_ANY);
    if (setsockopt(chat_sock_udp, IPPROTO_IP, IP_ADD_MEMBERSHIP, &group_chat, sizeof(group_chat)) < 0)
    {
        perror("setsockopt IP_ADD_MEMBERSHIP for chat_sock_udp failed");
        close(chat_sock_udp);
        close(sock_tcp);
        return 1;
    }
    printf("Joined chat multicast group %s:%d.\n", MULTICAST_GROUP_CHAT, CHAT_UDP_PORT);

    char command_buffer[MAX_MSG_LEN + MAX_USERNAME_LEN * 2 + 20];
    char username[MAX_USERNAME_LEN] = "";  // MODYFIKACJA: będzie przekazane do wątku
    int logged_in = 0;

    // MODYFIKACJA: Konfiguracja argumentów dla wątku z nazwą użytkownika
    chat_args.chat_sock = chat_sock_udp;
    chat_args.print_mutex = &print_mutex;
    chat_args.logged_username = username;  // Przekaż wskaźnik na tablicę username
    
    if (pthread_create(&chat_thread, NULL, chat_receiver_thread, &chat_args) != 0)
    {
        perror("pthread_create failed for chat_receiver_thread");
        close(chat_sock_udp);
        close(sock_tcp);
        return 1;
    }

    printf("\nWelcome! Commands:\n");
    printf("  register <user> <pass>\n");
    printf("  login <user> <pass>\n");
    printf("  send <recipient> <message>\n");
    printf("  history <other_user>\n");
    printf("  quit\n");
    printf("> ");
    fflush(stdout);

    while (1)
    {
        if (fgets(command_buffer, sizeof(command_buffer), stdin) == NULL) break;
        command_buffer[strcspn(command_buffer, "\n")] = 0;

        if (strncmp(command_buffer, "register ", 9) == 0)
        {
            char user[MAX_USERNAME_LEN], pass[MAX_PASSWORD_LEN];
            if (sscanf(command_buffer + 9, "%31s %31s", user, pass) == 2)
            {
                AuthPayload payload;
                strncpy(payload.username, user, MAX_USERNAME_LEN);
                strncpy(payload.password, pass, MAX_PASSWORD_LEN);
                send_tlv(sock_tcp, MSG_TYPE_REGISTER_REQ, &payload, sizeof(payload));
                TLVHeader resp_h; char resp_v[TLV_BUFFER_SIZE];
                if (receive_tlv(sock_tcp, &resp_h, resp_v, sizeof(resp_v)) == 0 && resp_h.type == MSG_TYPE_REGISTER_RESP)
                {
                    ResponsePayload *resp = (ResponsePayload *)resp_v;
                    printf("Server: %s\n", resp->message);
                }
            }
        }
        else if (strncmp(command_buffer, "login ", 6) == 0)
        {
            char user[MAX_USERNAME_LEN], pass[MAX_PASSWORD_LEN];
            if (sscanf(command_buffer + 6, "%31s %31s", user, pass) == 2)
            {
                AuthPayload payload;
                strncpy(payload.username, user, MAX_USERNAME_LEN);
                strncpy(payload.password, pass, MAX_PASSWORD_LEN);
                send_tlv(sock_tcp, MSG_TYPE_LOGIN_REQ, &payload, sizeof(payload));
                TLVHeader resp_h; char resp_v[TLV_BUFFER_SIZE];
                if (receive_tlv(sock_tcp, &resp_h, resp_v, sizeof(resp_v)) == 0 && resp_h.type == MSG_TYPE_LOGIN_RESP)
                {
                    ResponsePayload *resp = (ResponsePayload *)resp_v;
                    printf("Server: %s\n", resp->message);
                    if (resp->success)
                    {
                        logged_in = 1;
                        strncpy(username, user, MAX_USERNAME_LEN);
                        // username jest teraz aktualizowane i wątek ma dostęp przez wskaźnik
                    }
                }
            }
        }
        else if (strncmp(command_buffer, "send ", 5) == 0)
        {
            if (!logged_in) { printf("Please login first.\n"); }
            else
            {
                char recipient[MAX_USERNAME_LEN];
                char *msg_start = strchr(command_buffer + 5, ' ');
                if (msg_start && sscanf(command_buffer + 5, "%31s", recipient) == 1)
                {
                    msg_start++;
                    MessagePayload payload;
                    strncpy(payload.sender, username, MAX_USERNAME_LEN);
                    strncpy(payload.recipient, recipient, MAX_USERNAME_LEN);
                    strncpy(payload.message, msg_start, MAX_MSG_LEN);
                    send_tlv(sock_tcp, MSG_TYPE_SEND_MSG_REQ, &payload, sizeof(payload));
                    TLVHeader resp_h; char resp_v[TLV_BUFFER_SIZE];
                    if (receive_tlv(sock_tcp, &resp_h, resp_v, sizeof(resp_v)) == 0 && resp_h.type == MSG_TYPE_SEND_MSG_RESP) {
                        ResponsePayload *resp = (ResponsePayload *)resp_v;
                        printf("Server ACK: %s\n", resp->message);
                    }
                } else printf("Usage: send <recipient> <message>\n");
            }
        }
        else if (strncmp(command_buffer, "history ", 8) == 0)
        {
            if (!logged_in) { printf("Please login first.\n"); }
            else
            {
                char other_user[MAX_USERNAME_LEN];
                if (sscanf(command_buffer + 8, "%31s", other_user) == 1)
                {
                    AuthPayload req;
                    strncpy(req.username, username, MAX_USERNAME_LEN);
                    strncpy(req.password, other_user, MAX_PASSWORD_LEN); // Używane jako drugi user
                    send_tlv(sock_tcp, MSG_TYPE_GET_HISTORY_REQ, &req, sizeof(req));
                    printf("--- HISTORY with %s ---\n", other_user);
                    while(1) {
                        TLVHeader hist_h; char hist_v[TLV_BUFFER_SIZE];
                        if (receive_tlv(sock_tcp, &hist_h, hist_v, sizeof(hist_v)) != 0) break;
                        if (hist_h.type == MSG_TYPE_HISTORY_RESP_CHUNK) {
                            MessagePayload *chunk = (MessagePayload *)hist_v;
                            printf("%s\n", chunk->message);
                        } else if (hist_h.type == MSG_TYPE_HISTORY_RESP_END) {
                            break;
                        } else break;
                    }
                    printf("--- END HISTORY ---\n");
                } else printf("Usage: history <other_user>\n");
            }
        }
        else if (strcmp(command_buffer, "quit") == 0)
        {
            if (logged_in) send_tlv(sock_tcp, MSG_TYPE_LOGOUT_REQ, NULL, 0);
            break;
        }
        else
        {
            printf("Unknown command.\n");
        }

        pthread_mutex_lock(&print_mutex);
        printf("> ");
        fflush(stdout);
        pthread_mutex_unlock(&print_mutex);
    }

    pthread_cancel(chat_thread);
    pthread_join(chat_thread, NULL);
    pthread_mutex_destroy(&print_mutex);
    close(sock_tcp);
    // Gniazdo chat_sock_udp jest zamykane przez wątek
    printf("\nClient disconnected and exited.\n");
    closelog();
    return 0;
}
