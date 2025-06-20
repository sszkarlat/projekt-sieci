#include "common.h"
#include "utils.h"

// Dane przekazywane do wątku odbiorczego
typedef struct
{
    int chat_sock;
    pthread_mutex_t *print_mutex; // Mutex do ochrony stdio
} ChatReceiverArgs;

// Funkcja wątku odbierającego wiadomości multicast
void *chat_receiver_thread(void *arg)
{
    ChatReceiverArgs *args = (ChatReceiverArgs *)arg;
    int chat_sock = args->chat_sock;
    pthread_mutex_t *print_mutex = args->print_mutex;

    TLVHeader header;
    char value_buffer[TLV_BUFFER_SIZE];

    struct sockaddr_in sender_addr;
    socklen_t sender_len = sizeof(sender_addr);

    log_message(LOG_INFO, "Chat receiver thread started.");

    while (1)
    {
        // Użyj recvfrom, aby móc sprawdzić nadawcę (choć dla multicast nie zawsze ma sens)
        ssize_t bytes_received = recvfrom(chat_sock, value_buffer, sizeof(value_buffer), 0,
                                          (struct sockaddr *)&sender_addr, &sender_len);

        if (bytes_received < 0)
        {
            if (errno == EINTR)
                continue; // Przerwane przez sygnał
            perror("chat_receiver_thread: recvfrom failed");
            break;
        }
        else if (bytes_received == 0)
        {
            log_message(LOG_INFO, "Chat receiver thread: Multicast socket closed.");
            break;
        }

        // Wiadomość jest w formacie TLV
        if (bytes_received >= sizeof(TLVHeader))
        {
            memcpy(&header, value_buffer, sizeof(TLVHeader));
            header.type = ntohl(header.type);
            header.length = ntohs(header.length);

            if (header.type == MSG_TYPE_REALTIME_CHAT && header.length <= sizeof(MessagePayload))
            {
                MessagePayload payload;
                memcpy(&payload, value_buffer + sizeof(TLVHeader), header.length);

                pthread_mutex_lock(print_mutex); // Zablokuj stdout
                printf("\n[CHAT from %s]: %s\n", payload.sender, payload.message);
                printf("> "); // Ponowne wyświetlenie promptu
                fflush(stdout);
                pthread_mutex_unlock(print_mutex); // Odblokuj stdout
            }
            else
            {
                pthread_mutex_lock(print_mutex);
                printf("\n[CHAT]: Received unknown/malformed multicast message (type: %d, len: %u).\n", header.type, header.length);
                printf("> ");
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
{ // Zmieniono na IPv4
    int sock_udp;
    struct sockaddr_in multicast_addr, server_resp_addr; // Zmieniono na IPv4
    socklen_t server_resp_addr_len = sizeof(server_resp_addr);
    char buffer[TLV_BUFFER_SIZE];
    TLVHeader header;

    sock_udp = socket(AF_INET, SOCK_DGRAM, 0); // Używamy IPv4
    if (sock_udp < 0)
        error_exit("discover_server: socket failed", LOG_ERR);

    struct timeval tv;
    tv.tv_sec = 2; // Czekaj 2 sekundy na odpowiedź
    tv.tv_usec = 0;
    if (setsockopt(sock_udp, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
    { // Usunięto const char*
        perror("setsockopt SO_RCVTIMEO failed");
    }

    memset(&multicast_addr, 0, sizeof(multicast_addr));
    multicast_addr.sin_family = AF_INET;
    multicast_addr.sin_port = htons(DISCOVERY_UDP_PORT);
    inet_pton(AF_INET, MULTICAST_GROUP_DISCOVERY, &multicast_addr.sin_addr); // Używamy IPv4

    printf("Sending discovery ping to %s:%d\n", MULTICAST_GROUP_DISCOVERY, DISCOVERY_UDP_PORT);

    header.type = htonl(MSG_TYPE_DISCOVERY_PING);
    header.length = htons(0); // PING bez danych
    if (sendto(sock_udp, &header, sizeof(TLVHeader), 0,
               (struct sockaddr *)&multicast_addr, sizeof(multicast_addr)) < 0)
    {
        perror("sendto multicast ping failed");
        close(sock_udp);
        return;
    }

    printf("Waiting for discovery pong...\n");
    ssize_t len = recvfrom(sock_udp, buffer, sizeof(buffer), 0,
                           (struct sockaddr *)&server_resp_addr, &server_resp_addr_len);

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

    if (len >= sizeof(TLVHeader))
    {
        TLVHeader pong_header;
        memcpy(&pong_header, buffer, sizeof(TLVHeader));
        pong_header.type = ntohl(pong_header.type);
        pong_header.length = ntohs(pong_header.length);

        if (pong_header.type == MSG_TYPE_DISCOVERY_PONG && pong_header.length == sizeof(uint16_t))
        {
            uint16_t server_tcp_port_net;
            memcpy(&server_tcp_port_net, buffer + sizeof(TLVHeader), sizeof(uint16_t));

            memcpy(server_addr_out, &server_resp_addr, sizeof(struct sockaddr_in));
            server_addr_out->sin_port = server_tcp_port_net; // Już w sieciowej kolejności

            char server_ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &server_resp_addr.sin_addr, server_ip_str, INET_ADDRSTRLEN); // Adres z recvfrom
            printf("Server discovered at %s port %d (TCP service on port %d)\n",
                   server_ip_str, ntohs(server_resp_addr.sin_port), ntohs(server_addr_out->sin_port));
        }
        else
        {
            printf("Received invalid discovery pong.\n");
        }
    }
    else
    {
        printf("Received too short discovery response.\n");
    }
    close(sock_udp);
}

int main(int argc, char *argv[])
{
    int sock_tcp;                // Główny socket TCP do komunikacji z serwerem
    int chat_sock_udp;           // Socket UDP do odbierania wiadomości czatu multicast
    pthread_t chat_thread;       // Wątek do obsługi odbierania czatu multicast
    pthread_mutex_t print_mutex; // Mutex do ochrony stdio między wątkami
    ChatReceiverArgs chat_args;  // Argumenty dla wątku odbiorczego

    struct sockaddr_in server_addr_tcp; // Zmieniono na IPv4

    // Inicjalizacja mutexu
    pthread_mutex_init(&print_mutex, NULL);

    // Domyślne wartości
    char server_hostname[256] = "127.0.0.1"; // Domyślny serwer
    int use_discovery = 0;

    // Parsowanie argumentów
    if (argc > 1)
    {
        if (strcmp(argv[1], "-discover") == 0)
        {
            use_discovery = 1;
        }
        else
        {
            strncpy(server_hostname, argv[1], sizeof(server_hostname) - 1);
            server_hostname[sizeof(server_hostname) - 1] = '\0';
        }
    }
    else
    {
        printf("Usage: %s [-discover | <server_address_or_hostname>]\n", argv[0]);
        printf("Defaulting to server at %s:%d\n", server_hostname, SERVER_TCP_PORT);
    }

    if (use_discovery)
    {
        discover_server(&server_addr_tcp);
        if (server_addr_tcp.sin_family != AF_INET)
        { // Sprawdzamy czy discovery znalazło serwer
            return 1;
        }
    }
    else
    {
        // Rozwiązanie nazwy hosta przez DNS (IPv4)
        struct addrinfo hints, *res;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET; // Używamy IPv4
        hints.ai_socktype = SOCK_STREAM;

        char port_str[10];
        snprintf(port_str, sizeof(port_str), "%d", SERVER_TCP_PORT);

        int status = getaddrinfo(server_hostname, port_str, &hints, &res);
        if (status != 0)
        {
            fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
            return 1;
        }
        memcpy(&server_addr_tcp, res->ai_addr, sizeof(struct sockaddr_in));
        freeaddrinfo(res);
    }

    // 1. Utworzenie głównego gniazda TCP
    sock_tcp = socket(AF_INET, SOCK_STREAM, 0); // Używamy IPv4
    if (sock_tcp < 0)
        error_exit("socket failed", LOG_ERR);

    // 2. Połączenie z serwerem TCP
    if (connect(sock_tcp, (struct sockaddr *)&server_addr_tcp, sizeof(server_addr_tcp)) < 0)
    {
        perror("connect failed");
        close(sock_tcp);
        exit(EXIT_FAILURE);
    }
    printf("Connected to server.\n");

    // 3. Utworzenie i konfiguracja gniazda UDP do odbioru multicast czatu
    chat_sock_udp = socket(AF_INET, SOCK_DGRAM, 0); // Używamy IPv4
    if (chat_sock_udp < 0)
    {
        perror("chat_sock_udp socket failed");
        close(sock_tcp);
        exit(EXIT_FAILURE);
    }

    // SO_REUSEADDR dla multicast jest kluczowe!
    int optval = 1;
    if (setsockopt(chat_sock_udp, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0)
    {
        perror("setsockopt SO_REUSEADDR for chat_sock_udp failed");
        close(chat_sock_udp);
        close(sock_tcp);
        exit(EXIT_FAILURE);
    }

    // Powiązanie gniazda UDP z portem multicast czatu
    struct sockaddr_in chat_bind_addr;
    memset(&chat_bind_addr, 0, sizeof(chat_bind_addr));
    chat_bind_addr.sin_family = AF_INET;
    chat_bind_addr.sin_addr.s_addr = htonl(INADDR_ANY); // Nasłuchuj na wszystkich interfejsach
    chat_bind_addr.sin_port = htons(CHAT_UDP_PORT);

    if (bind(chat_sock_udp, (struct sockaddr *)&chat_bind_addr, sizeof(chat_bind_addr)) < 0)
    {
        perror("chat_sock_udp bind failed");
        close(chat_sock_udp);
        close(sock_tcp);
        exit(EXIT_FAILURE);
    }

    // Dołączenie do grupy multicast czatu
    struct ip_mreq group_chat;
    group_chat.imr_multiaddr.s_addr = inet_addr(MULTICAST_GROUP_CHAT);
    group_chat.imr_interface.s_addr = htonl(INADDR_ANY); // Domyślny interfejs
    if (setsockopt(chat_sock_udp, IPPROTO_IP, IP_ADD_MEMBERSHIP, &group_chat, sizeof(group_chat)) < 0)
    {
        perror("setsockopt IP_ADD_MEMBERSHIP for chat_sock_udp failed");
        close(chat_sock_udp);
        close(sock_tcp);
        exit(EXIT_FAILURE);
    }
    printf("Joined chat multicast group %s:%d.\n", MULTICAST_GROUP_CHAT, CHAT_UDP_PORT);

    // 4. Utworzenie wątku do odbierania wiadomości multicast
    chat_args.chat_sock = chat_sock_udp;
    chat_args.print_mutex = &print_mutex;
    if (pthread_create(&chat_thread, NULL, chat_receiver_thread, (void *)&chat_args) != 0)
    {
        perror("pthread_create failed for chat_receiver_thread");
        close(chat_sock_udp);
        close(sock_tcp);
        exit(EXIT_FAILURE);
    }

    // Główna pętla klienta (CLI i wysyłanie przez TCP)
    char command_buffer[MAX_MSG_LEN + MAX_USERNAME_LEN * 2 + 10]; // Na komendy i dane
    char username[MAX_USERNAME_LEN] = "";
    int logged_in = 0;

    printf("Welcome to the chat! Type 'register <user> <pass>' or 'login <user> <pass>'.\n");
    printf("Then 'send <recipient> <message>' or 'history <user_to_get_history>'. Type 'quit' to exit.\n");
    printf("> ");
    fflush(stdout);

    fd_set read_fds;
    int max_fd_cli = STDIN_FILENO;

    while (1)
    {
        FD_ZERO(&read_fds);
        FD_SET(STDIN_FILENO, &read_fds);
        // FD_SET(sock_tcp, &read_fds); // Jeśli chcemy asynchronicznie odbierać z TCP (np. błędy)

        // Używamy select na stdin
        int activity = select(max_fd_cli + 1, &read_fds, NULL, NULL, NULL);

        if (activity < 0)
        {
            if (errno == EINTR)
                continue;
            perror("select failed in main client loop");
            break;
        }

        if (FD_ISSET(STDIN_FILENO, &read_fds))
        {
            pthread_mutex_lock(&print_mutex); // Zablokuj stdout/stdin
            if (fgets(command_buffer, sizeof(command_buffer), stdin) == NULL)
            {
                printf("EOF on stdin. Exiting.\n");
                pthread_mutex_unlock(&print_mutex);
                break;
            }
            pthread_mutex_unlock(&print_mutex); // Odblokuj

            // Usuń znak nowej linii
            command_buffer[strcspn(command_buffer, "\n")] = 0;

            // Parsowanie komend
            if (strncmp(command_buffer, "register ", 9) == 0)
            {
                char user_tmp[MAX_USERNAME_LEN], pass_tmp[MAX_PASSWORD_LEN];
                if (sscanf(command_buffer + 9, "%s %s", user_tmp, pass_tmp) == 2)
                {
                    AuthPayload auth_payload;
                    strncpy(auth_payload.username, user_tmp, MAX_USERNAME_LEN - 1);
                    strncpy(auth_payload.password, pass_tmp, MAX_PASSWORD_LEN - 1);
                    send_tlv(sock_tcp, MSG_TYPE_REGISTER_REQ, &auth_payload, sizeof(auth_payload));
                    // Odczytaj odpowiedź serwera (synchronicznie)
                    TLVHeader resp_header;
                    char resp_value[TLV_BUFFER_SIZE];
                    if (receive_tlv(sock_tcp, &resp_header, resp_value, sizeof(resp_value)) == 0 && resp_header.type == MSG_TYPE_REGISTER_RESP)
                    {
                        ResponsePayload *resp = (ResponsePayload *)resp_value;
                        printf("Server response: %s (success: %d)\n", resp->message, resp->success);
                    }
                    else
                    {
                        printf("Error receiving register response.\n");
                    }
                }
                else
                {
                    printf("Usage: register <user> <pass>\n");
                }
            }
            else if (strncmp(command_buffer, "login ", 6) == 0)
            {
                char user_tmp[MAX_USERNAME_LEN], pass_tmp[MAX_PASSWORD_LEN];
                if (sscanf(command_buffer + 6, "%s %s", user_tmp, pass_tmp) == 2)
                {
                    AuthPayload auth_payload;
                    strncpy(auth_payload.username, user_tmp, MAX_USERNAME_LEN - 1);
                    strncpy(auth_payload.password, pass_tmp, MAX_PASSWORD_LEN - 1);
                    send_tlv(sock_tcp, MSG_TYPE_LOGIN_REQ, &auth_payload, sizeof(auth_payload));
                    // Odczytaj odpowiedź serwera
                    TLVHeader resp_header;
                    char resp_value[TLV_BUFFER_SIZE];
                    if (receive_tlv(sock_tcp, &resp_header, resp_value, sizeof(resp_value)) == 0 && resp_header.type == MSG_TYPE_LOGIN_RESP)
                    {
                        ResponsePayload *resp = (ResponsePayload *)resp_value;
                        printf("Server response: %s (success: %d)\n", resp->message, resp->success);
                        if (resp->success)
                        {
                            logged_in = 1;
                            strncpy(username, user_tmp, MAX_USERNAME_LEN - 1);
                            printf("Logged in as %s.\n", username);
                        }
                    }
                    else
                    {
                        printf("Error receiving login response.\n");
                    }
                }
                else
                {
                    printf("Usage: login <user> <pass>\n");
                }
            }
            else if (strncmp(command_buffer, "send ", 5) == 0)
            {
                if (!logged_in)
                {
                    printf("Please login first.\n");
                }
                else
                {
                    char recipient_tmp[MAX_USERNAME_LEN];
                    char *msg_start = strchr(command_buffer + 5, ' ');
                    if (msg_start && sscanf(command_buffer + 5, "%s", recipient_tmp) == 1)
                    {
                        msg_start++; // Pomiń spację
                        MessagePayload msg_payload;
                        strncpy(msg_payload.sender, username, MAX_USERNAME_LEN - 1);
                        strncpy(msg_payload.recipient, recipient_tmp, MAX_USERNAME_LEN - 1);
                        strncpy(msg_payload.message, msg_start, MAX_MSG_LEN - 1);
                        send_tlv(sock_tcp, MSG_TYPE_SEND_MSG_REQ, &msg_payload, sizeof(msg_payload));
                        // Server sends back an ACK or ERROR_RESP
                        TLVHeader ack_header;
                        char ack_value[TLV_BUFFER_SIZE];
                        if (receive_tlv(sock_tcp, &ack_header, ack_value, sizeof(ack_value)) == 0 && ack_header.type == MSG_TYPE_ERROR_RESP)
                        { // ACK
                            ResponsePayload *ack_resp = (ResponsePayload *)ack_value;
                            printf("Server ACK: %s (success: %d)\n", ack_resp->message, ack_resp->success);
                        }
                    }
                    else
                    {
                        printf("Usage: send <recipient> <message>\n");
                    }
                }
            }
            else if (strncmp(command_buffer, "history ", 8) == 0)
            {
                if (!logged_in)
                {
                    printf("Please login first.\n");
                }
                else
                {
                    char other_user_tmp[MAX_USERNAME_LEN];
                    if (sscanf(command_buffer + 8, "%s", other_user_tmp) == 1)
                    {
                        AuthPayload req_payload; // Używamy AuthPayload jako prostego sposobu przekazania username
                        strncpy(req_payload.username, username, MAX_USERNAME_LEN - 1);
                        strncpy(req_payload.password, other_user_tmp, MAX_PASSWORD_LEN - 1); // Drugie pole jako 'other_user'
                        send_tlv(sock_tcp, MSG_TYPE_GET_HISTORY_REQ, &req_payload, sizeof(req_payload));

                        // Odbieraj fragmenty historii
                        TLVHeader hist_header;
                        char hist_value[TLV_BUFFER_SIZE];
                        pthread_mutex_lock(&print_mutex); // Zablokuj stdout/stdin na czas wyświetlania historii
                        printf("--- HISTORY with %s ---\n", other_user_tmp);
                        while (receive_tlv(sock_tcp, &hist_header, hist_value, sizeof(hist_value)) == 0)
                        {
                            if (hist_header.type == MSG_TYPE_HISTORY_RESP_CHUNK)
                            {
                                MessagePayload *hist_chunk = (MessagePayload *)hist_value; // Odczytujemy jako MessagePayload
                                printf("%s\n", hist_chunk->message);                       // Wyświetlamy całą linię
                            }
                            else if (hist_header.type == MSG_TYPE_HISTORY_RESP_END)
                            {
                                printf("--- END HISTORY ---\n");
                                break;
                            }
                            else
                            {
                                printf("Received unexpected TLV type %d during history retrieval.\n", hist_header.type);
                                break;
                            }
                        }
                        pthread_mutex_unlock(&print_mutex);
                    }
                    else
                    {
                        printf("Usage: history <other_user>\n");
                    }
                }
            }
            else if (strcmp(command_buffer, "quit") == 0)
            {
                if (logged_in)
                {
                    send_tlv(sock_tcp, MSG_TYPE_LOGOUT_REQ, NULL, 0); // Wyślij logout
                }
                break;
            }
            else
            {
                printf("Unknown command.\n");
            }
            printf("> "); // Ponowne wyświetlenie promptu
            fflush(stdout);
        }
        // Brak FD_ISSET(sock_tcp, &read_fds) tutaj, ponieważ odpowiedzi od serwera (np. ACK, RESP)
        // są odbierane synchronicznie zaraz po wysłaniu żądania.
        // Asynchroniczne odbieranie jest tylko dla multicast.
    }

    // Opuść grupę multicast (opcjonalne, ale dobra praktyka)
    // struct ip_mreq group_chat;
    // group_chat.imr_multiaddr.s_addr = inet_addr(MULTICAST_GROUP_CHAT);
    // group_chat.imr_interface.s_addr = htonl(INADDR_ANY);
    // setsockopt(chat_sock_udp, IPPROTO_IP, IP_DROP_MEMBERSHIP, &group_chat, sizeof(group_chat));

    // Czekaj na wątek czatu, aby się zakończył
    pthread_cancel(chat_thread); // Wątek jest zablokowany na recvfrom, trzeba go anulować
    pthread_join(chat_thread, NULL);

    // Zniszcz mutex
    pthread_mutex_destroy(&print_mutex);

    close(sock_tcp);
    close(chat_sock_udp);
    printf("Client disconnected and exited.\n");
    return 0;
}