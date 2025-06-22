#include "common.h"
#include "utils.h"
#include "user_management.h"
#include "history_management.h"
#include <sys/stat.h>

volatile sig_atomic_t terminate_server = 0;

void handle_client_connection(int client_sock, struct sockaddr_in client_addr);
static int send_multicast_chat_message(const MessagePayload *payload);

void sigchld_handler(int sig)
{
    (void)sig;
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

void sigint_handler(int sig)
{
    (void)sig;
    log_message(LOG_INFO, "SIGINT received, setting termination flag.");
    terminate_server = 1;
}

void daemonize()
{
    pid_t pid = fork();
    if (pid < 0) error_exit("daemonize: fork 1 failed", LOG_ERR);
    if (pid > 0) exit(EXIT_SUCCESS);

    if (setsid() < 0) error_exit("daemonize: setsid failed", LOG_ERR);

    signal(SIGHUP, SIG_IGN);

    pid = fork();
    if (pid < 0) error_exit("daemonize: fork 2 failed", LOG_ERR);
    if (pid > 0) exit(EXIT_SUCCESS);

    umask(0);
    if (chdir("/") < 0) error_exit("daemonize: chdir failed", LOG_ERR);

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    open("/dev/null", O_RDWR);
    dup(0);
    dup(0);
}

// POPRAWIONA FUNKCJA: Używa sendto() zamiast send_tlv() dla UDP
static int send_multicast_chat_message(const MessagePayload *payload)
{
    int sock;
    struct sockaddr_in multicast_addr;
    char buffer[sizeof(TLVHeader) + sizeof(MessagePayload)];
    TLVHeader *header = (TLVHeader *)buffer;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        log_message(LOG_ERR, "send_multicast: Failed to create socket: %m");
        return -1;
    }

    memset(&multicast_addr, 0, sizeof(multicast_addr));
    multicast_addr.sin_family = AF_INET;
    multicast_addr.sin_port = htons(CHAT_UDP_PORT);
    if (inet_pton(AF_INET, MULTICAST_GROUP_CHAT, &multicast_addr.sin_addr) <= 0)
    {
        log_message(LOG_ERR, "send_multicast: Invalid multicast chat address: %s", MULTICAST_GROUP_CHAT);
        close(sock);
        return -1;
    }

    // Przygotuj pakiet TLV ręcznie
    header->type = htonl(MSG_TYPE_REALTIME_CHAT);
    header->length = htons(sizeof(MessagePayload));
    memcpy(buffer + sizeof(TLVHeader), payload, sizeof(MessagePayload));

    ssize_t sent_bytes = sendto(sock, buffer, sizeof(buffer), 0,
                               (struct sockaddr *)&multicast_addr, sizeof(multicast_addr));

    if (sent_bytes < 0)
    {
        log_message(LOG_WARNING, "send_multicast: sendto failed: %m");
        close(sock);
        return -1;
    }

    close(sock);
    return 0;
}

void handle_client_connection(int client_sock, struct sockaddr_in client_addr)
{
    char client_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip_str, INET_ADDRSTRLEN);
    log_message(LOG_INFO, "Handling client %s:%d (child PID %d)", client_ip_str, ntohs(client_addr.sin_port), getpid());

    init_user_management();
    init_history_management();

    TLVHeader header;
    char value_buffer[TLV_BUFFER_SIZE];

    while (1)
    {
        if (receive_tlv(client_sock, &header, value_buffer, sizeof(value_buffer)) < 0)
        {
            log_message(LOG_INFO, "Client %s:%d disconnected or TLV error, terminating child.", client_ip_str, ntohs(client_addr.sin_port));
            break;
        }
        log_message(LOG_DEBUG, "Received TLV type: %d, length: %u from %s", header.type, header.length, client_ip_str);

        switch (header.type)
        {
        case MSG_TYPE_REGISTER_REQ:
        {
            AuthPayload *payload = (AuthPayload *)value_buffer;
            ResponsePayload resp;
            memset(&resp, 0, sizeof(resp));
            if (register_new_user(payload->username, payload->password) == 0)
            {
                resp.success = 1;
                strncpy(resp.message, "Registration successful!", sizeof(resp.message) - 1);
            }
            else
            {
                resp.success = 0;
                strncpy(resp.message, "Registration failed (user exists or file error).", sizeof(resp.message) - 1);
            }
            send_tlv(client_sock, MSG_TYPE_REGISTER_RESP, &resp, sizeof(resp));
            break;
        }
        case MSG_TYPE_LOGIN_REQ:
        {
            AuthPayload *payload = (AuthPayload *)value_buffer;
            ResponsePayload resp;
            memset(&resp, 0, sizeof(resp));
            if (verify_user_credentials(payload->username, payload->password) == 0)
            {
                resp.success = 1;
                strncpy(resp.message, "Login successful!", sizeof(resp.message) - 1);
            }
            else
            {
                resp.success = 0;
                strncpy(resp.message, "Login failed (bad credentials or file error).", sizeof(resp.message) - 1);
            }
            send_tlv(client_sock, MSG_TYPE_LOGIN_RESP, &resp, sizeof(resp));
            break;
        }
        case MSG_TYPE_SEND_MSG_REQ:
        {
            MessagePayload *payload = (MessagePayload *)value_buffer;
            log_message(LOG_INFO, "Received SEND_MSG_REQ from %s to %s", payload->sender, payload->recipient);

            store_chat_message(payload->sender, payload->recipient, payload->sender, payload->message);

            if (send_multicast_chat_message(payload) == 0)
            {
                log_message(LOG_DEBUG, "Message from %s multicast broadcasted.", payload->sender);
            }
            else
            {
                log_message(LOG_WARNING, "Failed to broadcast message from %s.", payload->sender);
            }

            ResponsePayload ack_resp;
            memset(&ack_resp, 0, sizeof(ack_resp));
            ack_resp.success = 1;
            strncpy(ack_resp.message, "Message sent and broadcasted.", sizeof(ack_resp.message) - 1);
            // Użycie dedykowanego typu odpowiedzi
            send_tlv(client_sock, MSG_TYPE_SEND_MSG_RESP, &ack_resp, sizeof(ack_resp));
            break;
        }
        case MSG_TYPE_GET_HISTORY_REQ:
        {
            AuthPayload *req = (AuthPayload *)value_buffer;
            log_message(LOG_INFO, "Client requested history for %s with %s", req->username, req->password);
            retrieve_chat_history(req->username, req->password, client_sock);
            break;
        }
        case MSG_TYPE_LOGOUT_REQ:
        {
            log_message(LOG_INFO, "Client %s:%d requested logout.", client_ip_str, ntohs(client_addr.sin_port));
            break;
        }
        default:
        {
            log_message(LOG_WARNING, "Client %s:%d sent unknown TLV type: %d", client_ip_str, ntohs(client_addr.sin_port), header.type);
            break;
        }
        }
        if (header.type == MSG_TYPE_LOGOUT_REQ) break;
    }
    close(client_sock);
    log_message(LOG_INFO, "Closed connection with %s:%d (child PID %d)", client_ip_str, ntohs(client_addr.sin_port), getpid());
    exit(0);
}

void handle_discovery_request(int udp_sock, struct sockaddr_in client_addr)
{
    char client_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip_str, INET_ADDRSTRLEN);
    log_message(LOG_DEBUG, "Received discovery ping from %s:%d", client_ip_str, ntohs(client_addr.sin_port));

    uint16_t server_port_payload = htons(SERVER_TCP_PORT);
    char pong_buffer[sizeof(TLVHeader) + sizeof(server_port_payload)];
    TLVHeader *header = (TLVHeader *)pong_buffer;

    header->type = htonl(MSG_TYPE_DISCOVERY_PONG);
    header->length = htons(sizeof(server_port_payload));
    memcpy(pong_buffer + sizeof(TLVHeader), &server_port_payload, sizeof(server_port_payload));

    if (sendto(udp_sock, pong_buffer, sizeof(pong_buffer), 0, (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0)
    {
        log_message(LOG_WARNING, "Failed to send discovery pong to %s: %m", client_ip_str);
    }
}

int main(void)
{
    // daemonize(); // Odkomentuj, aby uruchomić jako demon
    openlog("KomunikatorSerwer", LOG_PID | LOG_CONS, LOG_DAEMON);
    log_message(LOG_INFO, "Server starting...");

    init_user_management();
    init_history_management();

    struct sigaction sa_chld, sa_int;
    sa_chld.sa_handler = sigchld_handler;
    sigemptyset(&sa_chld.sa_mask);
    sa_chld.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    if (sigaction(SIGCHLD, &sa_chld, 0) == -1) error_exit("sigaction SIGCHLD failed", LOG_ERR);

    sa_int.sa_handler = sigint_handler;
    sigemptyset(&sa_int.sa_mask);
    sa_int.sa_flags = 0;
    if (sigaction(SIGINT, &sa_int, 0) == -1) error_exit("sigaction SIGINT failed", LOG_ERR);

    int listen_sock_tcp, discovery_sock_udp;
    struct sockaddr_in server_addr_tcp, server_addr_udp, client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    int optval = 1;

    listen_sock_tcp = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_sock_tcp < 0) error_exit("TCP socket failed", LOG_ERR);
    setsockopt(listen_sock_tcp, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    memset(&server_addr_tcp, 0, sizeof(server_addr_tcp));
    server_addr_tcp.sin_family = AF_INET;
    server_addr_tcp.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr_tcp.sin_port = htons(SERVER_TCP_PORT);
    if (bind(listen_sock_tcp, (struct sockaddr *)&server_addr_tcp, sizeof(server_addr_tcp)) < 0) error_exit("TCP Bind failed", LOG_ERR);
    if (listen(listen_sock_tcp, SOMAXCONN) < 0) error_exit("TCP Listen failed", LOG_ERR);
    log_message(LOG_INFO, "TCP server listening on port %d.", SERVER_TCP_PORT);

    discovery_sock_udp = socket(AF_INET, SOCK_DGRAM, 0);
    if (discovery_sock_udp < 0) error_exit("UDP discovery socket failed", LOG_ERR);
    setsockopt(discovery_sock_udp, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    memset(&server_addr_udp, 0, sizeof(server_addr_udp));
    server_addr_udp.sin_family = AF_INET;
    server_addr_udp.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr_udp.sin_port = htons(DISCOVERY_UDP_PORT);
    if (bind(discovery_sock_udp, (struct sockaddr *)&server_addr_udp, sizeof(server_addr_udp)) < 0) error_exit("UDP discovery Bind failed", LOG_ERR);

    struct ip_mreq group_discovery;
    group_discovery.imr_multiaddr.s_addr = inet_addr(MULTICAST_GROUP_DISCOVERY);
    group_discovery.imr_interface.s_addr = htonl(INADDR_ANY);
    if (setsockopt(discovery_sock_udp, IPPROTO_IP, IP_ADD_MEMBERSHIP, &group_discovery, sizeof(group_discovery)) < 0) {
        log_message(LOG_ERR, "Failed to join discovery multicast group: %m");
    } else {
        log_message(LOG_INFO, "UDP listening for discovery on multicast %s port %d.", MULTICAST_GROUP_DISCOVERY, DISCOVERY_UDP_PORT);
    }

    fd_set read_fds;
    char discovery_buffer[TLV_BUFFER_SIZE];

    while (!terminate_server)
    {
        FD_ZERO(&read_fds);
        FD_SET(listen_sock_tcp, &read_fds);
        FD_SET(discovery_sock_udp, &read_fds);
        int max_fd = (listen_sock_tcp > discovery_sock_udp) ? listen_sock_tcp : discovery_sock_udp;

        int activity = select(max_fd + 1, &read_fds, NULL, NULL, NULL);
        if (activity < 0 && errno != EINTR) error_exit("Select error", LOG_ERR);
        if (terminate_server) break;

        if (FD_ISSET(listen_sock_tcp, &read_fds))
        {
            int new_sock = accept(listen_sock_tcp, (struct sockaddr *)&client_addr, &client_addr_len);
            if (new_sock < 0)
            {
                if (errno != EINTR) log_message(LOG_WARNING, "TCP Accept failed: %m");
                continue;
            }
            pid_t pid = fork();
            if (pid < 0)
            {
                log_message(LOG_ERR, "Fork failed: %m");
                close(new_sock);
            }
            else if (pid == 0)
            {
                close(listen_sock_tcp);
                close(discovery_sock_udp);
                handle_client_connection(new_sock, client_addr);
            }
            else
            {
                close(new_sock);
                log_message(LOG_INFO, "New TCP connection, handled by child PID %d.", pid);
            }
        }

        if (FD_ISSET(discovery_sock_udp, &read_fds))
        {
            ssize_t len = recvfrom(discovery_sock_udp, discovery_buffer, sizeof(discovery_buffer), 0, (struct sockaddr *)&client_addr, &client_addr_len);
            if (len >= (ssize_t)sizeof(TLVHeader))
            {
                TLVHeader *ping_header = (TLVHeader *)discovery_buffer;
                if (ntohl(ping_header->type) == MSG_TYPE_DISCOVERY_PING)
                {
                    handle_discovery_request(discovery_sock_udp, client_addr);
                }
            }
        }
    }

    log_message(LOG_INFO, "Server shutting down.");
    close(listen_sock_tcp);
    close(discovery_sock_udp);
    closelog();
    return 0;
}