#include "common.h"
#include "utils.h"
#include "user_management.h"
#include "history_management.h"
#include <sys/stat.h> // Dla umask
#include <string.h>   // Dla strncmp, strchr, strncpy

// Zmienna do sygnalizowania zakończenia serwera
volatile sig_atomic_t terminate_server = 0;

// Prototypy funkcji (deklaracje forward)
// Dostosowane do IPv4 dla uproszczenia (sockaddr_in zamiast sockaddr_in6)
void handle_discovery_request(int udp_sock, struct sockaddr_in client_addr);
void handle_client_connection(int client_sock, struct sockaddr_in client_addr);
static int send_multicast_chat_message(const MessagePayload* payload);


// Handler dla sygnału SIGCHLD (zakończenie procesu potomnego)
void sigchld_handler(int sig) {
    int status;
    // Użyj waitpid w pętli, aby zebrać wszystkie zakończone dzieci
    // WNOHANG oznacza, że waitpid nie będzie blokować, jeśli nie ma zakończonych dzieci
    while (waitpid(-1, &status, WNOHANG) > 0) {
        if (WIFEXITED(status)) {
            log_message(LOG_INFO, "Child process %d exited with status %d.", (int)getpid(), WEXITSTATUS(status));
        } else if (WIFSIGNALED(status)) {
            log_message(LOG_WARNING, "Child process %d terminated by signal %d.", (int)getpid(), WTERMSIG(status));
        }
    }
}

// Handler dla sygnału SIGINT (Ctrl+C)
void sigint_handler(int sig) {
    log_message(LOG_INFO, "SIGINT received, setting termination flag.");
    terminate_server = 1; // Ustaw flagę, aby główna pętla mogła się zakończyć
}

// Funkcja do daemonizacji procesu
void daemonize() {
    pid_t pid;

    // Krok 1: Fork i zakończenie procesu rodzicielskiego
    pid = fork();
    if (pid < 0) {
        error_exit("daemonize: fork 1 failed", LOG_ERR); // Użycie error_exit
    }
    if (pid > 0) {
        // Proces rodzicielski kończy działanie
        exit(EXIT_SUCCESS);
    }

    // Krok 2: Utworzenie nowej sesji i grupy procesów
    if (setsid() < 0) {
        error_exit("daemonize: setsid failed", LOG_ERR); // Użycie error_exit
    }

    // Krok 3: Ignorowanie sygnałów SIGHUP i SIGCHLD
    // SIGCHLD zostanie ponownie ustawiony w main() przez proces demona
    signal(SIGCHLD, SIG_IGN); 
    signal(SIGHUP, SIG_IGN);

    // Krok 4: Drugi fork, aby nie być liderem sesji
    pid = fork();
    if (pid < 0) {
        error_exit("daemonize: fork 2 failed", LOG_ERR); // Użycie error_exit
    }
    if (pid > 0) {
        // Proces rodzicielski (teraz już nie lider sesji) kończy działanie
        exit(EXIT_SUCCESS);
    }

    // Krok 5: Ustawienie maski tworzenia plików (umask)
    umask(0); // Daje plikom pełne uprawnienia (0777), które potem są redukowane przez chmod
              // lub w zależności od potrzeb, można ustawić np. umask(0022);

    // Krok 6: Zmiana katalogu roboczego
    if (chdir("/") < 0) {
        error_exit("daemonize: chdir failed", LOG_ERR); // Użycie error_exit
    }

    // Krok 7: Zamknięcie standardowych deskryptorów plików
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    
    // Krok 8: Przekierowanie standardowych deskryptorów do /dev/null
    // Otwórz /dev/null i przekieruj na deskryptory 0, 1, 2
    open("/dev/null", O_RDWR);   // stdin (deskryptor 0)
    dup(0);                      // stdout (kopia deskryptora 0, staje się deskryptorem 1)
    dup(0);                      // stderr (kopia deskryptora 0, staje się deskryptorem 2)
}


// Funkcja do wysyłania wiadomości multicast czatu z procesów dziecka
// Payload to struktura MessagePayload
static int send_multicast_chat_message(const MessagePayload* payload) {
    int child_multicast_send_sock;
    struct sockaddr_in multicast_addr; // Używamy IPv4

    // 1. Utwórz gniazdo UDP dla IPv4
    child_multicast_send_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (child_multicast_send_sock < 0) {
        log_message(LOG_ERR, "send_multicast_chat_message: Failed to create child multicast send socket: %m");
        return -1;
    }

    // 2. Ustaw TTL (Time To Live) dla multicast (IP_MULTICAST_TTL)
    // Domyślnie 1, co oznacza, że pakiet nie opuści sieci lokalnej.
    // Wyższa wartość pozwala routerom na przekazywanie pakietów.
    int ttl = 1; // 1 = tylko sieć lokalna (LAN)
    if (setsockopt(child_multicast_send_sock, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)) < 0) {
        log_message(LOG_WARNING, "send_multicast_chat_message: Failed to set IP_MULTICAST_TTL on child socket: %m");
        close(child_multicast_send_sock);
        return -1;
    }
    
    // 3. Skonfiguruj adres docelowy multicast
    memset(&multicast_addr, 0, sizeof(multicast_addr));
    multicast_addr.sin_family = AF_INET;
    multicast_addr.sin_port = htons(CHAT_UDP_PORT);
    
    // Konwertuj tekstowy adres multicast na binarny dla IPv4
    if (inet_pton(AF_INET, MULTICAST_GROUP_CHAT, &multicast_addr.sin_addr) <= 0) {
        log_message(LOG_ERR, "send_multicast_chat_message: Invalid multicast chat address: %s", MULTICAST_GROUP_CHAT);
        close(child_multicast_send_sock);
        return -1;
    }

    // 4. Wyślij wiadomość TLV (REALTIME_CHAT)
    if (send_tlv(child_multicast_send_sock, MSG_TYPE_REALTIME_CHAT, payload, sizeof(MessagePayload)) < 0) {
        log_message(LOG_WARNING, "send_multicast_chat_message: Failed to send multicast chat message from child: %m");
        close(child_multicast_send_sock);
        return -1;
    }
    
    // 5. Zamknij gniazdo po wysłaniu
    close(child_multicast_send_sock);
    return 0; // Sukces
}


// Funkcja obsługująca połączenie z pojedynczym klientem (wykonywana przez proces potomny)
void handle_client_connection(int client_sock, struct sockaddr_in client_addr) { // Zmieniono na IPv4
    char client_ip_str[INET_ADDRSTRLEN];
    // Konwertuj adres IP klienta na postać tekstową dla logów
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip_str, INET_ADDRSTRLEN);
    log_message(LOG_INFO, "Handling client %s:%d (child PID %d)", client_ip_str, ntohs(client_addr.sin_port), getpid());

    TLVHeader header; // Nagłówek wiadomości TLV
    char value_buffer[TLV_BUFFER_SIZE]; // Bufor na dane wiadomości TLV
    
    // Inicjalizacja modułów zarządzania danymi dla tego procesu potomnego
    init_user_management();
    init_history_management();

    // Główna pętla obsługi klienta
    while(1) {
        // Odbieranie wiadomości TLV od klienta
        // receive_tlv zwraca -1 w przypadku błędu lub zamknięcia połączenia
        if (receive_tlv(client_sock, &header, value_buffer, sizeof(value_buffer)) < 0) {
            log_message(LOG_INFO, "Client %s:%d disconnected or TLV error, terminating child.", client_ip_str, ntohs(client_addr.sin_port));
            break; // Wyjdź z pętli, aby zamknąć socket i zakończyć proces potomny
        }
        log_message(LOG_DEBUG, "Received TLV type: %d, length: %d from %s", header.type, header.length, client_ip_str);

        // Obsługa różnych typów wiadomości od klienta
        switch(header.type) {
            case MSG_TYPE_REGISTER_REQ: {
                AuthPayload *payload = (AuthPayload*)value_buffer;
                ResponsePayload resp;
                memset(&resp, 0, sizeof(resp)); // Wyczyść strukturę odpowiedzi

                // Próba rejestracji nowego użytkownika
                if (register_new_user(payload->username, payload->password) == 0) {
                    resp.success = 1;
                    strncpy(resp.message, "Registration successful!", sizeof(resp.message) - 1);
                } else {
                    resp.success = 0;
                    strncpy(resp.message, "Registration failed (user exists or file error).", sizeof(resp.message) - 1);
                }
                // Wyślij odpowiedź do klienta
                send_tlv(client_sock, MSG_TYPE_REGISTER_RESP, &resp, sizeof(resp));
                break;
            }
            case MSG_TYPE_LOGIN_REQ: {
                AuthPayload *payload = (AuthPayload*)value_buffer;
                ResponsePayload resp;
                memset(&resp, 0, sizeof(resp));

                // Weryfikacja danych logowania
                if (verify_user_credentials(payload->username, payload->password) == 0) {
                    resp.success = 1;
                    strncpy(resp.message, "Login successful!", sizeof(resp.message) - 1);
                    // W tym miejscu w prawdziwej aplikacji zapisałbyś, że użytkownik jest zalogowany
                    // i powiązałbyś jego sesję z tym procesem.
                } else {
                    resp.success = 0;
                    strncpy(resp.message, "Login failed (bad credentials or file error).", sizeof(resp.message) - 1);
                }
                // Wyślij odpowiedź do klienta
                send_tlv(client_sock, MSG_TYPE_LOGIN_RESP, &resp, sizeof(resp));
                break;
            }
            case MSG_TYPE_SEND_MSG_REQ: {
                MessagePayload *payload = (MessagePayload*)value_buffer;
                log_message(LOG_INFO, "Client %s:%d received SEND_MSG_REQ from %s to %s: %s", 
                            client_ip_str, ntohs(client_addr.sin_port), payload->sender, payload->recipient, payload->message);
                
                // 1. Zapisz wiadomość do historii czatu
                store_chat_message(payload->sender, payload->recipient, payload->sender, payload->message);

                // 2. ROZGŁOŚ WIADOMOŚĆ NA MULTICAST DLA CZATU W CZASIE RZECZYWISTYM
                // Ta wiadomość będzie odebrana przez wszystkich klientów nasłuchujących na odpowiedniej grupie multicast
                if (send_multicast_chat_message(payload) == 0) {
                    log_message(LOG_DEBUG, "Message from %s multicast broadcasted.", payload->sender);
                } else {
                    log_message(LOG_WARNING, "Failed to broadcast message from %s.", payload->sender);
                }

                // 3. Wyślij potwierdzenie (ACK) do nadawcy (klienta)
                ResponsePayload ack_resp;
                memset(&ack_resp, 0, sizeof(ack_resp));
                ack_resp.success = 1;
                strncpy(ack_resp.message, "Message sent and broadcasted.", sizeof(ack_resp.message)-1);
                send_tlv(client_sock, MSG_TYPE_ERROR_RESP, &ack_resp, sizeof(ack_resp)); // Użyłem ERROR_RESP tymczasowo jako ACK
                break;
            }
            case MSG_TYPE_GET_HISTORY_REQ: {
                AuthPayload *req_payload = (AuthPayload*)value_buffer; // Używam AuthPayload jako prostego sposobu przekazania username
                log_message(LOG_INFO, "Client %s:%d requested history for %s with %s", 
                            client_ip_str, ntohs(client_addr.sin_port), req_payload->username, req_payload->password); // drugie pole jako 'other_user'
                // Pobierz i wyślij historię do klienta
                retrieve_chat_history(req_payload->username, req_payload->password, client_sock);
                break;
            }
            case MSG_TYPE_LOGOUT_REQ: {
                log_message(LOG_INFO, "Client %s:%d requested logout.", client_ip_str, ntohs(client_addr.sin_port));
                break; // Wyjdź z pętli, co spowoduje zamknięcie połączenia
            }
            default: {
                ResponsePayload err_resp;
                memset(&err_resp, 0, sizeof(err_resp));
                err_resp.success = 0;
                strncpy(err_resp.message, "Unknown TLV type.", sizeof(err_resp.message) - 1);
                send_tlv(client_sock, MSG_TYPE_ERROR_RESP, &err_resp, sizeof(err_resp));
                log_message(LOG_WARNING, "Client %s:%d sent unknown TLV type: %d", client_ip_str, ntohs(client_addr.sin_port), header.type);
                break;
            }
        }
    }

    // Zamknij gniazdo klienta i zakończ proces potomny
    close(client_sock);
    log_message(LOG_INFO, "Closed connection with %s:%d (child PID %d)", client_ip_str, ntohs(client_addr.sin_port), getpid());
    exit(0);
}


// Główna funkcja serwera
int main() {
    // 1. Daemonizacja procesu
    daemonize();

    // 2. Otworzenie logów systemowych (syslog)
    openlog("KomunikatorSerwer", LOG_PID | LOG_CONS, LOG_DAEMON);
    log_message(LOG_INFO, "Server starting...");

    // 3. Inicjalizacja modułów zarządzania danymi (plikami użytkowników i historii)
    init_user_management();
    init_history_management();

    // 4. Konfiguracja handlerów sygnałów
    struct sigaction sa_chld, sa_int;
    sa_chld.sa_handler = sigchld_handler; // Handler dla SIGCHLD
    sigemptyset(&sa_chld.sa_mask);
    sa_chld.sa_flags = SA_RESTART; // Restartuj przerwane wywołania systemowe
    if (sigaction(SIGCHLD, &sa_chld, 0) == -1) {
        error_exit("sigaction SIGCHLD failed", LOG_ERR);
    }

    sa_int.sa_handler = sigint_handler; // Handler dla SIGINT
    sigemptyset(&sa_int.sa_mask);
    sa_int.sa_flags = 0;
    if (sigaction(SIGINT, &sa_int, 0) == -1) {
        error_exit("sigaction SIGINT failed", LOG_ERR);
    }
    // Można dodać też SIGHUP (dla rekonfiguracji) i SIGTERM (alternatywny sygnał zakończenia)

    int listen_sock_tcp;    // Gniazdo TCP do nasłuchu
    int discovery_sock_udp; // Gniazdo UDP do discovery multicast

    // Struktury adresowe dla serwera i klienta (IPv4)
    struct sockaddr_in server_addr_tcp, server_addr_udp, client_addr; 
    socklen_t client_addr_len = sizeof(client_addr); // Długość struktury adresu klienta
    int optval = 1; // Wartość dla opcji gniazda (np. SO_REUSEADDR)

    // 5. Konfiguracja i wiązanie gniazda TCP do nasłuchu połączeń (IPv4)
    listen_sock_tcp = socket(AF_INET, SOCK_STREAM, 0); // AF_INET dla IPv4, SOCK_STREAM dla TCP
    if (listen_sock_tcp < 0) error_exit("TCP socket failed", LOG_ERR);
    
    // Ustawienie SO_REUSEADDR, aby umożliwić szybki restart serwera na tym samym porcie
    setsockopt(listen_sock_tcp, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    
    memset(&server_addr_tcp, 0, sizeof(server_addr_tcp)); // Wyczyść strukturę adresu
    server_addr_tcp.sin_family = AF_INET;
    server_addr_tcp.sin_addr.s_addr = htonl(INADDR_ANY); // Nasłuchuj na wszystkich dostępnych interfejsach IPv4
    server_addr_tcp.sin_port = htons(SERVER_TCP_PORT); // Port TCP serwera

    if (bind(listen_sock_tcp, (struct sockaddr*)&server_addr_tcp, sizeof(server_addr_tcp)) < 0) {
        error_exit("TCP Bind failed", LOG_ERR);
    }
    // Rozpocznij nasłuchiwanie na połączenia, SOMAXCONN to maksymalna długość kolejki oczekujących połączeń
    if (listen(listen_sock_tcp, SOMAXCONN) < 0) {
        error_exit("TCP Listen failed", LOG_ERR);
    }
    log_message(LOG_INFO, "TCP server listening on port %d (IPv4).", SERVER_TCP_PORT);

    // 6. Konfiguracja i wiązanie gniazda UDP do discovery multicast (IPv4)
    discovery_sock_udp = socket(AF_INET, SOCK_DGRAM, 0); // AF_INET dla IPv4, SOCK_DGRAM dla UDP
    if (discovery_sock_udp < 0) error_exit("UDP discovery socket failed", LOG_ERR);
    
    // Ustawienie SO_REUSEADDR dla multicast jest kluczowe (aby wiele procesów mogło nasłuchiwać)
    setsockopt(discovery_sock_udp, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    
    memset(&server_addr_udp, 0, sizeof(server_addr_udp));
    server_addr_udp.sin_family = AF_INET;
    server_addr_udp.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr_udp.sin_port = htons(DISCOVERY_UDP_PORT); // Port discovery UDP

    if (bind(discovery_sock_udp, (struct sockaddr*)&server_addr_udp, sizeof(server_addr_udp)) < 0) {
        error_exit("UDP discovery Bind failed", LOG_ERR);
    }

    // Dołączenie do grupy multicast discovery (IPv4)
    struct ip_mreq group_discovery;
    group_discovery.imr_multiaddr.s_addr = inet_addr(MULTICAST_GROUP_DISCOVERY); // Adres grupy multicast discovery
    group_discovery.imr_interface.s_addr = htonl(INADDR_ANY); // Domyślny interfejs sieciowy
    if (setsockopt(discovery_sock_udp, IPPROTO_IP, IP_ADD_MEMBERSHIP, &group_discovery, sizeof(group_discovery)) < 0) {
        log_message(LOG_ERR, "Failed to join discovery multicast group: %m");
        // Jeśli ten krok się nie powiedzie, discovery multicast nie będzie działać, ale serwer może działać dalej
    } else {
        log_message(LOG_INFO, "UDP server listening for discovery on multicast %s port %d.", MULTICAST_GROUP_DISCOVERY, DISCOVERY_UDP_PORT);
    }

    // Zmienne i bufor dla pętli select()
    fd_set read_fds; // Zbiór deskryptorów do monitorowania
    int max_fd;       // Największy deskryptor + 1
    char discovery_buffer[TLV_BUFFER_SIZE]; // Bufor na pakiety discovery

    // 7. Główna pętla serwera - monitorowanie gniazd za pomocą select()
    while (!terminate_server) { // Pętla działa, dopóki flaga terminate_server nie zostanie ustawiona (np. przez SIGINT)
        FD_ZERO(&read_fds); // Wyczyść zbiór deskryptorów
        FD_SET(listen_sock_tcp, &read_fds);     // Dodaj gniazdo TCP do zbioru
        FD_SET(discovery_sock_udp, &read_fds); // Dodaj gniazdo UDP discovery do zbioru
        
        // Ustal największy deskryptor
        max_fd = (listen_sock_tcp > discovery_sock_udp) ? listen_sock_tcp : discovery_sock_udp;

        // Wywołanie select() - blokuje, dopóki nie ma aktywności na którymś z gniazd lub nie wystąpi błąd/sygnał
        int activity = select(max_fd + 1, &read_fds, NULL, NULL, NULL);

        if (activity < 0) {
            if (errno == EINTR) { // select() przerwany przez sygnał (np. SIGCHLD)
                continue; // Ponów pętlę
            }
            error_exit("Select error", LOG_ERR); // Inny błąd select()
        }
        if (terminate_server) break; // Sprawdź flagę po select()

        // Obsługa aktywności na gnieździe TCP (nowe połączenie)
        if (FD_ISSET(listen_sock_tcp, &read_fds)) {
            int new_sock = accept(listen_sock_tcp, (struct sockaddr*)&client_addr, &client_addr_len);
            if (new_sock < 0) {
                if (errno == EINTR && terminate_server) break; // Obsługa przerwania accept przez sygnał
                log_message(LOG_WARNING, "TCP Accept failed: %m");
                continue;
            }
            // Utwórz nowy proces potomny do obsługi klienta
            pid_t pid = fork();
            if (pid < 0) {
                log_message(LOG_ERR, "Fork failed: %m");
                close(new_sock); // Zamknij gniazdo, jeśli fork się nie powiódł
            } else if (pid == 0) { // Proces dziecka
                close(listen_sock_tcp);    // Dziecko nie potrzebuje gniazda nasłuchującego
                close(discovery_sock_udp); // Dziecko nie potrzebuje gniazda discovery
                handle_client_connection(new_sock, client_addr); // Obsługuj klienta
                // exit(0) jest wywoływane w handle_client_connection()
            } else { // Proces rodzica
                close(new_sock); // Rodzic zamyka deskryptor połączonego gniazda, dziecko ma swoją kopię
                char client_ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &client_addr.sin_addr, client_ip_str, INET_ADDRSTRLEN);
                log_message(LOG_INFO, "New TCP connection from %s:%d, handled by child PID %d.",
                       client_ip_str, ntohs(client_addr.sin_port), pid);
            }
        }

        // Obsługa aktywności na gnieździe UDP (pakiet discovery)
        if (FD_ISSET(discovery_sock_udp, &read_fds)) {
            ssize_t len = recvfrom(discovery_sock_udp, discovery_buffer, sizeof(discovery_buffer) -1 , 0,
                                   (struct sockaddr*)&client_addr, &client_addr_len);
            if (len > 0) {
                TLVHeader *ping_header = (TLVHeader*) discovery_buffer;
                // Sprawdź, czy to jest poprawny PING (w formacie TLV)
                if (len >= sizeof(TLVHeader) && ntohl(ping_header->type) == MSG_TYPE_DISCOVERY_PING) {
                    handle_discovery_request(discovery_sock_udp, client_addr);
                } else {
                    char client_ip_str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip_str, INET_ADDRSTRLEN);
                    log_message(LOG_DEBUG, "Received unknown UDP packet from %s:%d (len %zd).", client_ip_str, ntohs(client_addr.sin_port), len);
                }
            } else if (len < 0 && errno != EINTR) {
                 log_message(LOG_WARNING, "UDP recvfrom discovery error: %m");
            }
        }
    }

    // 8. Bezpieczne zamknięcie serwera
    log_message(LOG_INFO, "Server shutting down.");
    close(listen_sock_tcp);
    close(discovery_sock_udp);
    
    // Opcjonalnie: Opuszczenie grup multicast (zasoby są i tak zwalniane przy zamknięciu gniazd)
    setsockopt(discovery_sock_udp, IPPROTO_IP, IP_DROP_MEMBERSHIP, &group_discovery, sizeof(group_discovery));

    closelog(); // Zamknij sesję logowania do syslog
    return 0;
}

// Funkcja pomocnicza do obsługi żądań discovery (UDP)
void handle_discovery_request(int udp_sock, struct sockaddr_in client_addr) { // Zmieniono na IPv4
    char client_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip_str, INET_ADDRSTRLEN);
    log_message(LOG_DEBUG, "Received discovery ping from %s:%d", client_ip_str, ntohs(client_addr.sin_port));
    
    // Payload PONGa to port TCP serwera (w kolejności sieciowej)
    uint16_t server_port_payload = htons(SERVER_TCP_PORT); 

    // Przygotowanie wiadomości PONG w formacie TLV
    TLVHeader pong_header;
    pong_header.type = htonl(MSG_TYPE_DISCOVERY_PONG);
    pong_header.length = htons(sizeof(server_port_payload));

    char pong_buffer[sizeof(TLVHeader) + sizeof(server_port_payload)];
    memcpy(pong_buffer, &pong_header, sizeof(TLVHeader));
    memcpy(pong_buffer + sizeof(TLVHeader), &server_port_payload, sizeof(server_port_payload));

    // Wysłanie odpowiedzi PONG
    if (sendto(udp_sock, pong_buffer, sizeof(pong_buffer), 0,
               (struct sockaddr*)&client_addr, sizeof(client_addr)) < 0) {
        log_message(LOG_WARNING, "Failed to send discovery pong to %s: %m", client_ip_str);
    } else {
        log_message(LOG_DEBUG, "Sent discovery pong to %s", client_ip_str);
    }
}