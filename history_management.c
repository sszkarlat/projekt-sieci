#include "history_management.h"
#include "utils.h"
#include <sys/stat.h> // Dla mkdir
#include <dirent.h>   // Dla operacji na katalogach (jeśli potrzebne do listowania)

void init_history_management()
{
    struct stat st = {0};
    if (stat(HISTORY_DIR, &st) == -1)
    {
        if (mkdir(HISTORY_DIR, 0700) == -1)
        { // 0700 - uprawnienia tylko dla właściciela
            log_message(LOG_ERR, "Failed to create history directory '%s': %m", HISTORY_DIR);
            // Serwer może się zakończyć lub kontynuować bez historii
        }
        else
        {
            log_message(LOG_INFO, "History directory '%s' created.", HISTORY_DIR);
        }
    }
    else
    {
        log_message(LOG_INFO, "History management initialized, using directory: %s", HISTORY_DIR);
    }
}

// Funkcja pomocnicza do generowania nazwy pliku historii dla pary użytkowników
// (posortowane alfabetycznie, aby zawsze była ta sama nazwa dla danej pary)
static void get_history_filename(const char *user1, const char *user2, char *filename_out, size_t max_len)
{
    char u1_lower[MAX_USERNAME_LEN];
    char u2_lower[MAX_USERNAME_LEN];
    strncpy(u1_lower, user1, MAX_USERNAME_LEN - 1);
    u1_lower[MAX_USERNAME_LEN - 1] = '\0';
    strncpy(u2_lower, user2, MAX_USERNAME_LEN - 1);
    u2_lower[MAX_USERNAME_LEN - 1] = '\0';
    // Proste sortowanie alfabetyczne
    if (strcmp(u1_lower, u2_lower) < 0)
    {
        snprintf(filename_out, max_len, "%s/%s_%s.hist", HISTORY_DIR, u1_lower, u2_lower);
    }
    else
    {
        snprintf(filename_out, max_len, "%s/%s_%s.hist", HISTORY_DIR, u2_lower, u1_lower);
    }
}

int store_chat_message(const char *user_a, const char *user_b, const char *sender, const char *message_text)
{
    if (strlen(user_a) >= MAX_USERNAME_LEN || strlen(user_b) >= MAX_USERNAME_LEN ||
        strlen(sender) >= MAX_USERNAME_LEN || strlen(message_text) >= MAX_MSG_LEN)
    {
        log_message(LOG_WARNING, "Message or username too long for history storage.");
        return -1;
    }

    char filename[2 * MAX_USERNAME_LEN + 20]; // Trochę zapasu
    get_history_filename(user_a, user_b, filename, sizeof(filename));

    FILE *fp = fopen(filename, "a"); // Otwórz do dopisywania (tekstowego)
    if (fp == NULL)
    {
        log_message(LOG_ERR, "Could not open history file '%s' for append: %m", filename);
        return -1;
    }

    // Zablokuj plik do zapisu wyłącznego
    if (flock(fileno(fp), LOCK_EX) == -1)
    {
        log_message(LOG_ERR, "flock (EX) on history file '%s' failed: %m", filename);
        fclose(fp);
        return -1;
    }

    // Prosty format: [nadawca] wiadomosc\n
    // Można dodać timestamp
    if (fprintf(fp, "[%s] %s\n", sender, message_text) < 0)
    {
        log_message(LOG_ERR, "Failed to write to history file '%s': %m", filename);
        flock(fileno(fp), LOCK_UN);
        fclose(fp);
        return -1;
    }

    flock(fileno(fp), LOCK_UN);
    fclose(fp);
    log_message(LOG_DEBUG, "Message stored to history: %s", filename);
    return 0;
}

int retrieve_chat_history(const char *requesting_user, const char *other_user, int client_sockfd)
{
    char filename[2 * MAX_USERNAME_LEN + 20];
    get_history_filename(requesting_user, other_user, filename, sizeof(filename));

    FILE *fp = fopen(filename, "r"); // Otwórz do odczytu (tekstowego)
    if (fp == NULL)
    {
        if (errno == ENOENT)
        {
            log_message(LOG_INFO, "No history file found: %s", filename);
            // Wyślij informację do klienta, że historia jest pusta
            if (send_tlv(client_sockfd, MSG_TYPE_HISTORY_RESP_END, NULL, 0) < 0)
            {
                log_message(LOG_WARNING, "Failed to send HISTORY_END for empty history to socket %d", client_sockfd);
            }
            return 0; // To niekoniecznie błąd, po prostu brak historii
        }
        log_message(LOG_ERR, "Could not open history file '%s' for read: %m", filename);
        return -1;
    }

    // Zablokuj plik do odczytu współdzielonego
    if (flock(fileno(fp), LOCK_SH) == -1)
    {
        log_message(LOG_ERR, "flock (SH) on history file '%s' failed: %m", filename);
        fclose(fp);
        return -1;
    }

    char line_buffer[MAX_MSG_LEN + MAX_USERNAME_LEN + 5]; // Bufor na linię z pliku
    MessagePayload history_chunk;                         // Użyjemy tej struktury do wysłania linii
                                                          // (chociaż nie wszystkie pola będą potrzebne w tym przypadku)

    while (fgets(line_buffer, sizeof(line_buffer), fp) != NULL)
    {
        // Usuń znak nowej linii, jeśli jest
        line_buffer[strcspn(line_buffer, "\n")] = 0;

        memset(&history_chunk, 0, sizeof(MessagePayload));
        // W tym przypadku 'message' będzie zawierać całą linię z pliku
        strncpy(history_chunk.message, line_buffer, MAX_MSG_LEN - 1);

        if (send_tlv(client_sockfd, MSG_TYPE_HISTORY_RESP_CHUNK, &history_chunk, sizeof(MessagePayload)) < 0)
        {
            log_message(LOG_WARNING, "Failed to send history chunk to socket %d: %m", client_sockfd);
            flock(fileno(fp), LOCK_UN);
            fclose(fp);
            return -1; // Błąd wysyłania, przerwij
        }
    }

    if (ferror(fp))
    {
        log_message(LOG_ERR, "Error reading from history file '%s'", filename);
    }

    flock(fileno(fp), LOCK_UN);
    fclose(fp);

    // Wyślij znacznik końca historii
    if (send_tlv(client_sockfd, MSG_TYPE_HISTORY_RESP_END, NULL, 0) < 0)
    {
        log_message(LOG_WARNING, "Failed to send HISTORY_END to socket %d", client_sockfd);
        return -1;
    }

    log_message(LOG_DEBUG, "History sent for %s and %s to socket %d", requesting_user, other_user, client_sockfd);
    return 0;
}