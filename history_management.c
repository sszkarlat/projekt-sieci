#include "history_management.h"
#include "utils.h"
#include <sys/stat.h>
#include <dirent.h>

void init_history_management()
{
    struct stat st = {0};
    if (stat(HISTORY_DIR, &st) == -1)
    {
        if (mkdir(HISTORY_DIR, 0700) == -1)
        {
            log_message(LOG_ERR, "Failed to create history directory '%s': %m", HISTORY_DIR);
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

static void get_history_filename(const char *user1, const char *user2, char *filename_out, size_t max_len)
{
    if (strcmp(user1, user2) < 0)
    {
        snprintf(filename_out, max_len, "%s/%s_%s.hist", HISTORY_DIR, user1, user2);
    }
    else
    {
        snprintf(filename_out, max_len, "%s/%s_%s.hist", HISTORY_DIR, user2, user1);
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

    char filename[2 * MAX_USERNAME_LEN + 30];
    get_history_filename(user_a, user_b, filename, sizeof(filename));

    FILE *fp = fopen(filename, "a");
    if (fp == NULL)
    {
        log_message(LOG_ERR, "Could not open history file '%s' for append: %m", filename);
        return -1;
    }

    if (flock(fileno(fp), LOCK_EX) == -1)
    {
        log_message(LOG_ERR, "flock (EX) on history file '%s' failed: %m", filename);
        fclose(fp);
        return -1;
    }

    if (fprintf(fp, "[%s] %s\n", sender, message_text) < 0)
    {
        log_message(LOG_ERR, "Failed to write to history file '%s': %m", filename);
    }

    fflush(fp);
    flock(fileno(fp), LOCK_UN);
    fclose(fp);
    log_message(LOG_DEBUG, "Message stored to history: %s", filename);
    return 0;
}

int retrieve_chat_history(const char *requesting_user, const char *other_user, int client_sockfd)
{
    char filename[2 * MAX_USERNAME_LEN + 30];
    get_history_filename(requesting_user, other_user, filename, sizeof(filename));

    FILE *fp = fopen(filename, "r");
    if (fp == NULL)
    {
        if (errno == ENOENT)
        {
            log_message(LOG_INFO, "No history file found: %s", filename);
            send_tlv(client_sockfd, MSG_TYPE_HISTORY_RESP_END, NULL, 0);
            return 0;
        }
        log_message(LOG_ERR, "Could not open history file '%s' for read: %m", filename);
        return -1;
    }

    if (flock(fileno(fp), LOCK_SH) == -1)
    {
        log_message(LOG_ERR, "flock (SH) on history file '%s' failed: %m", filename);
        fclose(fp);
        return -1;
    }

    char line_buffer[MAX_MSG_LEN + MAX_USERNAME_LEN + 5];
    MessagePayload history_chunk;

    while (fgets(line_buffer, sizeof(line_buffer), fp) != NULL)
    {
        line_buffer[strcspn(line_buffer, "\n")] = 0;
        memset(&history_chunk, 0, sizeof(MessagePayload));
        strncpy(history_chunk.message, line_buffer, MAX_MSG_LEN - 1);

        if (send_tlv(client_sockfd, MSG_TYPE_HISTORY_RESP_CHUNK, &history_chunk, sizeof(MessagePayload)) < 0)
        {
            log_message(LOG_WARNING, "Failed to send history chunk to socket %d: %m", client_sockfd);
            flock(fileno(fp), LOCK_UN);
            fclose(fp);
            return -1;
        }
    }

    if (ferror(fp))
    {
        log_message(LOG_ERR, "Error reading from history file '%s'", filename);
    }

    flock(fileno(fp), LOCK_UN);
    fclose(fp);

    if (send_tlv(client_sockfd, MSG_TYPE_HISTORY_RESP_END, NULL, 0) < 0)
    {
        log_message(LOG_WARNING, "Failed to send HISTORY_END to socket %d", client_sockfd);
        return -1;
    }

    log_message(LOG_DEBUG, "History sent for %s and %s to socket %d", requesting_user, other_user, client_sockfd);
    return 0;
}