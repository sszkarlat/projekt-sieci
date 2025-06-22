#include "user_management.h"
#include "utils.h"

void init_user_management()
{
    FILE *fp = fopen(USERS_FILE, "ab");
    if (fp == NULL)
    {
        log_message(LOG_ERR, "Could not open/create users file '%s': %m", USERS_FILE);
    }
    else
    {
        fclose(fp);
        log_message(LOG_INFO, "User management initialized, using file: %s", USERS_FILE);
    }
}

static void very_simple_hash(const char *input, char *output, size_t out_len)
{
    strncpy(output, input, out_len - 1);
    output[out_len - 1] = '\0';
}

int register_new_user(const char *username, const char *password)
{
    if (strlen(username) >= MAX_USERNAME_LEN || strlen(password) >= MAX_PASSWORD_LEN)
    {
        log_message(LOG_WARNING, "Username or password too long for registration: %s", username);
        return -1;
    }

    FILE *fp = fopen(USERS_FILE, "r+b");
    if (fp == NULL)
    {
        if (errno == ENOENT)
        {
            fp = fopen(USERS_FILE, "w+b");
            if (fp == NULL)
            {
                log_message(LOG_ERR, "Could not create users file '%s': %m", USERS_FILE);
                return -2;
            }
        }
        else
        {
            log_message(LOG_ERR, "Could not open users file '%s': %m", USERS_FILE);
            return -2;
        }
    }

    if (flock(fileno(fp), LOCK_EX) == -1)
    {
        log_message(LOG_ERR, "flock (EX) on users file failed: %m");
        fclose(fp);
        return -2;
    }

    UserRecord record;
    int user_exists = 0;
    rewind(fp);
    while (fread(&record, sizeof(UserRecord), 1, fp) == 1)
    {
        if (strncmp(record.username, username, MAX_USERNAME_LEN) == 0)
        {
            user_exists = 1;
            break;
        }
    }

    if (user_exists)
    {
        log_message(LOG_INFO, "Registration failed: User '%s' already exists.", username);
        flock(fileno(fp), LOCK_UN);
        fclose(fp);
        return -1;
    }

    fseek(fp, 0, SEEK_END);
    memset(&record, 0, sizeof(UserRecord));
    strncpy(record.username, username, MAX_USERNAME_LEN - 1);
    very_simple_hash(password, record.password_hash, MAX_PASSWORD_LEN);

    if (fwrite(&record, sizeof(UserRecord), 1, fp) != 1)
    {
        log_message(LOG_ERR, "Failed to write new user record for '%s': %m", username);
        flock(fileno(fp), LOCK_UN);
        fclose(fp);
        return -2;
    }

    flock(fileno(fp), LOCK_UN);
    fclose(fp);
    log_message(LOG_INFO, "User '%s' registered successfully.", username);
    return 0;
}

int verify_user_credentials(const char *username, const char *password)
{
    FILE *fp = fopen(USERS_FILE, "rb");
    if (fp == NULL)
    {
        log_message(LOG_WARNING, "Could not open users file '%s' for verification: %m", USERS_FILE);
        return -2;
    }

    if (flock(fileno(fp), LOCK_SH) == -1)
    {
        log_message(LOG_ERR, "flock (SH) on users file failed for verification: %m");
        fclose(fp);
        return -2;
    }

    UserRecord record;
    char input_password_hash[MAX_PASSWORD_LEN];
    very_simple_hash(password, input_password_hash, MAX_PASSWORD_LEN);

    int found = 0;
    while (fread(&record, sizeof(UserRecord), 1, fp) == 1)
    {
        if (strncmp(record.username, username, MAX_USERNAME_LEN) == 0)
        {
            if (strncmp(record.password_hash, input_password_hash, MAX_PASSWORD_LEN) == 0)
            {
                found = 1;
            }
            break;
        }
    }

    flock(fileno(fp), LOCK_UN);
    fclose(fp);

    if (found)
    {
        log_message(LOG_INFO, "User '%s' authenticated successfully.", username);
        return 0;
    }
    else
    {
        log_message(LOG_WARNING, "Authentication failed for user '%s'.", username);
        return -1;
    }
}