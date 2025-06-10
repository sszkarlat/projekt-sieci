#include "user_management.h"
#include "utils.h" // Dla log_message

// UWAGA: TO JEST BARDZO UPROSZCZONA WERSJA BEZ PRAWDZIWEGO HASHOWANIA HASEŁ I SOLIDNEGO ZARZĄDZANIA PLIKIEM.
// W PRAWDZIWEJ APLIKACJI NALEŻY UŻYĆ BIBLIOTEKI DO HASHOWANIA (np. libsodium, OpenSSL)
// I ROZWAŻYĆ LEPSZY FORMAT PLIKU LUB BAZĘ DANYCH.

void init_user_management()
{
    FILE *fp = fopen(USERS_FILE, "ab"); // Utwórz, jeśli nie istnieje, otwórz do dopisywania binarnego
    if (fp == NULL)
    {
        log_message(LOG_ERR, "Could not open/create users file '%s': %m", USERS_FILE);
        // W zależności od wymagań, serwer może się tu zakończyć lub kontynuować
    }
    else
    {
        fclose(fp);
        log_message(LOG_INFO, "User management initialized, using file: %s", USERS_FILE);
    }
}

// Prosty "hash" - w rzeczywistości tylko kopiuje. ZMIEŃ TO!
static void very_simple_hash(const char *input, char *output, size_t out_len)
{
    strncpy(output, input, out_len - 1);
    output[out_len - 1] = '\0';
    // W prawdziwej implementacji: użyj np. argon2, scrypt, bcrypt
}

int register_new_user(const char *username, const char *password)
{
    if (strlen(username) >= MAX_USERNAME_LEN || strlen(password) >= MAX_PASSWORD_LEN)
    {
        log_message(LOG_WARNING, "Username or password too long for registration: %s", username);
        return -1; // Błąd danych wejściowych
    }

    FILE *fp;
    UserRecord record;
    int user_exists = 0;

    // Otwórz plik użytkowników do odczytu binarnego
    fp = fopen(USERS_FILE, "rb");
    if (fp != NULL)
    {
        // Zablokuj plik do odczytu współdzielonego
        if (flock(fileno(fp), LOCK_SH) == -1)
        {
            log_message(LOG_ERR, "flock (SH) on users file failed for read: %m");
            fclose(fp);
            return -2;
        }
        while (fread(&record, sizeof(UserRecord), 1, fp) == 1)
        {
            if (strncmp(record.username, username, MAX_USERNAME_LEN) == 0)
            {
                user_exists = 1;
                break;
            }
        }
        flock(fileno(fp), LOCK_UN); // Odblokuj
        fclose(fp);
    }
    else
    {
        // Plik może jeszcze nie istnieć, to ok przy pierwszym użytkowniku
        if (errno != ENOENT)
        {
            log_message(LOG_ERR, "Error opening users file for read: %m");
            return -2;
        }
    }

    if (user_exists)
    {
        log_message(LOG_INFO, "Registration failed: User '%s' already exists.", username);
        return -1; // Użytkownik już istnieje
    }

    // Otwórz plik do dopisywania binarnego
    fp = fopen(USERS_FILE, "ab");
    if (fp == NULL)
    {
        log_message(LOG_ERR, "Could not open users file '%s' for append: %m", USERS_FILE);
        return -2; // Błąd pliku
    }

    // Zablokuj plik do zapisu wyłącznego
    if (flock(fileno(fp), LOCK_EX) == -1)
    {
        log_message(LOG_ERR, "flock (EX) on users file failed for append: %m");
        fclose(fp);
        return -2;
    }

    memset(&record, 0, sizeof(UserRecord));
    strncpy(record.username, username, MAX_USERNAME_LEN - 1);
    very_simple_hash(password, record.password_hash, MAX_PASSWORD_LEN); // ZASTOSUJ PRAWDZIWE HASHOWANIE!

    if (fwrite(&record, sizeof(UserRecord), 1, fp) != 1)
    {
        log_message(LOG_ERR, "Failed to write new user record for '%s': %m", username);
        flock(fileno(fp), LOCK_UN);
        fclose(fp);
        return -2; // Błąd zapisu
    }

    flock(fileno(fp), LOCK_UN); // Odblokuj
    fclose(fp);
    log_message(LOG_INFO, "User '%s' registered successfully.", username);
    return 0; // Sukces
}

int verify_user_credentials(const char *username, const char *password)
{
    FILE *fp;
    UserRecord record;
    char input_password_hash[MAX_PASSWORD_LEN];

    fp = fopen(USERS_FILE, "rb");
    if (fp == NULL)
    {
        log_message(LOG_WARNING, "Could not open users file '%s' for verification: %m", USERS_FILE);
        return -2; // Błąd pliku (lub brak użytkowników)
    }

    // Zablokuj plik do odczytu współdzielonego
    if (flock(fileno(fp), LOCK_SH) == -1)
    {
        log_message(LOG_ERR, "flock (SH) on users file failed for verification: %m");
        fclose(fp);
        return -2;
    }

    very_simple_hash(password, input_password_hash, MAX_PASSWORD_LEN); // ZASTOSUJ TO SAMO "HASHOWANIE"

    int found = 0;
    while (fread(&record, sizeof(UserRecord), 1, fp) == 1)
    {
        if (strncmp(record.username, username, MAX_USERNAME_LEN) == 0)
        {
            if (strncmp(record.password_hash, input_password_hash, MAX_PASSWORD_LEN) == 0)
            {
                found = 1;
            }
            break; // Znaleziono użytkownika, nie trzeba dalej szukać
        }
    }

    flock(fileno(fp), LOCK_UN); // Odblokuj
    fclose(fp);

    if (found)
    {
        log_message(LOG_INFO, "User '%s' authenticated successfully.", username);
        return 0; // Sukces
    }
    else
    {
        log_message(LOG_INFO, "Authentication failed for user '%s'.", username);
        return -1; // Zły użytkownik lub hasło
    }
}