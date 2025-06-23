#include "user_management.h"
#include "utils.h"
#include <openssl/sha.h> // Dołączenie biblioteki do hashowania

// Długość hasha SHA256 w formie heksadecymalnej (32 bajty * 2 znaki hex) + null
#define SHA256_HEX_LEN (SHA256_DIGEST_LENGTH * 2 + 1)

void init_user_management()
{
    FILE *fp = fopen(USERS_FILE, "a"); // Utwórz plik tekstowy, jeśli nie istnieje
    if (fp == NULL)
    {
        log_message(LOG_ERR, "Could not open/create users file '%s': %m", USERS_FILE);
    }
    else
    {
        fclose(fp);
        log_message(LOG_INFO, "User management initialized, using text file: %s", USERS_FILE);
    }
}

// Funkcja pomocnicza do hashowania hasła i konwersji na string hex
static void hash_password_sha256(const char *password, char *hash_hex_output)
{
    unsigned char hash_binary[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)password, strlen(password), hash_binary);

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf(hash_hex_output + (i * 2), "%02x", hash_binary[i]);
    }
    hash_hex_output[SHA256_DIGEST_LENGTH * 2] = '\0';
}

int register_new_user(const char *username, const char *password)
{
    if (strlen(username) >= MAX_USERNAME_LEN || strlen(password) >= MAX_PASSWORD_LEN)
    {
        log_message(LOG_WARNING, "Username or password too long for registration: %s", username);
        return -1;
    }

    // Otwieramy plik w trybie "r+", aby czytać i pisać. Jeśli nie istnieje, fopen zwróci NULL.
    FILE *fp = fopen(USERS_FILE, "r+");
    if (fp == NULL)
    {
        // Jeśli plik nie istnieje, utwórz go w trybie "w+"
        if (errno == ENOENT)
        {
            fp = fopen(USERS_FILE, "w+");
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

    // Zablokuj plik do wyłącznego dostępu
    if (flock(fileno(fp), LOCK_EX) == -1)
    {
        log_message(LOG_ERR, "flock (EX) on users file failed: %m");
        fclose(fp);
        return -2;
    }

    char line_buffer[MAX_USERNAME_LEN + SHA256_HEX_LEN + 2];
    char existing_user[MAX_USERNAME_LEN];
    int user_exists = 0;

    rewind(fp); // Upewnij się, że czytamy od początku
    while (fgets(line_buffer, sizeof(line_buffer), fp) != NULL)
    {
        // Parsujemy tylko nazwę użytkownika z linii (wszystko przed ':')
        if (sscanf(line_buffer, "%31[^:]", existing_user) == 1)
        {
            if (strcmp(existing_user, username) == 0)
            {
                user_exists = 1;
                break;
            }
        }
    }

    if (user_exists)
    {
        log_message(LOG_INFO, "Registration failed: User '%s' already exists.", username);
        flock(fileno(fp), LOCK_UN);
        fclose(fp);
        return -1; // Użytkownik już istnieje
    }

    // Użytkownik nie istnieje, dopisujemy go na końcu pliku
    char password_hash[SHA256_HEX_LEN];
    hash_password_sha256(password, password_hash);

    fseek(fp, 0, SEEK_END); // Przejdź na koniec pliku
    if (fprintf(fp, "%s:%s\n", username, password_hash) < 0)
    {
        log_message(LOG_ERR, "Failed to write new user record for '%s': %m", username);
        flock(fileno(fp), LOCK_UN);
        fclose(fp);
        return -2;
    }

    flock(fileno(fp), LOCK_UN);
    fclose(fp);
    log_message(LOG_INFO, "User '%s' registered successfully.", username);
    return 0; // Sukces
}

int verify_user_credentials(const char *username, const char *password)
{
    FILE *fp = fopen(USERS_FILE, "r");
    if (fp == NULL)
    {
        log_message(LOG_WARNING, "Could not open users file '%s' for verification: %m", USERS_FILE);
        return -2;
    }

    // Zablokuj plik do odczytu współdzielonego
    if (flock(fileno(fp), LOCK_SH) == -1)
    {
        log_message(LOG_ERR, "flock (SH) on users file failed for verification: %m");
        fclose(fp);
        return -2;
    }

    char input_password_hash[SHA256_HEX_LEN];
    hash_password_sha256(password, input_password_hash);

    char line_buffer[MAX_USERNAME_LEN + SHA256_HEX_LEN + 2];
    char stored_user[MAX_USERNAME_LEN];
    char stored_hash[SHA256_HEX_LEN];
    int found = 0;

    while (fgets(line_buffer, sizeof(line_buffer), fp) != NULL)
    {
        // Parsuj linię, aby wyciągnąć nazwę użytkownika i zapisany hash
        if (sscanf(line_buffer, "%31[^:]:%64s", stored_user, stored_hash) == 2)
        {
            if (strcmp(stored_user, username) == 0)
            {
                // Porównaj hash podanego hasła z hashem z pliku
                if (strcmp(input_password_hash, stored_hash) == 0)
                {
                    found = 1;
                }
                break; // Znaleziono użytkownika, nie trzeba dalej szukać
            }
        }
    }

    flock(fileno(fp), LOCK_UN);
    fclose(fp);

    if (found)
    {
        log_message(LOG_INFO, "User '%s' authenticated successfully.", username);
        return 0; // Sukces
    }
    else
    {
        log_message(LOG_WARNING, "Authentication failed for user '%s'.", username);
        return -1; // Zły użytkownik lub hasło
    }
}