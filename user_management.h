#ifndef USER_MANAGEMENT_H
#define USER_MANAGEMENT_H

#include "common.h"

#define USERS_FILE "users.dat" // Nazwa pliku z danymi użytkowników
#define MAX_USERS 100          // Przykładowe ograniczenie

// Struktura do przechowywania danych użytkownika w pliku
typedef struct
{
    char username[MAX_USERNAME_LEN];
    char password_hash[MAX_PASSWORD_LEN]; // Przechowuj hash, nie czysty tekst!
    // Można dodać inne pola, np. status online
} UserRecord;

// Inicjalizacja (np. sprawdzenie, czy plik istnieje)
void init_user_management();

// Rejestracja użytkownika
// Zwraca 0 - sukces, -1 - błąd (np. użytkownik istnieje), -2 - błąd pliku
int register_new_user(const char *username, const char *password);

// Weryfikacja danych logowania
// Zwraca 0 - sukces, -1 - błąd (np. zły user/pass), -2 - błąd pliku
int verify_user_credentials(const char *username, const char *password);

// TODO: Funkcje do zarządzania statusem online/offline, jeśli potrzebne

#endif // USER_MANAGEMENT_H