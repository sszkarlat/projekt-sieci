#ifndef USER_MANAGEMENT_H
#define USER_MANAGEMENT_H

#include "common.h"

#define USERS_FILE "users.dat"

// Inicjalizacja (np. sprawdzenie, czy plik istnieje)
void init_user_management();

// Rejestracja użytkownika w pliku tekstowym z hashowanym hasłem
// Zwraca 0 - sukces, -1 - błąd (np. użytkownik istnieje), -2 - błąd pliku
int register_new_user(const char *username, const char *password);

// Weryfikacja danych logowania na podstawie hasha
// Zwraca 0 - sukces, -1 - błąd (np. zły user/pass), -2 - błąd pliku
int verify_user_credentials(const char *username, const char *password);

#endif // USER_MANAGEMENT_H