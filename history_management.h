#ifndef HISTORY_MANAGEMENT_H
#define HISTORY_MANAGEMENT_H

#include "common.h"

#define HISTORY_DIR "chat_history" // Katalog na pliki historii

// Inicjalizacja (np. utworzenie katalogu, jeśli nie istnieje)
void init_history_management();

// Zapis wiadomości do historii
// Nazwa pliku może być np. user1_user2.hist (posortowane alfabetycznie, aby uniknąć duplikatów)
// lub user/user_z_kim.hist
// Zwraca 0 - sukces, -1 - błąd
int store_chat_message(const char *user_a, const char *user_b, const char *sender, const char *message_text);

// Pobranie historii dla danego użytkownika i konwersacji (lub całej historii użytkownika)
// Ta funkcja będzie musiała wysyłać dane fragmentami (TLV chunk + TLV end)
// Zwraca 0 - sukces, -1 - błąd
int retrieve_chat_history(const char *requesting_user, const char *other_user, int client_sockfd);

#endif // HISTORY_MANAGEMENT_H