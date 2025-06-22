#ifndef HISTORY_MANAGEMENT_H
#define HISTORY_MANAGEMENT_H

#include "common.h"

#define HISTORY_DIR "chat_history"

void init_history_management();
int store_chat_message(const char *user_a, const char *user_b, const char *sender, const char *message_text);
int retrieve_chat_history(const char *requesting_user, const char *other_user, int client_sockfd);

#endif // HISTORY_MANAGEMENT_H