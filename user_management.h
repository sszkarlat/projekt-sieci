#ifndef USER_MANAGEMENT_H
#define USER_MANAGEMENT_H

#include "common.h"

#define USERS_FILE "users.dat"

typedef struct
{
    char username[MAX_USERNAME_LEN];
    char password_hash[MAX_PASSWORD_LEN];
} UserRecord;

void init_user_management();
int register_new_user(const char *username, const char *password);
int verify_user_credentials(const char *username, const char *password);

#endif // USER_MANAGEMENT_H