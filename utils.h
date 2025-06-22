#ifndef UTILS_H
#define UTILS_H

#include "common.h"

// Prosta funkcja do logowania błędów z perror i syslog i zakończenia programu
void error_exit(const char *msg, int log_level);

// Funkcja do logowania wiadomości do syslog (i opcjonalnie stderr)
void log_message(int log_level, const char *format, ...);

// Funkcja pomocnicza do odczytu n bajtów (obsługuje częściowe odczyty)
ssize_t read_n(int fd, void *vptr, size_t n);

// Funkcja pomocnicza do zapisu n bajtów (obsługuje częściowe zapisy)
ssize_t write_n(int fd, const void *vptr, size_t n);

#endif // UTILS_H