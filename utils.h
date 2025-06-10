#ifndef UTILS_H
#define UTILS_H

#include "common.h" // Zawiera syslog.h, stdio.h, itd.

// Prosta funkcja do logowania błędów z perror i syslog
void error_exit(const char *msg, int log_level);
void log_message(int log_level, const char *format, ...);

// Funkcja pomocnicza do odczytu n bajtów (obsługuje częściowe odczyty)
ssize_t read_n(int fd, void *vptr, size_t n);

// Funkcja pomocnicza do zapisu n bajtów (obsługuje częściowe zapisy)
ssize_t write_n(int fd, const void *vptr, size_t n);

#endif // UTILS_H