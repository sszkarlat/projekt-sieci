#include "utils.h"
#include <stdarg.h>

void error_exit(const char *msg, int log_level)
{
    // Log do syslog
    syslog(log_level, "%s: %m", msg); // %m zostanie zastąpione przez strerror(errno)
    // Log do stderr (użyteczne przy debugowaniu bez demona)
    perror(msg);
    exit(EXIT_FAILURE);
}

void log_message(int log_level, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    vsyslog(log_level, format, args);
    va_end(args);

    // Opcjonalnie: logowanie również do stderr, jeśli serwer nie jest w pełni zdaemonizowany
    // lub dla ułatwienia debugowania. W końcowej wersji można to usunąć.
    va_start(args, format);
    vfprintf(stderr, format, args);
    fprintf(stderr, "\n");
    va_end(args);
}

ssize_t read_n(int fd, void *vptr, size_t n)
{
    size_t nleft;
    ssize_t nread;
    char *ptr;

    ptr = vptr;
    nleft = n;
    while (nleft > 0)
    {
        if ((nread = read(fd, ptr, nleft)) < 0)
        {
            if (errno == EINTR)
                nread = 0; /* and call read() again */
            else
                return (-1);
        }
        else if (nread == 0)
            break; /* EOF */
        nleft -= nread;
        ptr += nread;
    }
    return (n - nleft); /* return >= 0 */
}

ssize_t write_n(int fd, const void *vptr, size_t n)
{
    size_t nleft;
    ssize_t nwritten;
    const char *ptr;

    ptr = vptr;
    nleft = n;
    while (nleft > 0)
    {
        if ((nwritten = write(fd, ptr, nleft)) <= 0)
        {
            if (nwritten < 0 && errno == EINTR)
                nwritten = 0; /* and call write() again */
            else
                return (-1); /* error */
        }
        nleft -= nwritten;
        ptr += nwritten;
    }
    return (n);
}