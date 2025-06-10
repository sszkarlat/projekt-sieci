#include "common.h"
#include "utils.h" // Używamy read_n/write_n

// Funkcja do wysyłania komunikatu TLV
int send_tlv(int sockfd, MessageType type, const void *value, uint16_t length)
{
    TLVHeader header;
    header.type = htonl(type);
    header.length = htons(length);

    // Wyślij nagłówek
    if (write_n(sockfd, &header, sizeof(TLVHeader)) != sizeof(TLVHeader))
    {
        perror("send_tlv: write header failed");
        return -1;
    }
    // Wyślij dane (jeśli są)
    if (length > 0 && value != NULL)
    {
        if (write_n(sockfd, value, length) != length)
        {
            perror("send_tlv: write value failed");
            return -1;
        }
    }
    return 0;
}

// Funkcja do odbierania komunikatu TLV
int receive_tlv(int sockfd, TLVHeader *header, char *value_buffer, uint16_t max_value_len)
{
    ssize_t bytes_read;
    // Odbierz nagłówek
    bytes_read = read_n(sockfd, header, sizeof(TLVHeader));
    if (bytes_read <= 0)
    {
        if (bytes_read == 0)
            log_message(LOG_DEBUG, "receive_tlv: Connection closed by peer.");
        else
            perror("receive_tlv: read header failed");
        return -1;
    }
    if (bytes_read != sizeof(TLVHeader))
    {
        log_message(LOG_WARNING, "receive_tlv: Incomplete TLV header received (%zd/%zu bytes).", bytes_read, sizeof(TLVHeader));
        return -1;
    }

    header->type = ntohl(header->type);
    header->length = ntohs(header->length);

    // Odbierz dane (jeśli są)
    if (header->length > 0)
    {
        if (header->length > max_value_len)
        {
            log_message(LOG_WARNING, "receive_tlv: TLV value too large for buffer (%u > %u). Discarding extra data.", header->length, max_value_len);
            // Próba odczytania i zignorowania nadmiarowych danych, aby gniazdo było czyste
            char discard_buffer[512];
            uint16_t to_discard = header->length;
            while (to_discard > 0)
            {
                ssize_t discarded = read_n(sockfd, discard_buffer, (to_discard > sizeof(discard_buffer) ? sizeof(discard_buffer) : to_discard));
                if (discarded <= 0)
                    break;
                to_discard -= discarded;
            }
            return -1; // Zwróć błąd, bo dane nie zmieściły się
        }
        bytes_read = read_n(sockfd, value_buffer, header->length);
        if (bytes_read <= 0)
        {
            if (bytes_read == 0)
                log_message(LOG_DEBUG, "receive_tlv: Connection closed by peer while receiving value.");
            else
                perror("receive_tlv: read value failed");
            return -1;
        }
        if (bytes_read != header->length)
        {
            log_message(LOG_WARNING, "receive_tlv: Incomplete TLV value received (%zd/%u bytes).", bytes_read, header->length);
            return -1;
        }
    }
    return 0;
}