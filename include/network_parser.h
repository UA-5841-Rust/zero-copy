#ifndef NETWORK_PARSER_H
#define NETWORK_PARSER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct PacketHandle PacketHandle;

enum PacketStatus {
    PACKET_STATUS_INVALID_ARGUMENT = -1,
    PACKET_STATUS_OK = 0,
    PACKET_STATUS_NULL_POINTER = 1,
    PACKET_STATUS_PACKET_TOO_SHORT = 2,
    PACKET_STATUS_INVALID_ETHERTYPE = 3,
    PACKET_STATUS_INVALID_IPV4_VERSION = 4,
    PACKET_STATUS_INVALID_IPV4_HEADER_LENGTH = 5,
    PACKET_STATUS_INVALID_IPV4_TOTAL_LENGTH = 6,
    PACKET_STATUS_INVALID_UDP_LENGTH = 7,
    PACKET_STATUS_UNSUPPORTED_PROTOCOL = 8,
    PACKET_STATUS_MALFORMED_PACKET = 9,
};

/* The input buffer must remain valid and unchanged until packet_free(handle). */
PacketHandle *packet_parse(const uint8_t *data, size_t len);
PacketHandle *packet_parse_with_status(
    const uint8_t *data,
    size_t len,
    int32_t *out_status
);

void packet_free(PacketHandle *handle);

int32_t packet_get_payload(
    const PacketHandle *handle,
    const uint8_t **out_ptr,
    size_t *out_len
);
int32_t packet_get_source_port(const PacketHandle *handle, uint16_t *out_port);
int32_t packet_get_destination_port(const PacketHandle *handle, uint16_t *out_port);
int32_t packet_get_ethertype(const PacketHandle *handle, uint16_t *out_ethertype);
int32_t packet_get_ipv4_protocol(const PacketHandle *handle, uint8_t *out_protocol);

#ifdef __cplusplus
}
#endif

#endif
