#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>

// Mirrors CParseError in ffi.rs
typedef enum {
    PARSE_OK = 0,
    PARSE_NULL_POINTER = 1,
    PARSE_PACKET_TOO_SHORT = 2,
    PARSE_INVALID_ETHER_TYPE = 3,
    PARSE_INVALID_IPV4_VERSION = 4,
    PARSE_INVALID_IPV4_HEADER_LENGTH = 5,
    PARSE_INVALID_IPV4_TOTAL_LENGTH = 6,
    PARSE_INVALID_UDP_LENGTH = 7,
    PARSE_UNSUPPORTED_PROTOCOL = 8,
} CParseError;

// Opaque handle, C never looks inside it.
typedef struct PacketHandle PacketHandle;

extern PacketHandle *packet_parse(const uint8_t *data, size_t len, CParseError *out_error);
extern void packet_free(PacketHandle *handle);

extern bool packet_dest_mac(const PacketHandle *handle, uint8_t *out);
extern bool packet_src_mac(const PacketHandle *handle, uint8_t *out);
extern bool packet_src_addr(const PacketHandle *handle, uint8_t *out);
extern bool packet_dest_addr(const PacketHandle *handle, uint8_t *out);
extern uint8_t packet_ttl(const PacketHandle *handle);
extern uint8_t packet_protocol(const PacketHandle *handle);
extern uint16_t packet_src_port(const PacketHandle *handle);
extern uint16_t packet_dest_port(const PacketHandle *handle);
extern const uint8_t *packet_payload(const PacketHandle *handle, size_t *out_len);

static void print_bytes(const char *label, const uint8_t *bytes, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x%s", bytes[i], i + 1 < len ? ":" : "");
    }
    printf("\n");
}

int main(void) {
    // Ethernet: dest MAC, src MAC, ether type = 0x0800 (IPv4)
    // IPv4: version/IHL=0x45, ..., TTL=64, protocol=17 (UDP), src/dst IP
    // UDP: src port=80, dst port=8080, len=12, checksum=0, payload="ping"
    uint8_t packet[] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
        0x08, 0x00,

        0x45, 0x00, 0x00, 0x20, 0x12, 0x34, 0x00, 0x00,
        0x40, 0x11, 0x00, 0x00,
        192, 168, 1, 1,
        192, 168, 1, 2,

        0x00, 0x50, 0x1F, 0x90, 0x00, 0x0C, 0x00, 0x00,
        'p', 'i', 'n', 'g',
    };

    CParseError err = PARSE_OK;
    PacketHandle *handle = packet_parse(packet, sizeof(packet), &err);

    if (handle == NULL) {
        printf("parse failed, error code: %d\n", err);
        return 1;
    }

    uint8_t dest_mac[6];
    uint8_t src_mac[6];
    uint8_t src_addr[4];
    uint8_t dest_addr[4];

    packet_dest_mac(handle, dest_mac);
    packet_src_mac(handle, src_mac);
    packet_src_addr(handle, src_addr);
    packet_dest_addr(handle, dest_addr);

    print_bytes("dest_mac", dest_mac, 6);
    print_bytes("src_mac", src_mac, 6);
    print_bytes("src_addr", src_addr, 4);
    print_bytes("dest_addr", dest_addr, 4);

    printf("ttl: %u\n", packet_ttl(handle));
    printf("protocol: %u\n", packet_protocol(handle));
    printf("src_port: %u\n", packet_src_port(handle));
    printf("dest_port: %u\n", packet_dest_port(handle));

    size_t payload_len = 0;
    const uint8_t *payload = packet_payload(handle, &payload_len);
    printf("payload (%zu bytes): %.*s\n", payload_len, (int)payload_len, payload);

    packet_free(handle);
    return 0;
}
