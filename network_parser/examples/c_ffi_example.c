#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct {
    uint8_t destination_mac[6];
    uint8_t source_mac[6];
    uint16_t ether_type;
} CEthernetHeader;

typedef struct {
    uint8_t version;
    uint8_t ihl;
    uint8_t dscp_ecn;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragment_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t header_checksum;
    uint8_t source_addr[4];
    uint8_t destination_addr[4];
    const uint8_t* options;
    size_t options_len;
} CIpv4Header;

typedef struct {
    uint16_t source_port;
    uint16_t destination_port;
    uint16_t length;
    uint16_t checksum;
    const uint8_t* payload;
    size_t payload_len;
} CUdpPacket;

typedef struct {
    CEthernetHeader ethernet;
    CIpv4Header ipv4;
    CUdpPacket udp;
} PacketHandle;

extern PacketHandle* packet_parse(const uint8_t* data, size_t len);
extern void packet_free(PacketHandle* handle);

int main() {
    uint8_t raw_packet[] = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66,  0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,  0x08, 0x00,
        0x45, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x01, 0x0A, 0x00, 0x00, 0x02,
        0x04, 0xD2, 0x16, 0x2E, 0x00, 0x0C, 0x00, 0x00,
        'H', 'E', 'L', 'L', 'O'
    };

    printf("Sending %zu bytes to Rust\n", sizeof(raw_packet));

    PacketHandle* handle = packet_parse(raw_packet, sizeof(raw_packet));

    if (handle == NULL) {
        printf("Error: Null returned.\n");
        return 1;
    }

    printf("\n=== Successfull parsing! ===\n");
    printf("EtherType: 0x%04X\n", handle->ethernet.ether_type);
    
    printf("IPv4 Src: %d.%d.%d.%d\n", 
        handle->ipv4.source_addr[0], handle->ipv4.source_addr[1], 
        handle->ipv4.source_addr[2], handle->ipv4.source_addr[3]);

    printf("UDP Src Port: %u\n", handle->udp.source_port);
    printf("UDP Dst Port: %u\n", handle->udp.destination_port);
    printf("UDP Payload Length: %zu\n", handle->udp.payload_len);
    
    printf("Payload: '%.*s'\n", (int)handle->udp.payload_len, handle->udp.payload);
    
    if (handle->udp.payload >= raw_packet && handle->udp.payload < raw_packet + sizeof(raw_packet)) {
        printf("\nThe payload address in inside the initial frame!\n");
    }

    packet_free(handle);
    printf("Memory cleaned.\n");

    return 0;
}