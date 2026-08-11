#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

#include "network_parser.h"

int main(void) {
    const uint8_t packet[] = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00,
        0x45, 0, 0, 32, 0, 0, 0, 0, 64, 17, 0, 0,
        192, 0, 2, 1, 198, 51, 100, 2,
        0x04, 0xd2, 0x10, 0xe1, 0, 12, 0, 0, 9, 8, 7, 6,
    };
    int32_t status = PACKET_STATUS_OK;
    PacketHandle *handle = packet_parse_with_status(packet, sizeof(packet), &status);
    if (handle == NULL) {
        fprintf(stderr, "packet_parse failed: status=%" PRId32 "\n", status);
        return 1;
    }

    const uint8_t *payload = NULL;
    size_t payload_len = 0;
    uint16_t source_port = 0;
    uint16_t destination_port = 0;
    if (packet_get_payload(handle, &payload, &payload_len) != PACKET_STATUS_OK ||
        packet_get_source_port(handle, &source_port) != PACKET_STATUS_OK ||
        packet_get_destination_port(handle, &destination_port) != PACKET_STATUS_OK) {
        fprintf(stderr, "failed to read parsed fields\n");
        packet_free(handle);
        return 1;
    }

    printf("UDP %u -> %u, payload (%zu bytes):", source_port, destination_port, payload_len);
    for (size_t index = 0; index < payload_len; ++index) {
        printf(" %u", payload[index]);
    }
    puts("");

    /* packet still owns the payload; free only the Rust handle. */
    packet_free(handle);
    return 0;
}
