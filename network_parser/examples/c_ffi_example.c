#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

typedef enum
{
    C_PARSE_OK = 0,
    C_PARSE_NULL_POINTER = 1,
    C_PARSE_PACKET_TOO_SHORT = 2,
    C_PARSE_INVALID_ETHERTYPE = 3,
    C_PARSE_INVALID_IPV4_VERSION = 4,
    C_PARSE_INVALID_IPV4_HEADER_LENGTH = 5,
    C_PARSE_INVALID_IPV4_TOTAL_LENGTH = 6,
    C_PARSE_INVALID_UDP_LENGTH = 7,
    C_PARSE_UNSUPPORTED_PROTOCOL = 8,
    C_PARSE_INTERNAL_PANIC = 9
} CParseError;

typedef struct
{
    uint8_t destination[6];
    uint8_t source[6];
    uint16_t ethertype;
} CEthernetHeader;

typedef struct
{
    uint8_t version;
    uint8_t ihl;
    uint8_t dscp;
    uint8_t ecn;
    uint16_t total_len;
    uint16_t identification;
    uint8_t flags;
    uint16_t fragment_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;

    uint8_t source[4];
    uint8_t destination[4];

    const uint8_t *options;
    size_t options_len;
} CIpv4Header;

typedef struct
{
    uint16_t source;
    uint16_t destination;
    uint16_t length;
    uint16_t checksum;

    const uint8_t *payload;
    size_t payload_len;
} CUdpPacket;

typedef struct
{
    CEthernetHeader ethernet;
    CIpv4Header ipv4;
    CUdpPacket udp;
} PacketHandle;

extern PacketHandle *packet_parse(const uint8_t *data, size_t len, CParseError *out_error);

extern void packet_free(PacketHandle *handle);

static void print_mac(const uint8_t *mac)
{
    printf("%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void print_ip(const uint8_t *ip)
{
    printf("%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
}

static const char *error_to_string(CParseError error)
{
    switch (error)
    {
    case C_PARSE_OK:
        return "Ok";

    case C_PARSE_NULL_POINTER:
        return "NullPointer";

    case C_PARSE_PACKET_TOO_SHORT:
        return "PacketTooShort";

    case C_PARSE_INVALID_ETHERTYPE:
        return "InvalidEtherType";

    case C_PARSE_INVALID_IPV4_VERSION:
        return "InvalidIpv4Version";

    case C_PARSE_INVALID_IPV4_HEADER_LENGTH:
        return "InvalidIpv4HeaderLength";

    case C_PARSE_INVALID_IPV4_TOTAL_LENGTH:
        return "InvalidIpv4TotalLength";

    case C_PARSE_INVALID_UDP_LENGTH:
        return "InvalidUdpLength";

    case C_PARSE_UNSUPPORTED_PROTOCOL:
        return "UnsupportedProtocol";

    case C_PARSE_INTERNAL_PANIC:
        return "InternalPanic";

    default:
        return "UnknownError";
    }
}

int main(void)
{

    const uint8_t packet[] = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x08, 0x00,

        0x45,       /* version = 4, IHL = 5 */
        0x00,       /* DSCP + ECN */
        0x00, 0x21, /* total length = 33 */
        0x12, 0x34, /* identification */
        0x00, 0x00, /* flags + fragment offset */
        0x40,       /* TTL */
        0x11,       /* protocol = UDP */
        0x00, 0x00, /* checksum */

        192, 168, 1, 10,
        192, 168, 1, 20,

        0x04, 0xD2, /* source port = 1234 */
        0x16, 0x2E, /* destination port = 5678 */
        0x00, 0x0D, /* length = 13 */
        0x00, 0x00, /* checksum */

        'h', 'e', 'l', 'l', 'o'};

    CParseError error = C_PARSE_OK;

    PacketHandle *handle = packet_parse(packet, sizeof(packet), &error);

    if (handle == NULL)
    {
        fprintf(
            stderr,
            "Failed to parse packet: %s (%d)\n",
            error_to_string(error),
            error);

        return 1;
    }

    printf("Packet parsed successfully!\n\n");

    printf("Ethernet:\n");

    printf("  Destination MAC: ");
    print_mac(handle->ethernet.destination);
    printf("\n");

    printf("  Source MAC: ");
    print_mac(handle->ethernet.source);
    printf("\n");

    printf("  EtherType: 0x%04X\n", handle->ethernet.ethertype);

    printf("\nIPv4:\n");

    printf("  Version: %u\n", handle->ipv4.version);

    printf("  IHL: %u\n", handle->ipv4.ihl);

    printf("  Source IP: ");
    print_ip(handle->ipv4.source);
    printf("\n");

    printf("  Destination IP: ");
    print_ip(handle->ipv4.destination);
    printf("\n");

    printf("  Protocol: %u\n", handle->ipv4.protocol);

    printf("\nUDP:\n");

    printf("  Source port: %u\n", handle->udp.source);

    printf("  Destination port: %u\n", handle->udp.destination);

    printf("  Length: %u\n", handle->udp.length);

    printf("\nPayload:\n");

    printf("  Length: %zu\n", handle->udp.payload_len);

    printf("  Data: ");

    for (size_t i = 0; i < handle->udp.payload_len; ++i)
    {
        putchar((char)handle->udp.payload[i]);
    }

    printf("\n");

    if (handle->udp.payload == packet + 42)
    {
        printf("\nZero-copy check: PASS\n");
    }
    else
    {
        printf("\nZero-copy check: FAIL\n");
    }
    packet_free(handle);

    return 0;
}