#include <stdint.h>

struct eth_header{
    uint8_t dmac[6];
    uint8_t smac[6];
    uint16_t eth_type;
};

struct arp_header{
    uint16_t hw_type;
    uint16_t protocol;
    uint8_t hw_add_len;
    uint8_t proto_add_len;
    uint16_t opcode;
    uint8_t smac[6];
    uint32_t sip;
    uint8_t dmac[6];
    uint32_t dip;
};

unsigned char* request(unsigned char *smac, char *sip, char *dip);
