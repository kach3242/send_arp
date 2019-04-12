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

unsigned char* arp_packet;

int main(int argc, char * argv[]){
    char * dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    int fd;
    struct ifreq ifr;
    char *iface = dev;
    unsigned char *mac;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name , iface , IFNAMSIZ-1);

    ioctl(fd, SIOCGIFHWADDR, &ifr);

    close(fd);

    mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;
    printf("Mac : %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n" , mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    arp_packet = request(mac,argv[2], argv[3]);
    for(int i=0; i<46; i++){
    printf("%02x ",*(arp_packet+i));
    }
    free(arp_packet);
    //----------------mac addr------------------

   /* uint32_t s_ip = ntohl(inet_addr(argv[2]));
    arp_packet[28] = (s_ip&0xff000000)>>24;
    arp_packet[29] = (s_ip&0x00ff0000)>>16;
    arp_packet[30] = (s_ip&0x0000ff00)>>8;
    arp_packet[31] = (s_ip&0x000000ff);
    uint32_t d_ip = ntohl(inet_addr(argv[3]));
    arp_packet[38] = (d_ip&0xff000000)>>24;
    arp_packet[39] = (d_ip&0x00ff0000)>>16;
    arp_packet[40] = (d_ip&0x0000ff00)>>8;
    arp_packet[41] = (d_ip&0x000000ff);
    for(int i=0; i<6; i++){
        arp_packet[6+i] = cMacAddr[i];
        arp_packet[22+i] = cMacAddr[i];
    }

    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    pcap_sendpacket(handle, arp_packet, 42);
    while (true){
        struct pcap_pkthdr* header;
        const unsigned char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        struct eth_header *eth = (struct eth_header *)packet;
        struct arp_header *arp = (struct arp_header *)(packet+14);

        if (res == 0) continue;
        if (ntohs(eth->eth_type) == 0x0806 && ntohs(arp->opcode) == 0x0002){
            for(int i=0; i<6; i++){
                arp_packet[i] = eth->smac[i];
                arp_packet[32+i] = eth->smac[i];
            }
            break;
        }
    }
    arp_packet[21] = 0x02;
    arp_packet[31] = 0x01;
    pcap_sendpacket(handle, arp_packet, 42);
    pcap_close(handle);*/
}
