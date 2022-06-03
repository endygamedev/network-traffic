#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include "main.h"

/* Maximum number of bytes to accept from the message */
#define BYTES 65536


FILE *logfile;
int total, udp, other, iphdrlen;


struct sockaddr saddr;
struct sockaddr_in source, dest;


int main(void)
{
    int sock_r, saddr_len, buflen;

    unsigned char *buffer = (unsigned char *)malloc(BYTES);
    memset(buffer, 0, BYTES);

    logfile = fopen("log", "w");

    if (!logfile) {
        fprintf(stderr, "Error: Unable to open log file\n");
        exit(EXIT_FAILURE);
    }

    fprintf(stdout, "Scanning ...\n");

    sock_r = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    
    if (sock_r < 0) {
        fprintf(stderr, "Error: Can't open socket\n");
        exit(EXIT_FAILURE);
    }

    while (1) {
        saddr_len = sizeof(saddr);
        buflen = recvfrom(sock_r, buffer, BYTES, 0, &saddr, (socklen_t *)&saddr_len);

        if (buflen < 0) {
            fprintf(stderr, "Error: Error while reading recvfrom function\n");
            exit(EXIT_FAILURE);
        }

        fflush(logfile);
        data_process(buffer, buflen);
    }

    close(sock_r);
    fclose(logfile);

    return EXIT_SUCCESS;
}


/*
 * Recieve data from OSI L2 and write it to log file.
 */
void ethernet_header(unsigned char *buffer)
{
    struct ethhdr *eth = (struct ethhdr *)(buffer);
    fprintf(logfile, "\nEthernet Header\n");
    fprintf(logfile, "\t|-Source Address: %.2X-%.2X-%.2X-%.2X-%.2X-%.2x\n",
                        eth->h_source[0], eth->h_source[1], eth->h_source[2],
                        eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    fprintf(logfile, "\t|-Destination Address: %.2X-%.2X-%.2X-%.2X-%.2X-%.2x",
                        eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
                        eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
}


/*
 * Recieve data from OSI L3 and write it to log file.
 */
void ip_header(unsigned char *buffer)
{
    struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    iphdrlen = ip->ihl*4;

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = ip->saddr;
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = ip->daddr;

    fprintf(logfile, "\nIP Header\n");

    fprintf(logfile, "\t|-Version: %d\n", (unsigned int)ip->version);
    fprintf(logfile, "\t|-Internet Header Length: %d DWORDS or %d Bytes\n",
                        (unsigned int)ip->ihl, ((unsigned int)(ip->ihl))*4);
    fprintf(logfile, "\t|-Type Of Service: %d\n", (unsigned int)ip->tos);
    fprintf(logfile, "\t|-Total Length: %d\n", ntohs(ip->tot_len));
    fprintf(logfile, "\t|-Identification: %d\n", ntohs(ip->id));
    fprintf(logfile, "\t|-Time To Live: %d\n", (unsigned int)ip->ttl);
    fprintf(logfile, "\t|-Protocol: %d\n", (unsigned int)ip->protocol);
    fprintf(logfile, "\t|-Header Checksum: %d\n", ntohs(ip->check));
    fprintf(logfile, "\t|-Source IP: %s\n", inet_ntoa(source.sin_addr));
    fprintf(logfile, "\t|-Destination IP: %s\n", inet_ntoa(dest.sin_addr));
}


/*
 * Takes data from the UDP datagram and writes it to the log file.
 * */
void payload(unsigned char *buffer, int buflen)
{
    unsigned char *data = (buffer + iphdrlen + sizeof(struct ethhdr) + sizeof(struct udphdr));
    fprintf(logfile, "\nData\n");
    int remaining_data = buflen - (iphdrlen + sizeof(struct ethhdr) + sizeof(struct udphdr));
    for (int i = 0; i < remaining_data; i++) {
        if (i != 0 && i % 16 == 0) {
            fprintf(logfile, "\n");
        }
        fprintf(logfile, "%.2X", data[i]);
    }
    fprintf(logfile, "\n");
}


/*
 * Recieve data from OSI L4 and write it to log file.
 */
void udp_header(unsigned char *buffer, int buflen)
{
    fprintf(logfile, "\n*******************UDP Packet********************");

    ethernet_header(buffer);
    ip_header(buffer);
    fprintf(logfile, "\nUDP Header\n");

    struct udphdr *udp = (struct udphdr *)(buffer + iphdrlen + sizeof(struct ethhdr));
    fprintf(logfile, "\t|-Source Port: %d\n", ntohs(udp->source));
    fprintf(logfile, "\t|-Destination Port: %d\n", ntohs(udp->dest));
    fprintf(logfile, "\t|-UDP Length: %d\n", ntohs(udp->len));
    fprintf(logfile, "\t|-UDP Checksum: %d\n", ntohs(udp->check));

    payload(buffer, buflen);

    fprintf(logfile, "************************************************\n\n\n");
}


/*
 * Sniffs all packets that arrive on a given network interface and takes only UDP.
 * */
void data_process(unsigned char *buffer, int buflen)
{
    struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    ++total;

    switch (ip->protocol) {
        case 17:            /* ID number for UDP protocol in /etc/protocols */
            ++udp;
            udp_header(buffer, buflen);
            break;
        default:
            ++other;
    }

    printf("UDP: %d Other: %d Total: %d \r", udp, other, total);
}
