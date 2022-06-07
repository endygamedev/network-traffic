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


struct correct_packets {
    char *ip_source;
    char *ip_dest;
    int port_source;
    int port_dest;
};

FILE *logfile;
int total, udp, other, iphdrlen;

struct sockaddr saddr;
struct sockaddr_in source, dest;
struct correct_packets cp;


int main(int argc, char *argv[])
{
    int sock_r, saddr_len, buflen;
    
    cp.ip_source = "";
    cp.ip_dest = "";
    cp.port_source = -1;
    cp.port_dest = -1;

    for (int i = 1; i < argc; i++) {
        if (!strcmp("--ip_source", argv[i]) || !strcmp("-ips", argv[i])) {
            cp.ip_source = argv[++i];
            continue;
        }

        if (!strcmp("--ip_dest", argv[i]) || !strcmp("-ipd", argv[i])) {
            cp.ip_dest = argv[++i];
            continue;
        }

        if (!strcmp("--port_source", argv[i]) || !strcmp("-ps", argv[i])) {
            if (is_number(argv[++i])) {
                cp.port_source = atoi(argv[i]);
                continue;
            } else {
                fprintf(stderr, "Error: Ivalid --port_source parameter\n");
                exit(EXIT_FAILURE);
            }
        }

        if (!strcmp("--port_dest", argv[i]) || !strcmp("-pd", argv[i])) {
            if (is_number(argv[++i])) {
                cp.port_dest = atoi(argv[i]);
                continue;
            } else {
                fprintf(stderr, "Error: Invalid --port_dest parameter\n");
                exit(EXIT_FAILURE);
            }
        }
    }
    
    printf("|-FILTER:\n");
    printf("|-%s\n", cp.ip_source);
    printf("|-%s\n", cp.ip_dest);
    printf("|-%d\n", cp.port_source);
    printf("|-%d\n", cp.port_dest);

    check_ip_record(cp.ip_source);
    check_ip_record(cp.ip_dest);
    check_port(cp.port_source);
    check_port(cp.port_dest);

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
        data_process(buffer);
    }

    close(sock_r);
    fclose(logfile);

    return EXIT_SUCCESS;
}


/*
 * Writes information about filtered packets into the log file.
 * */
void packet_information(unsigned char *buffer) {
    struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    iphdrlen = ip->ihl*4;

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = ip->saddr;
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = ip->daddr;
    
    char *ip_source = strdup(inet_ntoa(source.sin_addr));
    char *ip_dest = strdup(inet_ntoa(dest.sin_addr));

    struct udphdr *udp = (struct udphdr *)(buffer + iphdrlen + sizeof(struct ethhdr));

    int data_size = ntohs(udp->len);
    int port_source = ntohs(udp->source);
    int port_dest = ntohs(udp->dest);

    if ((!strcmp(cp.ip_source, "") || !strcmp(cp.ip_source, ip_source)) &&
        (!strcmp(cp.ip_dest, "") || !strcmp(cp.ip_dest, ip_dest)) &&
        (cp.port_source == -1 || cp.port_source == port_source) &&
        (cp.port_dest == -1 || cp.port_dest == port_dest)) {

        fprintf(logfile, "\n*******************UDP Packet********************");

        fprintf(logfile, "\nIP Header\n");
        fprintf(logfile, "\t|-Source IP: %s\n", ip_source);
        fprintf(logfile, "\t|-Destination IP: %s\n", ip_dest);

        fprintf(logfile, "\nUDP Header\n");
        fprintf(logfile, "\t|-Source Port: %d\n", port_source);
        fprintf(logfile, "\t|-Destination Port: %d\n", port_dest);
    
        fprintf(logfile, "\nData\n");
        fprintf(logfile, "\t|-Datagram size: %d\n", data_size);
        
        fprintf(logfile, "************************************************\n\n\n");
    }
}


/*
 * Sniffs all packets that arrive on a given network interface and takes only UDP.
 * */
void data_process(unsigned char *buffer)
{
    struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    ++total;

    switch (ip->protocol) {
        case 17:            /* ID number for UDP protocol in /etc/protocols */
            ++udp;
            packet_information(buffer);
            break;
        default:
            ++other;
    }

    printf("UDP: %d Other: %d Total: %d \r", udp, other, total);
}
