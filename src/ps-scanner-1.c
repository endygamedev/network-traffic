#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

/* Raw Socket */
#include <sys/socket.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>

/* POSIX Thread */
#include <pthread.h>

/* POSIX Message Queue */
#include <fcntl.h>
#include <sys/stat.h>
#include <mqueue.h>

/* ps-scanner.h file */
#include "ps-scanner.h"

/* colors.h file */
#include "colors.h"


/* Maximum number of bytes to accept from the message */
#define BYTES 65536

/* Maxium number of messages in message queue */
#define MAX_MESSAGES 1

/* UDP header size */
#define UDPHDR_SIZE 8

/* Message queue name (identificator) */
#define MQ_NAME "/mq_stats_queue"


struct correct_packets {
    char *ip_source;
    char *ip_dest;
    int port_source;
    int port_dest;
};


typedef struct {
    int count;
    int bytes;
} packet_message_t;


FILE *logfile;
int iphdrlen, bytes;

struct sockaddr saddr;
struct sockaddr_in source, dest;
char *interface = "";
struct correct_packets cp;

int fd_count[2];
int fd_data[2];

time_t start;


int main(int argc, char *argv[])
{
    start = clock();

    struct if_nameindex *if_nidxs, *intf;
    if_nidxs = if_nameindex();

    cp.ip_source = "";
    cp.ip_dest = "";
    cp.port_source = -1;
    cp.port_dest = -1;
    
    if (pipe(fd_count) == -1 || pipe(fd_data) == -1) {
        fprintf(stderr, "%sError: Error while opening pipe%s\n", RED, ENDC);
        exit(EXIT_FAILURE);
    }

    for (int i = 1; i < argc; i++) {
        if (!strcmp("--interface", argv[i]) || !(strcmp("-ni", argv[i]))) {
            char *tmp = argv[++i];
            if (if_nidxs != NULL) {
                for (intf = if_nidxs; intf->if_index != 0 || intf->if_name != NULL; intf++) {
                    if (!strcmp(intf->if_name, tmp)) {
                        interface = tmp;
                        break;
                    }
                }
                continue;
            } else {
                fprintf(stderr, "%sError: No network interface was found%s\n",
                                                                    RED, ENDC);
                exit(EXIT_FAILURE);
            }
        }

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
                fprintf(stderr, "%sError: Invalid --port_source parameter%s\n",
                                                                    RED, ENDC);
                exit(EXIT_FAILURE);
            }
        }

        if (!strcmp("--port_dest", argv[i]) || !strcmp("-pd", argv[i])) {
            if (is_number(argv[++i])) {
                cp.port_dest = atoi(argv[i]);
                continue;
            } else {
                fprintf(stderr, "%sError: Invalid --port_dest parameter%s\n",
                                                                    RED, ENDC);
                exit(EXIT_FAILURE);
            }
        }
    }

    if (!strcmp(interface, "")) {
        fprintf(stderr, "%sError: The parameter `-ni` is not set or invalid%s\n",
                                                                    RED, ENDC);
        exit(EXIT_FAILURE);
    }


    char port_dest[6], port_source[6];

    fprintf(stdout, "%sPacket Sniffer: Scanner\n\n%s", HEADER, ENDC);
    
    fprintf(stdout, "%sNETWORK INTERFACE: %s%s\n\n", GREEN, ENDC, interface);

    fprintf(stdout, "%sFILTER%s\n", GREEN, ENDC);
    fprintf(stdout, "|-IP source: \t\t %s\n",
                            strcmp(cp.ip_source, "") ? cp.ip_source : "None");
    fprintf(stdout, "|-IP destination: \t %s\n",
                            strcmp(cp.ip_dest, "") ? cp.ip_dest : "None");
    sprintf(port_source, "%d", cp.port_source);
    fprintf(stdout, "|-Port source: \t\t %s\n",
                    cp.port_source != -1 ? port_source : "None");
    sprintf(port_dest, "%d", cp.port_dest);
    fprintf(stdout, "|-Port destination: \t %s\n",
                    cp.port_dest != -1 ? port_dest : "None");


    /* Checking the filters */
    check_ip_record(cp.ip_source);
    check_ip_record(cp.ip_dest);
    check_port(cp.port_source);
    check_port(cp.port_dest);
    
    /* Create thread for sending data */
    pthread_t stats_thread;

    if (pthread_create(&stats_thread, NULL, send_stats, NULL)) {
        fprintf(stderr, "%sError: Send statistics thread creation failed%s\n",
                                                                    RED, ENDC);
        exit(EXIT_FAILURE);
    }
    
    /* Create thread for collecting data */
    pthread_t data_thread;

    if (pthread_create(&data_thread, NULL, get_data, NULL)) {
        fprintf(stderr, "%sError: Collecting data thread creation failed%s\n",
                                                                    RED, ENDC);
        exit(EXIT_FAILURE);
    }
   
    /* Joining new threads */
    pthread_join(stats_thread, NULL);
    pthread_join(data_thread, NULL);

    return EXIT_SUCCESS;
}


/*
 * Threading function for sending data to the user (recepient).
 * */
void *send_stats()
{
    int udp_count, data;

    struct mq_attr attributes = {
        .mq_flags = 0,
        .mq_maxmsg = MAX_MESSAGES,
        .mq_curmsgs = 0,
        .mq_msgsize = sizeof(packet_message_t),
    };
    
    mqd_t queue;
    packet_message_t msg;
    
    if ((queue = mq_open(MQ_NAME, O_CREAT | O_WRONLY,
                         S_IRUSR | S_IWUSR,
                         &attributes)) == -1) {
        fprintf(stderr, "%sError: Executing `mq_open`%s\n", RED, ENDC);
        exit(EXIT_FAILURE);
    }

    while (1) {
        /* Taking data from the first thread with data */
        read(fd_count[0], &udp_count, 1);
        read(fd_data[0], &data, 1);

        msg.count += udp_count;
        msg.bytes += data;
        
        if ((mq_send(queue, (char *)&msg, sizeof(msg), 1)) == -1) {
            fprintf(stderr, "%sError: Executing `mq_send`%s\n", RED, ENDC);
            exit(EXIT_FAILURE);
        }
    }

    mq_close(queue);
    mq_unlink(MQ_NAME);

    pthread_exit(0);
}


/*
 * Threading function for collecting data.
 * */
void *get_data()
{
    int sock_r, saddr_len;
    struct ifreq ifr;
    struct sockaddr_ll sll;
    unsigned char *buffer = (unsigned char *)malloc(BYTES);

    memset(buffer, 0, BYTES);
    memset(&ifr, 0, sizeof(ifr));
    memset(&sll, 0, sizeof(sll));

    /* Save all filtered packets in /var/log/ps-scanner.log */
    logfile = fopen("/var/log/ps-scanner.log", "w");

    if (!logfile) {
        fprintf(stderr, "%sError: Unable to open log file%s\n", RED, ENDC);
        exit(EXIT_FAILURE);
    }

    sock_r = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP));

    if (sock_r < 0) {
        fprintf(stderr, "%sError: Can't open socket%s\n", RED, ENDC);
        exit(EXIT_FAILURE);
    }

    strncpy((char *)ifr.ifr_name, interface, IFNAMSIZ);
    
    if (ioctl(sock_r, SIOCGIFINDEX, &ifr) < 0) {
        fprintf(stderr, "%sError: Unable to find interface index%s\n", RED, ENDC);
        exit(EXIT_FAILURE);
    }

    sll.sll_family = PF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_IP);
    
    if (bind(sock_r, (struct sockaddr *)&sll, sizeof(sll)) == -1) {
        fprintf(stderr, "%sError: Can't bind socket to specific interface%s\n",
                                                                    RED, ENDC);
        exit(EXIT_FAILURE);
    }
    
    fprintf(stdout, "\n%sScanning ...%s\n", BLINK, ENDC);

    while (1) {
        saddr_len = sizeof(saddr);

        if ((recvfrom(sock_r, buffer, BYTES, 0, &saddr, (socklen_t *)&saddr_len)) < 0) {
            fprintf(stderr, "%sError: Error while reading recvfrom function%s\n",
                                                                    RED, ENDC);
            exit(EXIT_FAILURE);
        }

        data_process(buffer);
        fflush(logfile);
    }

    close(sock_r);
    fclose(logfile);
    free(buffer);

    pthread_exit(0);
}


/*
 * Writes information about filtered packets into the log file.
 * */
void packet_information(unsigned char *buffer)
{
    struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    iphdrlen = ip->ihl*4;
    int num = 0, bytes = 0;
    time_t end = clock();

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = ip->saddr;
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = ip->daddr;
    
    char *ip_source = inet_ntoa(source.sin_addr);
    char *ip_dest = inet_ntoa(dest.sin_addr);

    struct udphdr *udp = (struct udphdr *)(buffer + iphdrlen + sizeof(struct ethhdr));

    int data_size = ntohs(udp->len) - UDPHDR_SIZE;
    int port_source = ntohs(udp->source);
    int port_dest = ntohs(udp->dest);
    
    if ((!strcmp(cp.ip_source, "") || !strcmp(cp.ip_source, ip_source)) &&
        (!strcmp(cp.ip_dest, "") || !strcmp(cp.ip_dest, ip_dest)) &&
        (cp.port_source == -1 || cp.port_source == port_source) &&
        (cp.port_dest == -1 || cp.port_dest == port_dest)) {
        
        fprintf(logfile, "%f \t Interface: %s \t Source: %s \t Destination: %s \t Info: %d->%d Len=%d\n",
                (double)(end-start)/CLOCKS_PER_SEC, interface, ip_source, ip_dest, port_source, port_dest, data_size);
        
        num = 1;
        bytes = data_size;
    }
    
    /* Pipe the data to the second thread, summarizing the statistics */
    write(fd_count[1], &num, 1);
    write(fd_data[1], &bytes, 1);
}


/*
 * Sniffs all packets that arrive on a given network interface and takes only UDP.
 * */
void data_process(unsigned char *buffer)
{
    struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    
    /* ID number for UDP protocol in /etc/protocols */
    if (ip->protocol == 17) {
        packet_information(buffer);
    }
}
