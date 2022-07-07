#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* POSIX Message Queue */
#include <fcntl.h>
#include <mqueue.h>
#include <sys/stat.h>

/* colors.h file */
#include "colors.h"


/* Maxium number of messages in message queue */
#define MAX_MESSAGES 1

/* Message queue name (identificator) */
#define MQ_NAME "/mq_stats_queue"


typedef struct {
    int count;
    int bytes;
} packet_message_t;


int main(void)
{
    struct mq_attr attributes = {
        .mq_flags = 0,
        .mq_maxmsg = 1,
        .mq_curmsgs = 0,
        .mq_msgsize = sizeof(packet_message_t),
    };

    mqd_t queue;
    packet_message_t msg;
    
    fprintf(stdout, "%sPacket Sniffer: Stats\n\n%s", HEADER, ENDC);
    fprintf(stdout, "\r%sCount: \t\t Bytes: %s", GREEN, ENDC);
    fflush(stdout);
    
    if ((queue = mq_open(MQ_NAME,
            O_RDONLY | O_NONBLOCK,
            S_IRUSR | S_IWUSR,
            &attributes)) == -1) {
        fprintf(stderr, "%sError: Executing `mq_open`%s\n", RED, ENDC);
        exit(EXIT_FAILURE);
    }

    while (1) {
        /*
         * TODO:
         * - Messages don't have time to be processed by the recipient, so you
         *   have to wait 5000 microsecond to update.
         * */
        usleep(5000);
        
        mq_receive(queue, (char *)&msg, sizeof(msg), NULL);

        fprintf(stdout, "\r%sCount: %d \t Bytes: %d%s", GREEN, msg.count,
                                                        msg.bytes, ENDC);
        
        fflush(stdout);
    }

    mq_close(queue);
    mq_unlink(MQ_NAME);

    return EXIT_SUCCESS;
}