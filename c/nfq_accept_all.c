//compile with `gcc -o nfq_accept_all nfq_accept_all.c -lnetfilter_queue`

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>        /* for NF_ACCEPT */
#include <libnetfilter_queue/libnetfilter_queue.h>

static int callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                    struct nfq_data *nfa, void *data) {
    uint32_t id = 0;
    struct nfqnl_msg_packet_hdr *ph;

    // Extract the packet ID from the nfq_data structure
    ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) {
        id = ntohl(ph->packet_id);
    }
    
    // Print a message when packet is being handled
    printf("Packet handled (ID: %u)\n", id);

    // Accept all packets
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv) {
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    int rv;
    char buf[4096];

    // Open a handle to the library
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "Error during nfq_open()\n");
        exit(1);
    }

    // Unbind existing nf_queue handler for AF_INET (if any)
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "Error during nfq_unbind_pf()\n");
        exit(1);
    }

    // Bind nfnetlink_queue as the handler for AF_INET
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "Error during nfq_bind_pf()\n");
        exit(1);
    }

    // Create a new queue handle
    qh = nfq_create_queue(h, 0, &callback, NULL);
    if (!qh) {
        fprintf(stderr, "Error during nfq_create_queue()\n");
        exit(1);
    }

    // Set the mode to copy packet data to userspace
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "Error during nfq_set_mode()\n");
        exit(1);
    }

    // Get the file descriptor associated with the queue
    fd = nfq_fd(h);

    // Main loop to process packets
    while ((rv = recv(fd, buf, sizeof(buf), 0))) {
        if (rv >= 0) {
            // Handle the packet
            nfq_handle_packet(h, buf, rv);
        } else {
            perror("recv");
            break;
        }
    }

    // Cleanup
    nfq_destroy_queue(qh);
    nfq_close(h);

    return 0;
}
