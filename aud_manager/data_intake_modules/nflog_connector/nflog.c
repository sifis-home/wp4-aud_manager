#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <net/if.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <libnetfilter_log/libnetfilter_log.h>


#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#define AF_SOCK_PATH "/tmp/aud/nflog_emit.sock"

#define BUFSIZE 512

#define TCP 6
#define UDP 17

struct connwrapper {
    int fd;
    int status;
};

static int cb(struct nflog_g_handle *gh, struct nfgenmsg *nfmsg,
              struct nflog_data *nfa, void *connwrap)
{
    int res;
    struct connwrapper *conn;
    struct nfulnl_msg_packet_hdr *ph = nflog_get_msg_packet_hdr(nfa);
    u_int32_t indev = nflog_get_indev(nfa);
    u_int32_t outdev = nflog_get_outdev(nfa);

    struct timeval tv;
    /* nflog_get_timestamp fails for some reason. Let's use gettimeofday for now. */
    //res = nflog_get_timestamp(nfa, &tv);
    gettimeofday(&tv, NULL);
    unsigned long ts = 1000000 * tv.tv_sec + tv.tv_usec;

    char *payload;
    char ifname[20] = {0};
    u_int16_t hw_proto = 0;

    char buffer[512] = {0};

    conn = (struct connwrapper *)connwrap;

    if ((nflog_get_payload(nfa, &payload)) == -1)
        return -1;

    char *hwll_hdr = nflog_get_msg_packet_hwhdr(nfa);
    int hwll_hdr_len = nflog_get_msg_packet_hwhdrlen(nfa);

    if (ph)
        hw_proto = ntohs(ph->hw_protocol);

    if (indev > 0)
        if_indextoname(indev, ifname);

    if (outdev > 0)
        if_indextoname(outdev, ifname);

    struct iphdr *iph = (struct iphdr *)payload;
    static struct in_addr src_addr;
    static struct in_addr dst_addr;
    src_addr.s_addr = iph->saddr;
    dst_addr.s_addr = iph->daddr;

    int idx;

    idx = sprintf(buffer, "t=%lu", ts);

    if (hwll_hdr_len >= 12) {
        idx += sprintf(buffer+idx, " dst_hw=%02x:%02x:%02x:%02x:%02x:%02x",
                       (unsigned char) hwll_hdr[0], (unsigned char) hwll_hdr[1],
                       (unsigned char) hwll_hdr[2], (unsigned char) hwll_hdr[3],
                       (unsigned char) hwll_hdr[4], (unsigned char) hwll_hdr[5]);

        idx += sprintf(buffer+idx, " src_hw=%02x:%02x:%02x:%02x:%02x:%02x",
                       (unsigned char) hwll_hdr[6], (unsigned char) hwll_hdr[7],
                       (unsigned char) hwll_hdr[8], (unsigned char) hwll_hdr[9],
                       (unsigned char) hwll_hdr[10], (unsigned char) hwll_hdr[11]);
    } else {
        idx += sprintf(buffer+idx, " dst_hw=N/A");
        idx += sprintf(buffer+idx, " src_hw=N/A");
    }
    idx += sprintf(buffer+idx, " hw=0x%.4x", hw_proto);
    idx += sprintf(buffer+idx, " len=%d", ntohs(iph->tot_len));
    idx += sprintf(buffer+idx, " src_addr=%s", inet_ntoa(src_addr));
    idx += sprintf(buffer+idx, " dst_addr=%s", inet_ntoa(dst_addr));
    idx += sprintf(buffer+idx, " proto=%d", iph->protocol);

    struct tcphdr *tcph;
    struct udphdr *udph;

    switch(iph->protocol) {
    case TCP:
        tcph = (struct tcphdr *)(payload + (iph->ihl << 2));
        idx += sprintf(buffer+idx, " src_port=%d", ntohs(tcph->source));
        idx += sprintf(buffer+idx, " dst_port=%d", ntohs(tcph->dest));
        idx += sprintf(buffer+idx, " flags=");

        if (tcph->syn)
            idx += sprintf(buffer+idx, "syn,");
        if (tcph->ack)
            idx += sprintf(buffer+idx, "ack");
        break;

    case UDP:
        udph = (struct udphdr *)(payload + (iph->ihl << 2));
        idx += sprintf(buffer+idx, " src_port=%d", ntohs(udph->source));
        idx += sprintf(buffer+idx, " dst_port=%d", ntohs(udph->dest));
        break;

    default:
        break;

    }

    printf("%s\n", buffer);

    res = send(conn->fd, buffer, idx, 0);

    if (res < 0)
        conn->status = -1;

    return 0;
}


int main(int argc, char **argv) {

    static int nflog_group_id = 7;
    static int nflog_nf_fd = -1;

    struct nflog_handle *nflog_h;
    struct nflog_g_handle *nflog_qh;

    int res;

    nflog_h = nflog_open();
    if (!nflog_h) {
        fprintf(stderr, "Unable to open nflog.");
        return -1;
    }
    if (nflog_unbind_pf(nflog_h, AF_INET) < 0) {
        fprintf(stderr, "Unable to unbind pf.");
        return -2;
    }
    if (nflog_bind_pf(nflog_h, AF_INET) < 0) {
        fprintf(stderr, "Unable to bind pf.");
        return -3;
    }

    nflog_qh = nflog_bind_group(nflog_h, nflog_group_id);
    if (!nflog_qh) {
        fprintf(stderr, "No handle for nf group.");
        return -4;
    }

    if (nflog_set_mode(nflog_qh, NFULNL_COPY_PACKET, 0x0040) < 0) {
        fprintf(stderr, "Can't set packet copy mode.");
        return -5;
    }

    nflog_nf_fd = nflog_fd(nflog_h);


    struct connwrapper conn;
    struct sockaddr_un server_address;
    struct sockaddr_un client_address;

    socklen_t server_addr_len = sizeof(sa_family_t) + strlen(AF_SOCK_PATH);
    socklen_t client_addr_len;

    char buf[BUFSIZE];

    memset(&server_address, 0, sizeof(server_address));
    server_address.sun_family = AF_UNIX;
    strcpy(server_address.sun_path, AF_SOCK_PATH);
    //server_address.sun_path[0] = 0;

    while (1) {
        unlink(AF_SOCK_PATH);
        client_addr_len = sizeof(struct sockaddr_un);

        if ((conn.fd = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0) {
            perror("server: socket");
            return -1;
        }

        if (bind(conn.fd,
                 (const struct sockaddr *) &server_address,
                 server_addr_len) < 0) {
            close(conn.fd);
            perror("server: bind");
            return -1;
        }

        res = recvfrom(conn.fd,
                       buf,
                       BUFSIZE,
                       0,
                       (struct sockaddr *) &client_address,
                       &client_addr_len);

        if(res > 0) {
            printf("received %d b\n", res);
        }

        if ((connect(conn.fd,
                     (const struct sockaddr *)&client_address,
                     client_addr_len)) < 0) {
            return -1;
        }
        conn.status = 1;

        nflog_callback_register(nflog_qh, &cb, &conn);

        while ((conn.status > 0) && (res = recv(nflog_nf_fd, buf, sizeof(buf), 0))) {
            res = nflog_handle_packet(nflog_h, buf, res);

            /* nflog_handle_packet() may return -1 due to internal errors,
               and hence it's not reliable to detect connection breakage. */
            //if (rc < 0) {
            //    perror("send() failed");
            //    break;
            //}


        }
        printf("conn.fd %d\n", conn.fd);
        close(conn.fd);
    }

    if (conn.fd != -1)
        close(conn.fd);

    unlink(AF_SOCK_PATH);


    nflog_unbind_group(nflog_qh);
    nflog_close(nflog_h);

    return 0;

}
