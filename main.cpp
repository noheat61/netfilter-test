#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <iso646.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h> /* for NF_ACCEPT */
#include <errno.h>
#include <libnet.h>
#include <string>
#include <libnetfilter_queue/libnetfilter_queue.h>

std::string method[9] = {"GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"};
std::string host = "Host: ";

static unsigned int get_id(struct nfq_data *tb)
{
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(tb);
    int id = 0;
    if (ph)
        id = ntohl(ph->packet_id);
    return id;
}

static bool check_host(unsigned char *packet)
{
    //HTTP에 대해서 HOST값이 인자와 같으면 차단
    struct libnet_ipv4_hdr *ipv4 = (struct libnet_ipv4_hdr *)packet;

    //TCP여야 함
    if (ipv4->ip_p not_eq IPPROTO_TCP)
        return false;
    struct libnet_tcp_hdr *TCP = (struct libnet_tcp_hdr *)(packet + ipv4->ip_hl * 4);
    const char *payload = (const char *)(packet + ipv4->ip_hl * 4 + TCP->th_off * 4);

    //source port나 destination port 둘 중 하나는 80이어야 HTTP
    if ((ntohs(TCP->th_sport) not_eq 80) and (ntohs(TCP->th_dport) not_eq 80))
        return false;

    //TCP payload가 HTTP의 method 중 하나여야 함(ex) GET, POST)
    bool IsHTTP = false;
    for (std::string str : method)
        IsHTTP |= (not strncmp(str.c_str(), payload, str.size()));
    if (not IsHTTP)
        return false;

    //payload의 HOST값 비교
    //printf("%s\n", payload);
    while (strncmp(host.c_str(), payload, 6))
        payload++;

    if (strncmp(host.c_str(), payload, host.size()))
        return false;
    return true;
}
//paket이 queue에 들어왔을 때 accept할 지 drop할 지 결정하는 함수
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{
    unsigned char *packet;
    unsigned int id = get_id(nfa);
    unsigned int len = nfq_get_payload(nfa, &packet);

    if (check_host(packet))
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    else
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

//main은 코드 그대로
int main(int argc, char **argv)
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__((aligned));

    if (argc not_eq 2)
    {
        printf("syntax : netfilter-test <host>\n");
        printf("sample : netfilter-test test.gilgil.net\n");
        return -1;
    }
    host += argv[1];

    printf("opening library handle\n");
    h = nfq_open();
    if (!h)
    {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0)
    {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0)
    {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h, 0, &cb, NULL);
    if (!qh)
    {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0)
    {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    for (;;)
    {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0)
        {
            //printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        /* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
        if (rv < 0 && errno == ENOBUFS)
        {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}
