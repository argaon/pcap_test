#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

struct ip *iph;
struct tcphdr *tcph;

void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet)

{
    (void)useless;
    struct ether_header *ep;
    unsigned short ether_type;
    int chcnt =0;
    int ehcnt = 12;
    int length=pkthdr->len;

    ep = (struct ether_header *)packet;

    u_char *eh = ep->ether_dhost;   //destination eth addr 6
 //   u_char *tcpdata;
    printf("Ethernet Header\n");
    printf("Dst Mac : ");
    while(ehcnt--)
    {
        printf("%02x ", *(eh++));
        if (ehcnt == 6)
            printf("\nSrc Mac : ");
    }

    packet += sizeof(struct ether_header);

    ether_type = ntohs(ep->ether_type);

    if (ether_type == 0x0800) //ETHERTYPE_IP_VALUE
    {
        iph = (struct ip *)packet;
        printf("\nIP Header\n");
        printf("Src Address : %s\n", inet_ntoa(iph->ip_src));
        printf("Dst Address : %s\n", inet_ntoa(iph->ip_dst));

 /*       if (iph->ip_p == 6) //IPPROTO_TCP_VALUE
        {
            tcph = (struct tcp *)(packet + iph->ip_hl * 4);
            printf("TCP Header\n");
            printf("Src Port : %d\n" , ntohs(tcph->source));
            printf("Dst Port : %d\n" , ntohs(tcph->dest));        
        }
        while(length--)
        {
            printf("%02x ", *(packet++));  //tcpdata++
            if ((++chcnt % 16) == 0)
                printf("\n");
        }
 */
        if (iph->ip_p == 6) //IPPROTO_TCP_VALUE
        {
            tcph = (struct tcp *)(packet + iph->ip_hl * 4);
            printf("TCP Header\n");
            printf("Src Port : %d\n" , ntohs(tcph->source));
            printf("Dst Port : %d\n" , ntohs(tcph->dest));
            packet = packet +iph->ip_hl*4 + tcph->th_off * 4;
            printf("TCP Data\n");
            while(length--)
            {
                printf("%02x ", *(packet++));  //
                if ((++chcnt % 16) == 0)
                    printf("\n");
            }
        }
    }
    else
    {
        printf("NONE IP 패킷\n");
    }
    printf("\n\n");
}

int main(int argc, char **argv)
{
    char *dev;
    bpf_u_int32 netp;
    char errbuf[PCAP_ERRBUF_SIZE];
    const u_char *packet;
    struct bpf_program fp;

    pcap_t *pcd;  // packet capture descriptor

    dev = argv[1];
    if (dev == NULL)
    {
        printf("%s\n", errbuf);
        exit(1);
    }
    printf("DEV : %s\n", dev);

    pcd = pcap_open_live(dev, BUFSIZ,  0, -1, errbuf);
    if (pcd == NULL)
    {
        printf("%s\n", errbuf);
        exit(1);
    }

    if (pcap_compile(pcd, &fp, argv[3], 0, netp) == -1)
    {
        printf("compile error\n");
        exit(1);
    }
    if (pcap_setfilter(pcd, &fp) == -1)
    {
        printf("setfilter error\n");
        exit(0);
    }
    pcap_loop(pcd, atoi(argv[2]), callback, NULL);
}
