#include <pcap/pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

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
    u_char *eh = ep->ether_dhost;   //shift Octets in one ethernet addr
    printf("Ethernet Header\n");
    printf("Dst Mac : ");
    while(ehcnt--)
    {
        printf("%02x ", *(eh++));
        if (ehcnt == 6)
            printf("\nSrc Mac : ");
    }
    printf("\n");
    packet += sizeof(struct ether_header);      //2+6+6
    ether_type = ntohs(ep->ether_type);
    if (ether_type == ETHERTYPE_IP) //ETHERTYPE_IP_VALUE
    {
        iph = (struct ip *)packet;
        printf("IP Header\n");
        printf("Src Address : %s\n", inet_ntoa(iph->ip_src));
        printf("Dst Address : %s\n", inet_ntoa(iph->ip_dst));
        if (iph->ip_p == 0x06) //IPPROTO_TCP_VALUE
        {
 //           tcph = (u_char*)iph+(iph->ip_hl *4);
            tcph = (struct tcp *)(packet + iph->ip_hl * 4);
            printf("TCP Header\n");
            printf("Src Port : %d\n" , ntohs(tcph->source));
            printf("Dst Port : %d\n" , ntohs(tcph->dest));
           // packet += 40;    //  start From TCP DATA = ipheaderlen(20) + tcp headerlen(20)
            //totallength
            packet += (iph->ip_hl *4)+(tcph->doff *4);
            length -= sizeof(struct ether_header)+(iph->ip_hl*4)+(tcph->doff*4);
            printf("TCP Data\n");

            while(length--) //length  need fix
            {
                printf("%02x ", *(packet++));
//                pcaket[chcnt++];
                if ((++chcnt % 16) == 0)
                    printf("\n");
            }
        }
        else
        printf("NOT FOUND TCP Packet\n");
    }
    else
        printf("NOT FOUND IP Packet\n");
    printf("\n\n");
}
int main(int argc, char **argv)
{//argc != 3 cannot exe
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;

    pcap_t *pcd;  // packet capture descriptor
    dev = argv[1];
    if(argc < 3)
    {
        printf("Input argument error!\n");
        if (dev == NULL)
        {
            dev = pcap_lookupdev(errbuf);
            printf("Your device is : %s\n",dev);
            printf("%s\n", errbuf);
            exit(1);
        }
    }
    else{
    printf("DEV : %s\n", dev);

    pcd = pcap_open_live(dev, BUFSIZ,  0,1000 , errbuf);
    if (pcd == NULL)
    {
        printf("%s\n", errbuf);
        exit(1);
    }
    if (pcap_compile(pcd, &fp, argv[3], 0, 0) == -1)
    {
        printf("compile error\n");
        exit(1);
    }
    if (pcap_setfilter(pcd, &fp) == -1)
    {
        printf("setfilter error\n");
        exit(0);
    }
 //   pcap_next_ex();
    pcap_loop(pcd, atoi(argv[2]), callback, NULL);
    }
}
