#include <iostream>
#include <pcap/pcap.h>
#include <pcap.h>
#include <stdio.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <ctype.h>
#define SIZE_ETHERNET 14
using namespace std;

struct sniff_tcp {
   u_short th_sport; /* порт источника */
   u_short th_dport; /* порт назначения */
   tcp_seq th_seq;  /* номер последовательности */
   tcp_seq th_ack;  /* номер подтверждения */
   u_char th_offx2; /* смещение данных, rsvd */
   #define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
   u_char th_flags;
   #define TH_FIN 0x01
   #define TH_SYN 0x02
   #define TH_RST 0x04
   #define TH_PUSH 0x08
   #define TH_ACK 0x10
   #define TH_URG 0x20
   #define TH_ECE 0x40
   #define TH_CWR 0x80
   #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
   u_short th_win;  /* окно */
   u_short th_sum;  /* контрольная сумма */
   u_short th_urp;  /* экстренный указатель */
};
#define ETHER_ADDR_LEN 6

 /* Заголовок Ethernet */
 struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Адрес назначения */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Адрес источника */
    u_short ether_type; /* IP? ARP? RARP? и т.д. */
 };

 /* IP header */
 struct sniff_ip {
    u_char ip_vhl;  /* версия << 4 | длина заголовка >> 2 */
    u_char ip_tos;  /* тип службы */
    u_short ip_len;  /* общая длина */
    u_short ip_id;  /* идентефикатор */
    u_short ip_off;  /* поле фрагмента смещения */
    #define IP_RF 0x8000  /* reserved флаг фрагмента */
    #define IP_DF 0x4000  /* dont флаг фрагмента */
    #define IP_MF 0x2000  /* more флаг фрагмента */
    #define IP_OFFMASK 0x1fff /* маска для битов фрагмента */
    u_char ip_ttl;  /* время жизни */
    u_char ip_p;  /* протокол */
    u_short ip_sum;  /* контрольная сумма */
    struct in_addr ip_src,ip_dst; /* адрес источника и адрес назначения */
 };
 #define IP_HL(ip)  (((ip)->ip_vhl) & 0x0f)
 #define IP_V(ip)  (((ip)->ip_vhl) >> 4)

 typedef u_int tcp_seq;

int main(int argc, char *argv[])
{
    if(argc<2){
        printf("File name can not be empty!\n");
        return 1;
    }
    const char * file = argv[1];
    char errbuff[PCAP_ERRBUF_SIZE];

    pcap_t * pcap = pcap_open_offline(file, errbuff);
    char filter_exp[] = "tcp[tcpflags] & (tcp-ack|tcp-fin|tcp-rst) != 0";
    struct bpf_program fp;
    bpf_u_int32 net;

    if (pcap_compile(pcap, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(pcap));
        return(2);
    }

    if (pcap_setfilter(pcap, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(pcap));
        return(2);
    }

    struct pcap_pkthdr *header;
    const u_char *data;
    const struct sniff_ethernet *ethernet;
    const struct sniff_ip *ip;
    const struct sniff_tcp *tcp;
    int ACK =0;
    int RST=0;
    int FIN=0;
    while (int returnValue = pcap_next_ex(pcap, &header, &data) >= 0)
    {
        u_int size_ip;
        u_int size_tcp;

        ethernet = (struct sniff_ethernet*)(data);
        ip = (struct sniff_ip*)(data + SIZE_ETHERNET);
        size_ip = IP_HL(ip)*4;
        tcp = (struct sniff_tcp*)(data + SIZE_ETHERNET + size_ip);
        size_tcp = TH_OFF(tcp)*4;

        int flag=tcp->th_flags;
        if(flag==0x04)
            RST=RST+1;
        else if(flag==0x01)
            FIN=FIN+1;
        else if(flag==0x10)
            ACK=ACK+1;
        else
            continue;
    }

    printf("Number of incomplete sessions %d\n", ACK);
    printf("Number of sessions completed normally (by handshake) %d\n", RST);
    printf("Number of sessions completed abnormally %d\n", FIN);

}
