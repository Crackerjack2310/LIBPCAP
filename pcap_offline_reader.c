#include <pcap.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>

#define SNAP_LEN 1518
#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN	6
#define PACKSIZ	1518

struct sniff_ethernet
{
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

struct sniff_ip
{
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

typedef u_int tcp_seq;

struct sniff_tcp 
{
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
	#define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

//int main(u_char *args, const struct pcap_pkthdr *header, const u_char *packet_arg)
int main()
{
	static int count = 1;                   /* packet counter */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const char *payload;                    /* Packet payload */
	u_char *packet = (u_char*) malloc(sizeof(char)*10000);
	int fd, count_packet;
	fd = open("pcapfile.pcap", O_RDWR);
	if (fd == -1)
	{
		perror("opening packet file :");
		exit(EXIT_FAILURE);
	}
	while (1)
	{
		count_packet = read(fd, packet, PACKSIZ);
		if (count_packet < 1)
		{
			perror("reading from packet file :");
			exit(EXIT_FAILURE);
		}
		printf("Successfully read a packet from file !!\n");
		int size_ip;
		int size_tcp;
		int size_payload;
			
		printf("\nPacket number %d:\n", count);
		count++;

		ethernet = (struct sniff_ethernet*)(packet);

		ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);		
		size_ip = IP_HL(ip)*4;					// IP size is variable; in blocks of 4 bytes each
		if (size_ip < 20)					// as 20 bytes is minimum size for IP
		{
			printf("   * Invalid IP header length: %u bytes\n", size_ip);
			return 0;
		}
		printf("       Source Address: %s\n", inet_ntoa(ip->ip_src));
		printf("       Destination Address: %s\n", inet_ntoa(ip->ip_dst));
		printf("       IP Version : IPv%d\n", IP_V(ip));
/*		printf("       Type of service: %d\n", ip->ip_tos);
		printf("       Identification: %d\n", ip->ip_id);
		printf("       total length: %d\n", ip->ip_len);
*/										/* determine protocol */	
		switch(ip->ip_p) 
		{
			case IPPROTO_TCP:
				printf("   Protocol: TCP\n");
				tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
				size_tcp = TH_OFF(tcp)*4;
				if (size_tcp < 20) 
				{
					printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
					return 0;
				}
				printf("   Source Port: %d\n", ntohs(tcp->th_sport));
				printf("   Destination Port: %d\n", ntohs(tcp->th_dport));
				payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
				break;
			case IPPROTO_UDP:
				printf("   Protocol: UDP\n");
				break;
			case IPPROTO_ICMP:
				printf("   Protocol: ICMP\n");
				break;;
			case IPPROTO_IP:
				printf("   Protocol: IP\n");
				break;;
			default:
				printf("   Protocol: unknown\n");
				break;;
		}
	}	
	free(packet);
	return 0;
}
