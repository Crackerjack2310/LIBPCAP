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

#define SNAP_LEN 1518
#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN	6

struct sniff_ethernet
{
	u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
	u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
	u_short ether_type;                     /* IP? ARP? RARP? etc */
};

struct ipv4
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
#define IP_V6(ip)                (((ip)->field & 0x000000f0) >> 4)

struct ipv6
{
	/*   unsigned int
version : 4,
traffic_class : 8,
flow_label : 20;
	 */ unsigned int field;
	uint16_t length;			// payload length only, excluding IPv6 header of lentgh 40 bytes
	uint8_t  next_header;
	uint8_t  hop_limit;
	struct in6_addr src;
	struct in6_addr dst;
};

struct sniff_udp
{
	u_short src_port;
	u_short dst_port;
	u_short length;				// payload plus udp header
	u_short checksum;
};

typedef u_int tcp_seq;

struct sniff_tcp {
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


void ipv4_routine(const struct ipv4 * ip, const u_char *packet)
{
	const struct sniff_tcp *tcp;            /* The TCP header */
	const struct sniff_udp *udp;            /* The UDP header */
	const char *payload;                    /* Packet payload */
	int size_ip;
	int size_tcp;
	int size_udp = 8;
	int size_payload;

	printf("   IP Version : IPv%d\n", IP_V(ip));	// msb of 1st byte as in little endian	

	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) 
	{
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	char temp[INET_ADDRSTRLEN];
	printf("       Source : %s\n", inet_ntop(AF_INET, (const void*) &ip->ip_src, temp, INET_ADDRSTRLEN));
	printf("       Destination : %s\n", inet_ntop(AF_INET, (const void*) &ip->ip_dst, temp, INET_ADDRSTRLEN));
	printf("   IPv4 total length : %d\n", ip->ip_len);
	printf("   IPv4 total length converted : %d\n", ntohs(ip->ip_len));

	switch(ip->ip_p)
	{
		case IPPROTO_TCP:
			printf("   Protocol: TCP\n");
			tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
			size_tcp = TH_OFF(tcp)*4;
			if (size_tcp < 20) {
				printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
				return;
			}				
			printf("   Src port: %d\n", ntohs(tcp->th_sport));
			printf("   Dst port: %d\n", ntohs(tcp->th_dport));

			payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
			size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

			if (size_payload > 0)
			{
				printf("   Payload (%d bytes):\n", size_payload);
			}
			break;
		case IPPROTO_UDP:
			printf("   Protocol: UDP\n");
			udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);

			printf("   Src port: %d\n", ntohs(udp->src_port));
			printf("   Dst port: %d\n", ntohs(udp->dst_port));

			payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_udp);

			size_payload = ntohs(ip->ip_len) - (size_ip + size_udp);

			if (size_payload > 0) 
			{
				printf("   Payload (%d bytes): udp len : %d\n", size_payload, ntohs(udp->length) - size_udp);
			}
			else
				printf("   No Payload !!\n");
			return;
		case IPPROTO_ICMP:
			printf("   Protocol: ICMP\n");
			return;
		case IPPROTO_IGMP:
			printf("   Protocol: IGMP\n");
			return;
		case IPPROTO_IP:
			printf("   Protocol: IP\n");
			return;
		case IPPROTO_SCTP:
			printf("   Protocol: SCTP\n");
			return;
		case IPPROTO_ENCAP:
			printf("   Protocol: ENCAP\n");
			return;
		case IPPROTO_ICMPV6:
			printf("   Protocol: ICMPV6\n");
			return;
		default:
			printf("   Protocol: unknown : %d\n", ip->ip_p);
			return;
	}
	return;
}

void ipv6_routine(const struct ipv6 * ip, const u_char* packet)
{
	const struct sniff_tcp *tcp;            /* The TCP header */
	const struct sniff_udp *udp;            /* The UDP header */
	const char *payload;                    /* Packet payload */
	int size_ip = 40;
	int size_tcp;
	int size_udp = 8;
	int size_payload;

	printf("   IP Version : IPv%d\n", IP_V6(ip));	// msb of 1st byte as in little endian	

	/*	size_ip = IP_HL(ip)*4;
		if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
		}
	 */	
	char temp[INET6_ADDRSTRLEN];
	printf("       Source : %s\n", inet_ntop(AF_INET6, (const void*) &ip->src, temp, INET6_ADDRSTRLEN));
	printf("       Destination : %s\n", inet_ntop(AF_INET6, (const void*) &ip->dst, temp, INET6_ADDRSTRLEN));
	printf("   IPv6 payload length : %d\n", ip->length);
	printf("   IPv6 payload length converted : %d\n", ntohs(ip->length));

	switch(ip->next_header)
	{
		case IPPROTO_TCP:
			printf("   Protocol: TCP\n");
			tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
			size_tcp = TH_OFF(tcp)*4;
			if (size_tcp < 20) {
				printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
				return;
			}

			printf("   Src port: %d\n", ntohs(tcp->th_sport));
			printf("   Dst port: %d\n", ntohs(tcp->th_dport));

			payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

			size_payload = ntohs(ip->length) - size_tcp;

			if (size_payload > 0)
			{
				printf("   Payload (%d bytes):\n", size_payload);
			}
			break;
		case IPPROTO_UDP:
			printf("   Protocol: UDP\n");
			udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);

			printf("   Src port: %d\n", ntohs(udp->src_port));
			printf("   Dst port: %d\n", ntohs(udp->dst_port));

			payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_udp);

			size_payload = ntohs(ip->length) - (size_udp);

			if (size_payload > 0) 
			{
				printf("   Payload (%d bytes): udp len : %d\n", size_payload, ntohs(udp->length) - size_udp);
			}
			else
				printf("   No Payload !!\n");
			return;
		case IPPROTO_ICMP:
			printf("   Protocol: ICMP\n");
			return;
		case IPPROTO_IGMP:
			printf("   Protocol: IGMP\n");
			return;
		case IPPROTO_IP:
			printf("   Protocol: IP\n");
			return;
		case IPPROTO_SCTP:
			printf("   Protocol: SCTP\n");
			return;
		case IPPROTO_ENCAP:
			printf("   Protocol: ENCAP\n");
			return;
		case IPPROTO_ICMPV6:
			printf("   Protocol: ICMPV6\n");
			return;
		default:
			printf("   Protocol: unknown : %d\n", ip->next_header);
			return;
	}
	return;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	static int count = 1;                   /* packet counter */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct ipv4 *ip4;              /* The IP header */

	printf("\nPacket number %d:\n", count);
	count++;
	ethernet = (struct sniff_ethernet*)(packet);
	ip4 = (struct ipv4*)(packet + SIZE_ETHERNET);


	/////////////////////////////////////////////////////// Selection btween IPv6 and IPv4


	if (IP_V(ip4) == 4)		// if IPv4 === true
	{
		ipv4_routine(ip4, packet);
	}
	else					// if IPv6 == true
	{
		const struct ipv6 *ip6 = (struct ipv6*)(packet + SIZE_ETHERNET);
		ipv6_routine(ip6, packet);
	}
}

int main(int argc, char **argv)
{
	char *dev = NULL;                       /* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];          /* error buffer */
	pcap_t *handle;                         /* packet capture handle */
	int ret = 0;
	struct bpf_program fp;                  /* compiled filter program (expression) */
	bpf_u_int32 mask;                       /* subnet mask */
	bpf_u_int32 net;                        /* ip */
	int num_packets = atoi(argv[2]);              /* number of packets to capture */

/*	if (argc == 2) {
		dev = argv[1];
	}
	else if (argc > 2) {
		fprintf(stderr, "error: unrecognized command-line options\n\n");
		exit(EXIT_FAILURE);
	}
	else {
		
*/		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n",
					errbuf);
			exit(EXIT_FAILURE);
//		}
	}
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
				dev, errbuf);
		net = 0;
		mask = 0;
	}
	handle = pcap_open_offline(argv[1], errbuf);
	if (handle == NULL)
	{
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}
	ret = pcap_dispatch(handle, num_packets, got_packet, NULL);
	if (ret == -1)
	{
		perror("pcap_dispatch ()");
		exit(EXIT_FAILURE);
	}
	pcap_close(handle);
	printf("\nCapture complete.\n");
	return 0;
}


