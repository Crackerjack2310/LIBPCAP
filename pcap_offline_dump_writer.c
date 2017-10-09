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
#include <fcntl.h>
#include <unistd.h>


#define SNAP_LEN 1518
#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN	6
#define PACKSIZ	1518

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	static int count = 1;                   /* packet counter */
	int fd, count_packet;
	pcap_dumper_t *dumper;
	pcap_t *handle = (pcap_t*) args;
	dumper = pcap_dump_open_append(handle, "pcapfile.pcap");
	if (dumper== NULL)
	{
		perror("open_append failed :");
		exit(EXIT_FAILURE);
	}
	//void pcap_dump(u_char *user, struct pcap_pkthdr *h,u_char *sp)
	pcap_dump((u_char*)dumper, header, packet);
	printf("Total packets dumped to pcap file : %d\n", count);
	pcap_dump_close(dumper);
	count++;
}

int main(int argc, char **argv)
{
	system("rm -rf pcapfile.pcap");
	system("touch pcapfile.pcap");
	char *dev = NULL;			/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */

	char filter_exp[] = "ip";		/* filter expression [3] */
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	int num_packets = 10;			/* number of packets to capture */

	if (argc == 2) {
	dev = argv[1];
	}
	else if (argc > 2) {
		fprintf(stderr, "error: unrecognized command-line options\n\n");
		exit(EXIT_FAILURE);
	}
	else 
	{
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL)
		{
			fprintf(stderr, "Couldn't find default device: %s\n",
			    errbuf);
			exit(EXIT_FAILURE);
		}
	}
	
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
		    dev, errbuf);
		net = 0;
		mask = 0;
	}
	
	printf("Device: %s\n", dev);
	printf("Number of packets to capture : %d\n", num_packets);
	memset(errbuf, '\0', strlen(errbuf));
	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	if (handle == NULL) 
	{
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}
	if (strlen(errbuf))					// if errbuf has any warning messages for us
		printf("Warning message : %s\n", errbuf);
	if (pcap_datalink(handle) != DLT_EN10MB)
	{
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
	{
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}
	if (pcap_setfilter(handle, &fp) == -1)
	{
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}
	pcap_loop(handle, num_packets, got_packet, (u_char*) handle) ;
									/* cleanup */
	pcap_freecode(&fp);						// free up memory of bpf
	pcap_close(handle);

	printf("\nCapture complete.\n");

return 0;
}
