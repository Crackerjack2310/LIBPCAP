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

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet_arg)
{
	static int count = 1;                   /* packet counter */
	int fd, count_packet;
	fd = open("pcapfile.pcap", O_CREAT | O_RDWR | O_APPEND);
	if (fd == -1)
	{
		perror("opening packet file :");
		exit(EXIT_FAILURE);
	}
	count_packet = write(fd, packet_arg, PACKSIZ);
	if (count_packet == -1)
	{
		perror("writing to packet file :");
		exit(EXIT_FAILURE);
	}
	printf("Total packets wriiten to pcap file : %d\n", count);
	close(fd);
	count++;
}

int main(int argc, char **argv)
{
	system("rm -rf packet_file.pcap");
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
								/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(handle) != DLT_EN10MB)
	{
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}
									/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
	{
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}
									/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1)
	{
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}
									/* now we can set our callback function */
	pcap_loop(handle, num_packets, got_packet, NULL);
									/* cleanup */
	pcap_freecode(&fp);						// free up memory of bpf
	pcap_close(handle);

	printf("\nCapture complete.\n");

return 0;
}
