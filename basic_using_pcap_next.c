#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <errno.h>

int main(int argc, char *argv[])
{
	char *dev, errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;		/* The compiled filter expression */
	char filter_exp[] = "ip";	/* The filter expression */
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) 
	{
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	printf("Device: %s\n", dev);
	pcap_t *handle;
	bpf_u_int32 mask;							/* The netmask of our sniffing device */
	bpf_u_int32 net;							/* The IP of our sniffing device */
	struct in_addr addr;
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) 
	{
		fprintf(stderr, "Can't get netmask for device %s\n", dev);
		net = 0;
		mask = 0;
	}
									/* changing to human readable form */
	addr.s_addr = net;
	printf("Got IP : %s\n", inet_ntoa(addr));
	addr.s_addr = mask;
	printf("Got MASK : %s\n", inet_ntoa(addr));
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) 
	{
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}
	printf("Got a valid handle !!\n");
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) 
	{
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	printf("pcap_compile success !!\n");
	if (pcap_setfilter(handle, &fp) == -1) 
	{
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	printf("Filter applied successfully !!\n");
	printf("Now listening for packets....\n");

											/* Grab a packet */
	if ((pcap_next(handle, &header)) == NULL)
	{
		fprintf(stderr, "pcap__next failed with error : %d\n", errno);
		return(2);
	}
	printf("Jacked a packet with length of [%d]\n", header.len);
											/* And close the session */
	pcap_close(handle);
	return(0);
}
