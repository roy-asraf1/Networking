#include "definesToPartC.h"

void packet_to_spoof(struct ipheader *ip_packet);
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
int main(int argc, char *argv[]);

int main(int argc, char *argv[])
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	char *device = "enp0s3";
	char *filter = "icmp[icmptype] = icmp-echo";
	struct bpf_program filter_exp;
	bpf_u_int32 net = 0;
	printf("Starting sniffer\n");
	printf("Internet device : enp0s3 \n");

	handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL)
	{
		fprintf(stderr, "pcan open live error %s\n", errbuf);
		return -1;
	}

	if (pcap_compile(handle, &filter_exp, filter, 0, net) == -1)
	{
		fprintf(stderr, "error compiling: %s\n", errbuf);
		return -1;
	}

	if (pcap_setfilter(handle, &filter_exp) == -1)
	{
		fprintf(stderr, "error setting filter: %s\n", errbuf);
		return -1;
	}
	pcap_loop(handle, -1, got_packet, NULL);
	pcap_close(handle);
	return 0;
}

void packet_to_spoof(struct ipheader *ip_packet)
{
	struct sockaddr_in dest;
	int enable = 1;
	// sock creation
	int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sockfd == -1)
	{
		printf("error creating socket\n");
		return;
	}

	setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));

	// information about dest
	dest.sin_family = AF_INET;
	dest.sin_addr = ip_packet->dest_ip;

	// sends packet
	int send = sendto(sockfd, ip_packet, ntohs(ip_packet->ip_len), 0, (struct sockaddr *)&dest, sizeof(dest));
	if (send == -1)
	{
		printf("error sending packet\n");
		ip_packet->ip_ver = 4;
		ip_packet->ip_ihl = 5;
		return;
	}
	prinf("packet sent\n");
	close(sockfd);
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

	struct ethheader *ether_packet = (struct ethheader *)packet;
	struct ipheader *ip_packet;
	ip_packet = (struct ipheader *)(packet +sizeof(struct ethheader);
    char buffer[1500];
    memset((char *)buffer, 0, 1500);
    memcpy((char *)buffer, ip_packet, ntohs(ip_packet->ip_len));

    struct ipheader *ip_spoof = (struct ipheader *)buffer;
    struct icmpheader *icmp_spoof = (struct icmpheader *)(buffer + (ip_packet->ip_ihl * 4));

    ip_spoof->source_ip = ip_packet->dest_ip;
    ip_spoof->dest_ip = ip_packet->source_ip;
    ip_spoof->ip_ttl = 64;
    icmp_spoof->type = 0;

    packet_to_spoof(ip_spoof);
}
