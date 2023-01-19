#include "definesToPartC.h"

void icmp_raw_packet(struct ipheader *ip_packet);
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
unsigned short calculate_checksum(unsigned short *paddress, int len);
int main(int argc, char *argv[]);

int main(int argc, char *argv[])
{

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	char *device = "enp0s3";						 // internet device
	char *filter_exp = "icmp[icmptype] = icmp-echo"; // filter
	struct bpf_program filter_exp;					 // filter
	bpf_u_int32 net = 0;
	printf("Starting sniffer\n");
	printf("Internet device : %s\n", device);
	printf("Filter : %s\n", filter_exp);
	handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL)
	{
		fprintf(stderr, "Error opening device: %s\n", errbuf);
		return -1;
	}

	if (pcap_compile(handle, &filter_exp, filter_exp, 0, net) == -1)
	{
		fprintf(stderr, "Error compiling filter: %s\n", pcap_geterr(handle));
		return -1;
	}

	if (pcap_setfilter(handle, &filter_exp) == -1)
	{
		fprintf(stderr, "Error setting filter: %s\n", pcap_geterr(handle));
		return -1;
	}
	pcap_loop(handle, -1, got_packet, NULL);
	pcap_close(handle);
	return 0;
}
/**
 * @brief icmp raw packet
 *
 * @param ip_packet pointer to ip header
 */

void icmp_raw_packet(struct ipheader *ip_packet)
{

	int enable = 1;
	int sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sock_fd == -1)
	{
		printf("error creating socket\n");
		return;
	}

	setsockopt(sock_fd, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));

	struct sockaddr_in dest;
	dest.sin_family = AF_INET;
	dest.sin_addr = ip_packet->dest_ip;
	dest.sin_port = 0;
	int send = sendto(sock_fd, ip_packet, ntohs(ip_packet->ip_len), 0, (struct sockaddr *)&dest, sizeof(dest));
	if (send == -1)
	{
		printf("error sending packet\n");
		ip_packet->ip_ver = 4;
		ip_packet->ip_ihl = 5;
		return;
	}
	close(sock_fd);
}
/**
 * @brief Calculate checksum
 *
 * @param paddress  pointer to address
 * @param len length of packet
 * @return unsigned short checksum
 */

unsigned short calculate_checksum(unsigned short *paddress, int len)
{
	int nleft = len;
	int sum = 0;
	unsigned short *w = paddress;
	unsigned short answer = 0;

	while (nleft > 1)
	{
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1)
	{
		*((unsigned char *)&answer) = *((unsigned char *)w);
		sum += answer;
	}

	// add back carry outs from top 16 bits to low 16 bits
	sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
	sum += (sum >> 16);					// add carry
	answer = ~sum;						// truncate to 16 bits

	return answer;
}
/**
 * @brief got packet
 *
 * @param args pointer to arguments
 * @param header pointer to header
 * @param packet pointer to packet
 */
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	struct ethheader *ether_packet = (struct ethheader *)packet;														 // pointer to ethernet header
	struct ipheader *ip_packet;																							 // pointer to ip header
	ip_packet = (struct ipheader *)(packet + sizeof(struct ethheader));													 // pointer to ip header
	struct icmpheader *icmp_packet = (struct icmpheader *)(packet + sizeof(struct ethheader) + sizeof(struct ipheader)); // pointer to icmp header
	// ask tomorow if  the if is needed
	if (icmp_packet->type == ICMP_ECHO) // if packet is echo request

	{

		char buf[1500];											  // buffer for ip packet
		memset((char *)buf, 0, 1500);							  // clear buffer
		memcpy((char *)buf, ip_packet, ntohs(ip_packet->ip_len)); // copy ip packet to buffer

		struct ipheader *ip_spoof = (struct ipheader *)buf;													  // pointer to ip header in buffer
		struct icmpheader *icmp_spoof = (struct icmpheader *)(buf + sizeof(struct ipheader));				  // pointer to icmp header in buffer
		icmp_spoof->type = 0;																				  // change type to echo reply
		ip_spoof->source_ip = ip_packet->dest_ip;															  // change source ip to destination ip
		ip_spoof->dest_ip = ip_packet->source_ip;															  // change destination ip to source ip
		ip_spoof->ip_checksum = 0;																			  // set checksum to 0
		icmp_spoof->checksum = 0;																			  // set checksum to 0
		ip_spoof->ip_checksum = (calculate_checksum((unsigned short *)ip_spoof, sizeof(struct ipheader)));	  // calculate checksum for ip header
		icmp_spoof->checksum = (calculate_checksum((unsigned short *)icmp_spoof, sizeof(struct icmpheader))); // calculate checksum for icmp header

		icmp_raw_packet(ip_spoof); // send packet
	}
}
