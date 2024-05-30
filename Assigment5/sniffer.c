#include "defines.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void write_data(FILE *fp, const uint8_t *data, uint16_t length);
int main(int argc, char **argv);
int count = 1;

int main(int argc, char **argv)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	bpf_u_int32 net = 0;
	struct bpf_program fp;
	char filter_exp[] = "tcp";
	int status;

	printf("Starting sniffer\n");
	printf("Internet device : lo\n");

	handle = pcap_open_live("lo", BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL)
	{
		fprintf(stderr, "pcan open live error %s\n", errbuf);
		return -1;
	}

	status = pcap_compile(handle, &fp, filter_exp, 0, net);
	if (status == -1)
	{
		fprintf(stderr, "error compiling: %s\n", errbuf);
		return -1;
	}

	status = pcap_setfilter(handle, &fp);
	if (status == -1)
	{
		fprintf(stderr, "error setting filter: %s\n", errbuf);
		return -1;
	}

	pcap_loop(handle, -1, got_packet, NULL);

	pcap_close(handle);
	return 0;
}

void write_data(FILE *fp, const uint8_t *data, uint16_t length)
{
	for (int i = 0; i < length; i++)
	{
		if (!(i & 15))
		{
			fprintf(fp, "\n%04X: ", i);
		}
		fprintf(fp, "%02X ", data[i]);
	}
	fprintf(fp, "\n\n");
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

	printf("Packet number %d  Capture \n", count++);
	FILE *fp = NULL;
	fp = fopen("209452093_302211958.txt", "a+");
	if (fp == NULL)
	{
		perror("fopen");
	}


	char src_ip[16], dest_ip[16]; // 16 bytes for IPv4 address
	struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader)); // ip header
	inet_ntop(AF_INET, &(ip->iph_sourceip), src_ip, INET_ADDRSTRLEN); // convert ip address to string
	inet_ntop(AF_INET, &(ip->iph_destip), dest_ip, INET_ADDRSTRLEN); // convert ip address to string
	printf("Source IP: %s, Destination IP: %s\n", src_ip, dest_ip); // print ip address

	struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct ethheader) + ip->iph_ihl * 4);
	if (!tcp->psh)
	{
		return;
	}

	// Extract source and destination ports
	uint16_t src_port = ntohs(tcp->source);
	uint16_t dest_port = ntohs(tcp->dest);
	printf("The Source Port of data : %hu, Destination Port of data: %hu\n", src_port, dest_port);

	// Extract application header
	struct appheader *app = (struct appheader *)(packet + sizeof(struct ethheader) + ip->iph_ihl * 4 + tcp->doff * 4);
	uint32_t timestamp = ntohl(app->timestamp);
	uint16_t total_length = ntohs(app->total_length);
	app->flags = ntohs(app->flags);
	uint16_t cache_flag = ((app->flags >> 12) & 1);
	uint16_t steps_flag = ((app->flags >> 11) & 1);
	uint16_t type_flag = ((app->flags >> 10) & 1);
	uint16_t status_code = app->status_code;
	uint16_t cache_control = ntohs(app->cache_control);

	// Extract packet data
	uint8_t data[total_length];
	memcpy(data, (packet + sizeof(struct ethheader) + ip->iph_ihl * 4 + tcp->doff * 4 + 12), total_length);
	if (total_length >500)
	{
		fprintf(fp, "REQUEST:\n");
	}
	else
	{
		fprintf(fp, "RESPONSE:\n");
	}

	fprintf(fp, "Source IP: %s, Destination IP: %s, Source Port: %hu, \n"
				"Destination Port: %hu, Timestamp: %u, Total Length: %hu, Cache Flag: %hu, \n"
				"Steps Flag: %hu, Type Flag: %hu, Status Code: %hu, Cache Control: %hu, \n"
				"Data:\n",
			src_ip, dest_ip, src_port, dest_port, timestamp, total_length, cache_flag,
			steps_flag, type_flag, status_code, cache_control);

	write_data(fp, data, total_length);
	fclose(fp);
}
