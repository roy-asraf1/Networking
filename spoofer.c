#include <netinet/tcp.h>
#include <stdlib.h>
#include <net/ethernet.h>
#include <getopt.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <arpa/inet.h> // for inet_ntoa()
#include <net/ethernet.h>
#include <string.h>
#include <sys/socket.h>
#include <stdio.h>
#include <netinet/ip.h>

/* IP Header */
struct ipheader
{
	unsigned char iph_ihl : 4;		 // IP header length
	unsigned char iph_ver : 4;		 // IP version
	unsigned char iph_tos;			 // Type of service
	unsigned short int ipacketh_len; // IP Packet length (data + header)
	unsigned short int iph_ident;	 // Identification
	unsigned short int iph_flag : 3; // Fragmentation flags
	unsigned short int iph_id;
	unsigned short int iph_offset : 13; // Flags offset
	unsigned char iph_ttl;				// Time to Live
	unsigned char iph_protocol;			// Protocol type
	unsigned short int iph_chksum;		// IP datagram checksum
	struct in_addr iph_sourceip;		// Source IP address
	struct in_addr iph_destip;			// Destination IP address
};
/* ICMP Header  */
struct icmpheader
{
	unsigned char icmp_type;		// ICMP message type
	unsigned char icmp_code;		// Error code
	unsigned short int icmp_chksum; // Checksum for ICMP Header and data
	unsigned short int icmp_id;		// Used for identifying request
	unsigned short int icmp_seq;	// Sequence number
};
void send_raw_ip_packet(struct ipheader *ip)
{
	struct sockaddr_in dest_info;
	int enable = 1;

	// Step 1: Create a raw network socket.
	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

	// Step 2: Set socket option.
	setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable)); // IP_HDRINCL to tell the kernel that headers are included in the packet

	// Step 3: Provide needed information about destination.
	dest_info.sin_family = AF_INET;
	dest_info.sin_addr = ip->iph_destip;

	// Step 4: Send the packet out.
	sendto(sock, ip, ntohs(ip->ipacketh_len), 0,
		   (struct sockaddr *)&dest_info, sizeof(dest_info));
	close(sock);
}
/* UDP Header */
struct udpheader
{
	u_int16_t udp_sport; /* source port */
	u_int16_t udp_dport; /* destination port */
	u_int16_t udp_ulen;	 /* udp length */
	u_int16_t udp_sum;	 /* udp checksum */
};

unsigned short in_checksum(unsigned short *buf, int length)
{
	unsigned short *w = buf;
	int nleft = length;
	int sum = 0;
	unsigned short temp = 0;

	/*
	 * The algorithm uses a 32 bit accumulator (sum), adds
	 * sequential 16 bit words to it, and at the end, folds back all
	 * the carry bits from the top 16 bits into the lower 16 bits.
	 */
	while (nleft > 1)
	{
		sum += *w++;
		nleft -= 2;
	}

	/* treat the odd byte at the end, if any */
	if (nleft == 1)
	{
		*(u_char *)(&temp) = *(u_char *)w;
		sum += temp;
	}

	/* add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
	sum += (sum >> 16);					// add carry
	return (unsigned short)(~sum);
}

/**********************
  Spoof an ICMP echo request using an arbitrary source IP Address
***********************/

void icmp()
{
	char buffer[1500];

	memset(buffer, 0, 1500);
	// Step 1: Fill in the ICMP header.
	struct icmpheader *icmp = (struct icmpheader *)(buffer + sizeof(struct ipheader));
	icmp->icmp_type = 8; // ICMP Type: 8 is request, 0 is reply.

	// Calculate the checksum for integrity
	icmp->icmp_chksum = 0;
	icmp->icmp_chksum = in_checksum((unsigned short *)icmp,
									sizeof(struct icmpheader));

	// Step 2: Fill in the IP header.

	struct ipheader *ip = (struct ipheader *)buffer;
	ip->iph_ver = 4;
	ip->iph_ihl = 5;
	ip->iph_ttl = 20;
	ip->iph_sourceip.s_addr = inet_addr("1.1.1.1");
	ip->iph_destip.s_addr = inet_addr("2.2.2.2");
	ip->iph_protocol = IPPROTO_ICMP;
	ip->ipacketh_len = htons(sizeof(struct ipheader) +
							 sizeof(struct icmpheader));

	// Step 3: Finally, send the spoofed packet
	send_raw_ip_packet(ip);
}

void udp()
{
	char buffer2[1500];
	memset(buffer2, 0, 1500);
	struct ipheader *ip = (struct ipheader *)buffer2;
	struct udpheader *udp = (struct udpheader *)(buffer2 + sizeof(struct ipheader));
	/*******************
	   Step 1: Fill in the UDP data field.
	 ********************/
	char *data2 = buffer2 + sizeof(struct ipheader) +
				  sizeof(struct udpheader);
	const char *msg2 = "Hello Server!\n";
	int data_len2 = strlen(msg2);
	strncpy(data2, msg2, data_len2);

	/*******************
	   Step 2: Fill in the UDP header.
	 ********************/
	udp->udp_sport = htons(5555);
	udp->udp_dport = htons(5555);
	udp->udp_ulen = htons(sizeof(struct udpheader) + data_len2);
	udp->udp_sum = 0; /* Many OSes ignore this field, so we do not
						 calculate it. */

	// ip header
	/* Code omitted here; same as that in (@Listing~\ref{snoof:list:icmpecho}@) */
	(*ip).iph_ver = 4;
	(*ip).iph_ihl = 5;
	(*ip).iph_ttl = 20;
	ip->iph_sourceip.s_addr = inet_addr("3.3.3.3");
	ip->iph_destip.s_addr = inet_addr("0.0.0.0");
	ip->iph_protocol = IPPROTO_UDP; // The value is 17.
	ip->ipacketh_len = htons(sizeof(struct ipheader) +
							 sizeof(struct udpheader) + data_len2);
	/*******************
	   Step 4: Finally, send the spoofed packet
	 ********************/
	send_raw_ip_packet(ip);
}
struct help_header
{
	u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t tcp_length;
};
void tcp()
{
	// Create a raw socket
	int newSocket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (newSocket == -1)
	{
		perror("We could not create a socket");
		exit(1);
	}
	// Datagram to represent the packet
	char buffer[4096], source_ip[32], *data, *pseudogram;
	memset(buffer, 0, 4096);
	// IP header
	struct iphdr *iph = (struct iphdr *)buffer;
	// TCP header
	struct tcphdr *tcph = (struct tcphdr *)(buffer + sizeof(struct ip));
	struct sockaddr_in sin;
	struct help_header psh;

	// Data part
	data = buffer + sizeof(struct iphdr) + sizeof(struct tcphdr);
	strcpy(data, "OREL_DAYAN_AND_ROY_ASRAF_HAYU_PO");
	strcpy(source_ip, "3.3.3.3");
	sin.sin_family = AF_INET;
	sin.sin_port = htons(80);
	sin.sin_addr.s_addr = inet_addr("1.1.1.1");
	// ip header
	iph->version = 4;
	iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + strlen(data);
	iph->id = htonl(11111); // id to the packet
	iph->frag_off = 0;
	iph->ttl = 255;
	iph->protocol = IPPROTO_TCP;
	iph->check = 0;
	iph->ihl = 5;
	// Set to 0 before calculating checksum
	// Spoof the source ip address
	iph->tos = 0;
	iph->saddr = inet_addr(source_ip);
	iph->daddr = sin.sin_addr.s_addr;
	// Ip checksum
	iph->check = in_checksum((unsigned short *)buffer, iph->tot_len);
	// TCP Header
	(*tcph).source = htons(1111);
	(*tcph).dest = htons(2222);
	(*tcph).seq = 0;
	(*tcph).ack_seq = 0;
	(*tcph).doff = 5; // tcp header size
	(*tcph).fin = 0;
	(*tcph).syn = 1;
	(*tcph).rst = 0;
	(*tcph).psh = 0;
	(*tcph).ack = 0;
	(*tcph).urg = 0;
	// maximum size
	(*tcph).window = htons(5840);
	(*tcph).check = 0;
	(*tcph).urg_ptr = 0;

	// tcp checksum
	psh.source_address = inet_addr(source_ip);
	psh.dest_address = sin.sin_addr.s_addr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons(sizeof(struct tcphdr) + strlen(data));
	int psize = sizeof(struct help_header) + sizeof(struct tcphdr) + strlen(data);
	pseudogram = malloc(psize);

	memcpy(pseudogram, (char *)&psh, sizeof(struct help_header));
	memcpy(pseudogram + sizeof(struct help_header), tcph, sizeof(struct tcphdr) + strlen(data));
	tcph->check = in_checksum((unsigned short *)pseudogram, psize);
	// IP_HDRINCL to tell the kernel that headers are included in the packet
	int one = 1;
	const int *val = &one;

	if (setsockopt(newSocket, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
	{
		perror("Error setting IP_HDRINCL");
		exit(0);
	}
	// Send the packet
	(sendto(newSocket, buffer, iph->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) ? perror("sendto failed") : printf("Packet Send. Length : %d \n", iph->tot_len); // Data send successfully
	// sleep for 1 seconds
	sleep(1);
}

// Can choose between icmp, udp and tcp packets

int main()
{
	// icmp();
	// udp();
	tcp();
	return 0;
}
