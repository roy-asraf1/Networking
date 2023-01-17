#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <pcap.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <pcap/pcap.h>
#include <time.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

/* Ethernet header */
struct ethheader
{
	u_char ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* source host address */
	u_short ether_type;					/* IP? ARP? RARP? etc */
};

// ip header

struct ipheader
{
	unsigned char iph_ihl : 4,		 // IP header length
		iph_ver : 4;				 // IP version
	unsigned char iph_tos;			 // Type of service
	unsigned short int iph_len;		 // IP Packet length (data + header)
	unsigned short int iph_ident;	 // Identification
	unsigned short int iph_flag : 3, // Fragmentation flags
		iph_offset : 13;			 // Flags offset
	unsigned char iph_ttl;			 // Time to Live
	unsigned char iph_protocol;		 // Protocol type
	unsigned short int iph_chksum;	 // IP datagram checksum
	struct in_addr iph_sourceip;	 // Source IP address
	struct in_addr iph_destip;		 // Destination IP address
};

/* app header*/
struct appheader
{
	uint32_t timestamp;
	uint16_t total_length;
	union
	{
		uint16_t reserved : 3, cache_flag : 1, steps_flag : 1, type_flag : 1, status_code : 10;
		uint16_t flags;
	};

	uint16_t cache_control;
	uint16_t padding;
};
