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
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <netinet/tcp.h>

int seq =0;
typedef __u_char u_char;

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518
/* IP Header */
struct ipheader
{
    unsigned char       iph_ihl : 4,    // IP header length
                        iph_ver : 4;    // IP version
    unsigned char       iph_tos;        // Type of service
    unsigned short int  iph_len;        // IP Packet length (data + header)
    unsigned short int  iph_ident;      // Identification
    unsigned short int  iph_flag : 3,   // Fragmentation flags        
                        iph_offset : 13;// Flags offset
    unsigned char       iph_ttl;        // Time to Live 
    unsigned char       iph_protocol;   // Protocol type
    unsigned short int  iph_chksum;     // IP datagram checksum
    struct in_addr      iph_sourceip;   // Source IP address
    struct in_addr      iph_destip;     // Destination IP address
};
/* ICMP Header  */
struct icmpheader
{
    unsigned char icmp_type;        // ICMP message type
    unsigned char icmp_code;        // Error code
    unsigned short int icmp_chksum; // Checksum for ICMP Header and data
    unsigned short int icmp_id;     // Used for identifying request
    unsigned short int icmp_seq;    // Sequence number
    unsigned short int time;
};
