#include "definesToPartC.h"
unsigned short checksum(unsigned short *buf, int length);
void icmp_raw_packet(struct ipheader *ip);
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);


int main(){
	char errbuf[PCAP_ERRBUF_SIZE]; // error buffer
	pcap_t *handle;  // handle to device
	char *device = "br-bdcb435cfc0e"; // device to sniff on
	char *filter = "icmp"; // filter for icmp echo request
	struct bpf_program filter_exp;
	bpf_u_int32 net;  // ip address of device
	bpf_u_int32 mask;

	
	if (pcap_lookupnet(device, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
		    device, errbuf);
		
		mask = 0;
		net = 0;
	}
	handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Error opening device %s: %s\n", device, errbuf);
		return -1;
	}
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", device);
		return -1;
	}

	if (pcap_compile(handle, &filter_exp, filter, 0, net) == -1) {
		fprintf(stderr, "Error opening device %s: %s\n",
		    filter, pcap_geterr(handle));
		return -1;
	}

	
	if (pcap_setfilter(handle, &filter_exp) == -1) {
		fprintf(stderr, "Error compiling filter %s: %s\n",
		    filter, pcap_geterr(handle));
		return -1;
	}
	// Step 3: Capture packets
	pcap_loop(handle, -1, got_packet, NULL);
	pcap_close(handle); 
    pcap_freecode(&filter_exp);

    return 0;
}

unsigned short checksum(unsigned short *buf, int length)
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
    sum += (sum >> 16);                 // add carry
    return (unsigned short)(~sum);
}


/*
 * dissect/print packet
 */
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    
	struct ipheader *ip_2 = (struct ipheader *) (packet + sizeof(struct ether_header));	
	struct icmpheader *icmp_2 = (struct icmpheader *) (packet + sizeof(struct ether_header) + sizeof(struct ipheader));
    if(ip_2->iph_protocol != IPPROTO_ICMP){
      
      exit(1);
    }
    if(icmp_2->icmp_type == 8){
             char buffer[1500];
                memset(buffer, 0, 1500);

    // Step 1: Fill in the ICMP header.

    struct icmpheader *icmp = (struct icmpheader *)(buffer + sizeof(struct ipheader));
    
    icmp->icmp_chksum = 0;
    icmp->icmp_id = icmp_2->icmp_id;
    icmp->icmp_code = icmp_2->icmp_code;
  	icmp->icmp_type = 0; 
    icmp->icmp_seq = icmp_2->icmp_seq;
    icmp->icmp_chksum = checksum((unsigned short *)icmp,sizeof(struct icmpheader));
    
    // Step 2: Fill in the IP header.

    struct ipheader *ip = (struct ipheader *)buffer;
    struct in_addr fun ;

    ip->iph_sourceip.s_addr = ip_2->iph_destip.s_addr;
    ip->iph_destip.s_addr = fun.s_addr;
    ip->iph_protocol = IPPROTO_ICMP;
	fun.s_addr = ip_2->iph_sourceip.s_addr;
    ip->iph_ver = ip_2->iph_ver;
    ip->iph_ihl = ip_2->iph_ihl;
    ip->iph_ttl = ip_2->iph_ttl;
    ip->iph_len =  (htons(sizeof(struct ipheader) +sizeof(struct icmpheader)));
    ip->iph_chksum =checksum((unsigned short *)ip,sizeof(struct ipheader));
    char* sa = inet_ntoa(ip->iph_sourceip);
    printf("a:\n");
    printf("source_ip: %s",sa);
    char* da = inet_ntoa(ip->iph_sourceip);
    printf(", b: %s\n",da);
    icmp_raw_packet(ip);
    }
    
		
}
/****************************************************************** 
  Spoof an ICMP echo request using an arbitrary source IP Address
*******************************************************************/


void icmp_raw_packet(struct ipheader *ip)
{
	int enable = 1;
    struct sockaddr_in dest_info;
    int sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if(sock_fd==-1){
		printf("error creating socket\n");
		return;
	}
    setsockopt(sock_fd, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable)); 
	dest_info.sin_addr = ip->iph_destip;
    dest_info.sin_family = AF_INET;
    
    int send = sendto(sock_fd, ip, ntohs(ip->iph_len), 0,(struct sockaddr *)&dest_info, sizeof(dest_info));
    if (send == -1)
	{
		printf("error sending packet\n");
		return;
	}       
    close(sock_fd);
}
