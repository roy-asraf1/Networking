#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <inttypes.h>
#include <strings.h>
#include <stdio.h>

int main(int argc, char *argv[])
{

	int sockfd;
	int cc;
	socklen_t fsize;
	struct
	{
		char head;
		u_long body;
		char tail;
	} msgbuf;

	struct sockaddr_in s_in, from, send_out;
	bzero((char *)&s_in, sizeof(s_in));
	bzero((char *)&from, sizeof(from));

	sockfd = socket(AF_INET, SOCK_DGRAM, 0); // create socket for UDP connection with IPv4 protocol and UDP protocol
	//(SOCK_DGRAM) and no protocol (0) for default protocol (UDP) (IPv4) and return socket file descriptor
	// check that not failed to create socket
	if (sockfd < 0)
	{
		perror("socket");
		exit(1);
	}
	// initialize socket address structure s_in with IP address of host and port number P
	s_in.sin_family = AF_INET;		   // set family to internet (IPv4)
	s_in.sin_port = atoi(argv[2]);	   // set port number to struct (sin_port)
	s_in.sin_addr.s_addr = INADDR_ANY; // set address to struct (sin_addr)

	// bind socket to address s_in
	send_out.sin_family = AF_INET;		   // set family to internet (IPv4)
	send_out.sin_port = atoi(argv[3]);	   // set port number to struct (sin_port)
	send_out.sin_addr.s_addr = INADDR_ANY; // set address to struct (sin_addr)
	// check that not failed to bind socket to port
	if (bind(sockfd, (struct sockaddr *)&s_in, sizeof(s_in)) < 0)
	{
		perror("bind");
		exit(1);
	}

	srand(time(NULL)); // seed random number generator
	while (1)
	{
		fsize = sizeof(from);																 // set size of struct (from)
		bzero((char *)&msgbuf, sizeof(msgbuf));												 // set all bytes of struct (msgbuf) to 0
		cc = recvfrom(sockfd, &msgbuf, sizeof(msgbuf), 0, (struct sockaddr *)&from, &fsize); // receive datagram from socket
		if (cc < 0)																			 // check that not failed to receive datagram
		{
			perror("recvfrom");
			exit(1);
		}
		printf("Received datagram from %s:%d\n", inet_ntoa(from.sin_addr), ntohs(from.sin_port)); // print address and port of datagram sender
		if (((float)random()) / ((float)RAND_MAX) > 0.5)										  // check if random number is greater than 0.5
		{
			cc = sendto(sockfd, &msgbuf, sizeof(msgbuf), 0, (struct sockaddr *)&send_out, sizeof(send_out)); // send datagram to socket
			if (cc < 0)																						 // check that not failed to send datagram
			{
				perror("sendto");
				exit(1);
			}
		}
	}

	close(sockfd);

	return 0;
}
