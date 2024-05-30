// Program that work like origin "ping" with Timeout

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>

#include "defines.h"

char dest[16]; // destination address ,16 is the max length of IPv4 address
char end = '-'; // signal to end the watchdog 
int watchdog_sock = -1;
int pid;

int non_blocking(int sock);
ssize_t send_packet(int sock, void *buffer, int length);
ssize_t receive_packet(int sock, void *buffer, int lenght);
unsigned short calculate_checksum(unsigned short *paddress, int len);
ssize_t receiveICMP(int sock, void *response, int response_len, struct sockaddr_in *dest_in, socklen_t *lenght);
int main(int argc, char *argv[]);

/**
 * @brief The main function 
 * 
 *
 * @param argc number of arguments
 * @param argv arguments
 * @return int the error number 0 if no error
 */
 
int main(int argc, char *argv[])
{

	char *args[2];
	char packet[IP_MAXPACKET];	  // Buffer to hold the ICMP packet.
	char icmp_response[IP_MAXPACKET];  // Buffer to receive the ICMP response.
	char space[INET_ADDRSTRLEN];	  // Buffer to hold the IP address.
	char sign = '+';			 // sign to continue the watchdog


	// Varibles setup
	struct icmp icmph;
	struct iphdr *iphdr;
	struct icmphdr *icmphdr;
	struct sockaddr_in watchdog_address, dest_in;
	socklen_t addr_len;
	ssize_t bytes_received = 0;
	size_t datalen;
	int status;


	char data[IP_MAXPACKET] = "This is the ping \n"; // Data to be sent with the ICMP packet.
    datalen = (strlen(data) + 1);		// Calculate the length of the data.

	// Check the arguments passed to the program and check IP validity.
	if (argc != 2)
	{
		fprintf(stderr, "Usage: %s <destination>\n", argv[0]);
		exit(1);
	}
	memset(&dest_in, 0, sizeof(dest_in));
	if (inet_pton(AF_INET, argv[1], &dest_in.sin_addr) != 1) // Convert the IP address to binary form.
	{
		fprintf(stderr, "Invalid IP address: %s\n", argv[1]); // If the IP address is invalid, print an error message and exit.
		exit(1);
	}
	dest_in.sin_family = AF_INET; // Set the destination address family to IPv4.
	addr_len = sizeof(dest_in);	  // Set the size of the destination address.
	strcpy(dest, argv[1]); // Copy the destination address to a global variable.
	int socketfd = -1;
	if ((socketfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1) // Create a raw socket.
	{
		perror("socket");
		exit(errno);
	}
	non_blocking(socketfd);		   // Set the socket to non-blocking mode.
	icmph.icmp_type = ICMP_ECHO; // Set the ICMP type to ECHO.
	icmph.icmp_code = 0;		   // Set the ICMP code to 0.
	icmph.icmp_id = getpid();	   // Set the ICMP ID to the process ID.

	// Prepare the TCP socket with the watchdog program (default port 3000).
	memset(&watchdog_address, 0, sizeof(watchdog_address));
	watchdog_address.sin_family = AF_INET;
	watchdog_address.sin_port = htons(WATCHDOG_PORT);
	if (inet_pton(AF_INET, WATCHDOG_IP, &watchdog_address.sin_addr) == -1) // convert the IP address to binary form.
	{
		fprintf(stderr, "Invalid IP address: %s\n", WATCHDOG_IP);
		exit(1);
	}
	if ((watchdog_sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) // Create a TCP socket.
	{
		perror("socket");
		exit(errno);
	}

	// Passing the arguments needed to start the watchdog program and fork the process.
	args[0] = "./watchdog";
	args[1] = NULL;

	pid = fork();

	// In child process (watchdog).
	if (pid == 0)
	{
		// Executing the watchdog program.
		execvp(args[0], args);
		fprintf(stderr, "Error starting watchdog\n");
		perror("execvp"); // If the watchdog program failed to start, print an error message and exit.
		exit(errno);
	}

	else // In parent process (ping).
	{
		// Wait some time until the watchdog will prepare it's own TCP socket.
		usleep(WATCHDOG_TIMEOUT_IN_MS);

		// Check if watchdog is still running.
		if (waitpid(pid, &status, WNOHANG) != 0)
		{
			exit(1);
		}

		// Try to connect to the watchdog's socket.
		if (connect(watchdog_sock, (struct sockaddr *)&watchdog_address, sizeof(watchdog_address)) == -1)
		{
			perror("connect");
			exit(errno);
		}

		printf( "ping %s: %ld data bytes\n", argv[1], datalen); // Print the destination address and the data length.
		struct timeval start, end; // Start and end time of the ping.
		int counter = 0;
		float time = 0.0;


		while (true)
		{

			// Prepare the ICMP ECHO packet.

			bzero(packet, IP_MAXPACKET);
			// Calculate the ICMP checksum.
			icmph.icmp_cksum = 0;
			memcpy(packet, &icmph, ICMP_HDRLEN);		 // Copy the ICMP header to the packet.
			memcpy(packet + ICMP_HDRLEN, data, datalen); // Copy the data to the packet.
			icmph.icmp_cksum = calculate_checksum((unsigned short *)&packet, ICMP_HDRLEN + datalen);
			memcpy(packet, &icmph, ICMP_HDRLEN); // Copy the ICMP header to the packet.

			// Calculate starting time.
			gettimeofday(&start, NULL);

			// Send the ICMP ECHO packet to the destination address.
			ssize_t bytes_sent = sendto(socketfd, packet, ICMP_HDRLEN + datalen, 0, (struct sockaddr *)&dest_in, sizeof(dest_in));
			if (bytes_sent == -1)
			{
				fprintf(stderr, "sendto() failed with error: %d", errno);
				return -1;
			}
			// Wait and receive the ICMP ECHO REPLAY packet.
			bytes_received = receiveICMP(socketfd, icmp_response, sizeof(icmp_response), &dest_in, &addr_len);

			// Calculate ending time.
			gettimeofday(&end, NULL);

			// Send OK signal to watchdog.
			send_packet(watchdog_sock, &sign, sizeof(char));

			// Calculate the time it took to send and receive the packet
			time = (end.tv_sec - start.tv_sec) * 1000.0f + (end.tv_usec - start.tv_usec) / 1000.0f;

			// Extract the ICMP ECHO Replay headers via the IP header
			iphdr = (struct iphdr *)icmp_response;
			icmphdr = (struct icmphdr *)(icmp_response + iphdr->ihl * 4);

			inet_ntop(AF_INET, &(iphdr->saddr), space, INET_ADDRSTRLEN);

			// Print the packet data (total length, source IP address, ICMP ECHO REPLAY sequance number, IP Time-To-Live and the calculated time).
			printf("	%ld bytes from %s: icmp_seq=%d ttl=%d time=%0.3f ms\n",  bytes_received, space, counter++,iphdr->ttl,time);

			// Make the ping program sleep some time before sending another ICMP ECHO packet.
			usleep(PING_TIMEOUT_IN_MS); 
		}
	}

	close(watchdog_sock);
	close(socketfd);

	wait(&status); // waiting for child to finish before exiting
	printf("child exit status is: %d\n", status);

	return 0;
}

/**
 * @brief Function to set the socket to non-blocking mode.
 * @param socketfd
 * @return int 1 if sucsesfull else errno
 */
int non_blocking(int sock)
{
	int flag;
	if ((flag = fcntl(sock, F_GETFL, 0)) == -1) // Get the current flags of the socket file descriptor.
	{
		perror("fcntl");
		exit(errno);
	}
	// We set the flags include to a Non-Blocking I/O mode.
	flag |= O_NONBLOCK; // flags = flags | O_NONBLOCK

	// We set the new flags of the socket file descriptor.
	if ((flag = fcntl(sock, F_SETFL, flag)) == -1)
	{
		perror("fcntl");
		exit(errno);
	}

	return 1;
}

/**
 * @brief send_packet() sends a packet to the socket.
 * 
 * @param sock  - the socket to send the packet to.
 * @param buffer  - the buffer to send.
 * @param length - the length of the buffer.
 * @return ssize_t  -1 if failed, otherwise the number of bytes sent.
 */
ssize_t send_packet(int sock, void *buffer, int len)
{
	ssize_t s = send(sock, buffer, len, MSG_DONTWAIT);

	if (s == -1)
	{
		perror("send");
		exit(errno);
	}

	return s;
}

/**
 * @brief receive_packet() receives a packet from the socket.
 * 
 * @param sock  - the socket to receive the packet from.
 * @param buffer  - the buffer to receive the packet to.
 * @param length - the length of the buffer.
 * @return ssize_t  -1 if failed, otherwise the number of bytes received.
 */
ssize_t receive_packet(int socketfd, void *buffer, int len)
{
	ssize_t r = recv(socketfd, buffer, len, MSG_DONTWAIT);

	if (r == -1)
	{
		if (errno != EWOULDBLOCK)
		{
			perror("recv");
			exit(errno);
		}
	}

	return r;
}
/**
 * @brief receiveICMP() receives an ICMP ECHO REPLAY packet.
 * 
 * @param sock  - the socket to receive the packet from.
 * @param response  - the buffer to receive the packet to.
 * @param response_len  - the length of the buffer.
 * @param dest_in  - the destination address.
 * @param length  - the length of the destination address.
 * @return ssize_t  -1 if failed, otherwise the number of bytes received.
 */
ssize_t receiveICMP(int sock, void *response, int response_len, struct sockaddr_in *dest_in, socklen_t *length)
{
	ssize_t bytes_received = 0;

	bzero(response, IP_MAXPACKET); // Clear the buffer.

	while (bytes_received <= 0)
	{
		// Trying to receive an ICMP ECHO REPLAY packet.
		bytes_received = recvfrom(sock, response, response_len, 0, (struct sockaddr *)dest_in, length);

		if (bytes_received == -1)
		{
			// Filter Non-Blocking I/O.
			if (errno != EAGAIN)
			{
				perror("recvfrom");
				exit(errno);
			}

			// Check with watchdog if timeout passed.
			char sign = '\0'; // OK signal

			receive_packet(watchdog_sock, &sign, sizeof(char));

			if (sign == '-') // means timeout passed
			{
				printf("Server %s cannot be reached.\n", dest);
				close(watchdog_sock);
				exit(0);
			}
		}

		else if (bytes_received > 0) // We received an ICMP ECHO REPLAY packet.
			break;
	}

	return bytes_received;
}

/**
 * @brief calculate_checksum() calculates the checksum of the ICMP ECHO packet.
 *
 * @param paddress - the address of the ICMP ECHO packet.
 * @param len - the length of the ICMP ECHO packet.
 * @return unsigned short - the checksum of the ICMP ECHO packet.
 */
unsigned short calculate_checksum(unsigned short *paddress, int len)
{
	int nleft = len, sum = 0;
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
