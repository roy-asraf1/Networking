// This program is the watchdog program for the safe_ping program.
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <time.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "defines.h"

ssize_t send_packet(int sock, void *buffer, int length);
ssize_t receive_packet(int sock, void *buffer, int length);
/**
 * @brief The main
 * The watchdog program will create a TCP socket and will listen to it. It will wait for a signal.
 * If it haven’t received any sign, it will increase by 1 his time and go to sleep for 1 second before checking again.
 * If it received an '+' sign, it will reset his timer, and go sleep for 1 second.
 * If it received an '-' sign, it will immediately shutdown.
 * 
 * 
 * @return int  0 if success, error number otherwise
 */

int main()
{
	/**
	 * @brief poll() performs a similar task to select(2): it waits for one of a set of file descriptors to become ready to perform I/O.
	 * The field fd contains a file descriptor for an open file. 
	 * If this field is negative, then the corresponding events field is ignored and the revents field returns zero.
	 * If none of the events requested (and no error) has occurred for any of the file descriptors, then poll() blocks until one of the events occurs.
	 * The timeout argument specifies the limit on the amount of time that poll() will block in this case.
	 * https://linux.die.net/man/2/poll
	 */

    struct pollfd fd; // poll() functionality
    int client_socket = -1;
    char sign = '\0';
    int time = 0, bytes_received = 0, result;
    int socket_server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket_server == -1)
    {
        printf("Could not create socket\n");
        return 1;
    }
    int enableReuse = 1;
    int ret = setsockopt(socket_server, SOL_SOCKET, SO_REUSEADDR, &enableReuse, sizeof(int));
    if (ret < 0) // if the socket is already in use
    {
        printf("setsockopt() failed with error code : %d\n", errno);
        return 1;
    }
    // creating the struct with the name and the address of the server
    struct sockaddr_in server_address;
    memset(&server_address, 0, sizeof(server_address));

    // saving the ipv4 type and the server port using htons to convert the server port to network's order
    server_address.sin_family = AF_INET;
    // allow any IP at this port to address the server
    server_address.sin_addr.s_addr = INADDR_ANY;
    server_address.sin_port = htons(WATCHDOG_PORT);

    // Bind the socket to the port with any IP at this port
    int bind_res = bind(socket_server, (struct sockaddr *)&server_address, sizeof(server_address));
    if (bind_res == -1)
    {
        printf("Bind failed with error code : %d\n", errno);
        close(socket_server);
        return -1;
    }

    // Make the socket listen.
    int listen_value = listen(socket_server, 3);
    if (listen_value == -1)
    {
        printf("listen() failed with error code : %d\n", errno);
        close(socket_server);
        return -1;
    }
    else
    {
        printf("Waiting for incoming connections...\n");
    }

    // Prepare the TCP socket with the ping program (default port 3000).
    struct sockaddr_in client_address;
    memset(&client_address, 0, sizeof(client_address));
    socklen_t lenClient = sizeof(client_address);

    // Accept the first connection request only.
    fd.fd = socket_server;
    fd.events = POLLIN;       // Check for incoming data.
    result = poll(&fd, 1, 1000); // Wait for 1 second.

    if (result == 0) // Timeout.
    {
        fprintf(stderr, "Watchdog internal error: please run better_ping.\n");
        exit(1);
    }
    else if (result == -1) // Error
    {
        perror("poll");
        exit(1);
    }

    else // We got a connection request.
        client_socket = accept(socket_server, (struct sockaddr *)&client_address, &lenClient);

    if (client_socket == -1) // Error.
    {
        printf("listen failed with error code : %d\n", errno);
        close(socket_server);
        return -1;
    }

    // Time functionality
    while (time < 10) // 10 seconds.
    {
        bytes_received = receive_packet(client_socket, &sign, sizeof(char));

        if (bytes_received > 0) //
        {
            // Error signal from the ping program - close EVERYTHING.
            if (sign == '-')
            {
                close(client_socket);
                close(socket_server);
                exit(1);
            }

            time = 0;
        }

        else if (bytes_received == -1) // we didn't get any data from the ping program - send a sign.
        {
            send_packet(client_socket, &sign, sizeof(char));
            time++;
        }

        sleep(1); // Sleep for 1 second.
    }

    /**
	 * 
     * sign + means that the ping program is alive.
	 * sign - means that the ping program is dead.
     * 
     */
    sign = '-'; // Send the error signal to the ping program.

    send_packet(client_socket, &sign, sizeof(char)); // Send the signal to the ping program.

    close(client_socket);
    close(socket_server);

    return 0;
}
/**
 * @brief send_packet() sends a packet to the socket.
 * 
 * @param sock  - the socket to send the packet to.
 * @param buffer  - the buffer to send.
 * @param length - the length of the buffer.
 * @return ssize_t  -1 if failed, otherwise the number of bytes sent.
 */
 

ssize_t send_packet(int sock, void *buffer, int length)
{

    ssize_t s = send(sock, buffer, length, MSG_DONTWAIT);

    if (s == -1)
    {
        printf("send() failed with error code : %d\n", errno);
        exit(errno);
    }

    return s;
}
/**
 * @brief receive_packet() receives a packet from the socket.
 * for tcp sockets, we can use the MSG_DONTWAIT flag to set the specific send/recv function to operate on on-blocking  mode.
 * @param sock  - the socket to receive the packet from.
 * @param buffer  - the buffer to receive the packet to.
 * @param length  - the length of the buffer.
 * @return ssize_t  -1 if failed, otherwise the number of bytes received.
 */

ssize_t receive_packet(int sock, void *buffer, int length)
{
    ssize_t r = recv(sock, buffer, length, MSG_DONTWAIT); // Non-Blocking socket.

    if (r == -1)
    {
        // Non-Blocking socket - no data to read.
        if (errno != EWOULDBLOCK) // EWOULDBLOCK - 11 - Operation would block.
        {
            printf("recv() failed with error code : %d\n", errno); // Error.
            exit(errno);
        }
    }

    return r;
}
