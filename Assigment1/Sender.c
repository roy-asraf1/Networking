#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/tcp.h>
#include <unistd.h>

#define SERVER_PORT 10003
#define SERVER_IP_ADDRESS "127.0.0.1"

int main()
{

    // pointer to the file we want to send to the receiver and size.
    FILE *file1;
    int fileSize = 0;
    file1 = fopen("test.txt", "r");

    // We make sure we opened the file successfully

    if (file1 == NULL)
    {
        printf("Error opening file");
        return -1;
    }
    else
    {
        printf("Opened file successfully\n");
    }

    // In order to find the size of the file we loop through until we the end

    while (1)
    {
        char c = fgetc(file1);

        if (c == EOF)
        {
            break;
        }
        fileSize++;
    }

    // each array will hold half of the file we want to send
    char first_half[fileSize / 2];
    char second_half[fileSize / 2];

    // we close and re-open the file so the pointer will be adjusted correctly
    fclose(file1);
    file1 = fopen("test.txt", "r");

    for (int i = 0; i <= fileSize; i++)
    {
        char c = fgetc(file1);

        if (c == EOF)
        {
            break;
        }

        if (i < fileSize / 2)
        {
            first_half[i] = c;
        }
        else
        {
            second_half[i - fileSize / 2] = c;
        }
    }

    // creating a TCP socket using IPV4
    int sock = socket(AF_INET, SOCK_STREAM, 0);

    if (sock == -1)
    {
        printf("No socket was created");
        return -1;
    }
    else
    {
        printf("Socket Created\n");
    }

    struct sockaddr_in serverAddress;
    memset(&serverAddress, 0, sizeof(serverAddress)); // we initiliaze the memory at sin_zero

    serverAddress.sin_family = AF_INET;

    // we turn the server ip address from a binary sequence to a network representation
    // and then check if it worked

    int check = inet_pton(AF_INET, (const char *)SERVER_IP_ADDRESS, &serverAddress.sin_addr);
    if (check > 0)
    {
        printf("Successfully converted the address\n");
    }
    else
    {
        printf("Unsuccessfully converted the address\n");
        close(sock);
        return -1;
    }

    // we convert the server port into a Network Byte Order representation
    serverAddress.sin_port = htons(SERVER_PORT);


    // we connect the socket to the server and check if we have succeeded
    int didConnect = connect(sock, (struct sockaddr *)&serverAddress, sizeof(serverAddress));
    if (didConnect >= 0)
    {
        printf("Successfully connected\n");
    }
    else
    {
        printf("%d", didConnect);
        printf("Unsuccessfully connected\n");
        close(sock);
        return -1;
    }


    // in this while loop we send the first half of the file in a cubic CC algorithm
    // then we change the CC algorithm to reno and send the second half. After sending
    // each part we expect to receive authentication from the server and we ask the
    // user to input 1/0 to see if we should send the files again or exit the program,
    // Sending an exit message to the server.

    int timesSent = 0;
    int d = 1;
    while(d)
    {
        // we send the first half of the message and check for success

        int first_half_len = strlen(first_half) + 1;       
            int bytesSent = send(sock, first_half, first_half_len, 0);
            if (bytesSent > 0)
            {
                printf("Successfully sent\n");
                printf("bytes sent: %d\n" , bytesSent);
            }
            else
            {
                printf("Unsuccessfully sent\n");
                close(sock);
                return -1;
            }
            if (first_half_len > bytesSent)
            {
                printf("sent only %d of %d\n", bytesSent, first_half_len);
                close(sock);
                return -1;
            }
        

        // we receive from the server authentication and compare it to the
        // authentication array
        char xor [16] = {0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0};
        char buf[16] = {0};
        int authen = recv(sock, buf, sizeof(xor) + 1, 0);

        if (authen < 0)
        {
            printf("Unsuccessfully recieved");
            close(sock);
            return -1;
        }
        else if (authen == 0)
        {
            printf("Not able to receive because the connection has been closed");
            close(sock);
            return -1;
        }
        else
        {
            int isEqual = strcmp(xor, buf);
            if (isEqual == 0)
            {
                printf("Authentication Success\n");
            }
            else
            {
                printf("Authentication Failed");
                close(sock);
                return -1;
            }
        }


        // we change the CC algorithm to reno and check for success
        int checkCongestionChange = setsockopt(sock, IPPROTO_TCP, TCP_CONGESTION, "reno", 4);
        if (checkCongestionChange == 0)
        {
            printf("Successfully changed Congestion Control algorithm\n");
        }
        else
        {
            printf("Unsuccessfully changed Congestion Control algorithm\n");
            close(sock);
            return -1;
        }


        // we send the second half of the message and check for success
        int second_half_len = strlen(second_half) + 1;
        int bytesSent2 = send(sock, second_half, second_half_len, 0);

        if (bytesSent2 > 0)
        {
            printf("Successfully sent second half\n");
        }
        else
        {
            printf("Unsuccessfully sent second half\n");
            return -1;
        }
        if (second_half_len > bytesSent2)
        {
            printf("sent only %d of %d\n", bytesSent2, second_half_len);
            close(sock);
            return -1;
        }

        // we receive from the server authentication and compare it to the
        // authentication array
        authen = recv(sock, buf , sizeof(xor) , 0);
        if (authen < 0)
        {
            printf("Unsuccessfully recieved");
            close(sock);
            return -1;
        }
        else if (authen == 0)
        {
            printf("Not to able receive because the connection has been closed");
            close(sock);
            return -1;
        }
        else
        {
            int isEqual = strcmp(xor, buf);
            if (isEqual == 0)
            {
                printf("Authentication Success second half\n");
            }
            else
            {
                printf("Authentication Failed second half\n");
                close(sock);
                return -1;
            }
        }


        // we ask the user if he would like to send again , if so we tell the server
        // we would like to keep on going, if not we send him an exit message
        // and exit the loop, unless the user sent the file more then 7 times
        // we force-exit

        if(timesSent >= 6)
        {
            printf("You have sent the maximum amount of times , now exiting\n");
            d = 0;
        }
        else
        {
            printf("Do you want to send again 1/0\n");
            scanf("%d", &d);
        }
        
        if(d == 0)
        {
            printf("Sending Exit Message\n");
            char exit[] = {"EXIT"};
            int exitMessage = send(sock , exit , strlen(exit) , 0);
            if(exitMessage <= 0)
            {
                printf("Error sending exit message\n");
                close(sock);
                return -1;
            }
        }
        else
        {
            char keepOn[] = {"OKAY!"};
            int keepOnMessage = send(sock , keepOn , strlen(keepOn) , 0);
            if(keepOnMessage <= 0)
            {
                printf("Error sending keep on message\n");
                close(sock);
                return -1;
            }
            printf("Resending file\n");
        }


        timesSent++;
    }

    // we close the socket
    close(sock);
    return 0;
}