#include <sys/socket.h>
#include <sys/types.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>

#define SERVER_PORT 10003
#define SERVER_IP_ADDRESS "127.0.0.1"

int main()
{

    // we create a socket and then check for success
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

    // we build a struct holding the server address data and we initialize
    // the memory in this address
    struct sockaddr_in serverAddress;
    memset(&serverAddress, 0, sizeof(serverAddress)); 
    
    // we set the field to AF_INET
    serverAddress.sin_family = AF_INET;
    
    // we convert the server port into a Network Byte Order representation
    serverAddress.sin_port = htons(SERVER_PORT);
    
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
        return -1;
    }


    // in order to re-use the port we enter the following code
    int yes = 1;
    if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes , sizeof(yes)) == -1)
    {
        perror("setsockopt");
        exit(1);
    }


    // we bind the server address and port to the socket and check for success
    int didBind = bind(sock, (const struct sockaddr *)&serverAddress , sizeof(serverAddress));
    if(didBind == -1)
    {
        printf("Unsuccessfully binded\n");
        close(sock);
        return -1;
    }
    else
    {
        printf("Successful bind\n");
    }

    // the server is going into " waiting " mode and we check for success
    int didListen = listen(sock, 500);
    if(didListen == -1)
    {
        printf("Unseccessful attempt to listen\n");
    }
    else
    {
        printf("---------Waiting for TCP connection---------\n");
    }


    // we build a struct for the client address data and initialize the memory
    struct sockaddr_in client;
    socklen_t clientLen = sizeof(client);
    memset(&client , 0 , sizeof(client));
    clientLen = sizeof(client);


    // we request permission to connect from the queue of requests and check for succession
    int clientS = accept(sock, (struct sockaddr*)&client , &clientLen);
    if (clientS == -1)
    {
        printf("Unsuccessfull accept\n");
    }
    else
    {
        printf("New Connection\n");
    }


    // we will receive the message in two parts , the first half in cubic and the second half
    // in reno,and we measure the time it took for each half and store it in the corresponding
    // array

    // BUF array intended to divide the message we recieve from the sender into chunks
    // we declare two arrays to hold the times for each half of the message
    char BUF[5000];
    float timeFirstHalf[8] = {0};
    float timeSecondHalf[8] = {0};
    int timesFileReceived = 0;
    struct timeval firstHalfStartTime, firstHalfEndTime , secondHalfStartTime , secondHalfEndTime;
    while(1)
    {
        // the file size of the chosen file , we decrease it by the amount of bytes
        // we received in amount until it reaches zero and then we carry on
        int bufRend = 489576;

        // we get current starting time
        gettimeofday(&firstHalfStartTime, NULL);

        while (bufRend > 0)
        {
            // in amount we hold the amount of bytes received and we check for success
            int amount = recv(clientS , BUF , sizeof(BUF) , 0);
            printf("this is amount %d\n" , amount);
            if (amount > 0)
            {
                printf("Received %d bytes\n" , amount);
            }
            if (amount < 0)
            {
                printf("Failed to receive\n");
                return -1;
            }
            if (amount == 0)
            {
                printf("Connection closed\n");
                return -1;
            }
            bufRend = bufRend - amount;

            printf("This is amount left: %d\n" , bufRend);
        }

        // we get current ending time
        gettimeofday(&firstHalfEndTime , NULL);

        // in the array we store the time it took to receive the first half
        timeFirstHalf[timesFileReceived] = firstHalfEndTime.tv_usec - firstHalfStartTime.tv_usec;

        // we send back authentication that we received the message and check for success
        char xor [16] = {0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0};
        int xorlen = strlen(xor) + 1;
        int checkSend = send(clientS, xor, xorlen, 0);
        if (checkSend == -1)
        {
            printf("There Was An Error sending first half\n");
            return -1;
        }

        printf("First half of message was sent\n");

        // we change the CC algorithm to reno and check for success
        int changeCC = setsockopt(sock , IPPROTO_TCP , TCP_CONGESTION , "reno" , 4); 
        if(changeCC == 0)
        {
            printf("Successfully changed Congeston Control algorithm\n");
        }
        else
        {
            printf("Error changing CC algoithm");
            return -1;
        }

        printf("Preparing to get Second half of message\n");

        // we reset the buffer renderer to the amount we expect to get in the second
        // half of the message
        bufRend = 489576;

        // we get current starting time of the second half of the message
        gettimeofday(&secondHalfStartTime,NULL);

        while (bufRend > 0)
        {
            // in amount we hold the amount of bytes received and we check for success
            int amount = recv(clientS , BUF , sizeof(BUF) , 0);
            printf("this is amount %d of second half\n" , amount);
            if (amount > 0)
            {
                printf("Received %d bytes of second half\n" , amount);
            }
            if (amount < 0)
            {
                printf("Failed to receive of second half\n");
                return -1;
            }
            if (amount == 0)
            {
                printf("Connection closed of second half\n");
                return -1;
            }
            bufRend = bufRend - amount;

            printf("This is amount left: %d of second half\n" , bufRend);

        }
        
        // we get current ending time of the second half of the message
        gettimeofday(&secondHalfEndTime,NULL);

        // in the array we store the time it took to receive the second half
        timeSecondHalf[timesFileReceived] = secondHalfEndTime.tv_usec - secondHalfStartTime.tv_usec;

        // we send authentication back to the client ,  check for success
        checkSend = send(clientS, xor, xorlen, 0);
        if (checkSend == -1)
        {
            printf("There Was An Error sending second half\n");
            return -1;
        }

        printf("Authentication for second half was sent\n");

        // we change the CC algorithm to cubic and check for success
        changeCC = setsockopt(sock , IPPROTO_TCP , TCP_CONGESTION , "cubic" , 5);
        if(changeCC == 0)
        {
            printf("Successfully changed Congeston Control algorithm\n");
        }
        else
        {
            printf("Error changing CC algoithm");
            return -1;
        }

        
        // we expect the client to tell us if we want to resend or exit , check for success
        char message[5] = {0};
        int checkR = recv(clientS , message , sizeof(message) , 0);
        if(checkR < 0)
        {
            printf("Error receiving exit or continue message\n");
        }
        if (checkR == 0)
        {   
            printf("Error receiving exit or continue message connection closed\n");
        }


        // if the user sent the exit message we exit , if not we iterate through
        // the loop again
        char exit[] = {"EXIT"};
        int cmp = strcmp(exit,message);        
        if (cmp == 0)
        {
            break;
        }

        // this counter will count the amount of times we have received the whole message
        // and stores it in the corresponding spot in the array
        timesFileReceived++;
    }


    // we loop through each array and print the amount of time it took to receive
    // the first half and second half of the message
    for (int i = 0; i < timesFileReceived; i++)
    {
        printf("This is the %dth time\n" , i + 1);

        printf("The time it takes in milliseconds to receive the first half of the file: %f\n", timeFirstHalf[i]);
        printf("The time it takes in milliseconds to receive the second half of the file: %f\n", timeSecondHalf[i]);
    }
    

    // here we calculate the average time it took to receive the first half of the file
    // and the second half of the file seperatly
    float firstHalfAvg = 0;
    float secondHalfAvg = 0;

    for (int i = 0; i < timesFileReceived; i++)
    {
        firstHalfAvg += timeFirstHalf[i];
        secondHalfAvg += timeSecondHalf[i];
    }
    
    printf("The Average time for the first half in milliseconds is: %f\n" , firstHalfAvg/timesFileReceived);
    printf("The Average time for the seoncd half in milliseconds is: %f\n" , secondHalfAvg/timesFileReceived);

    printf("DONE\n");   


    // we close both sockets and end the program
    close(sock);
    close(clientS); 
    
    return 0;
}