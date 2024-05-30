# File Transfer over TCP with Congestion Control
This repository contains two C programs that demonstrate file transfer over TCP with dynamic congestion control algorithms. The sender splits a file into two halves and sends each half using a different congestion control algorithm. The receiver times the transfers and verifies the received data.

## Prerequisites
Ensure you have the necessary libraries installed:

bash
Copy code
sudo apt-get install build-essential
## Files
- sender.c: This program reads a file, splits it into two halves, and sends each half to the receiver. It changes the TCP congestion control algorithm between the halves.
- receiver.c: This program receives the two halves of the file, measures the time taken for each half, and verifies the data.
## How to Compile
Compile the sender and receiver programs using gcc:

gcc -o sender sender.c
gcc -o receiver receiver.c

## How to Run
- Start the receiver program:
./receiver

In another terminal, start the sender program:
./sender
### sender.c
This program performs the following steps:

- Opens the file test.txt and reads its contents.
- Splits the file into two halves.
- Creates a TCP socket and connects to the receiver.
- Sends the first half of the file using the default congestion control algorithm (CUBIC).
- Receives authentication from the receiver.
- Changes the congestion control algorithm to reno.
- Sends the second half of the file.
- Receives authentication from the receiver.
- Repeats the process based on user input or exits after 7 attempts.
### receiver.c
This program performs the following steps:

- Creates a TCP socket and binds it to a port.
- Listens for incoming connections.
- Accepts a connection from the sender.
- Receives the first half of the file and measures the time taken.
- Sends authentication to the sender.
- Changes the congestion control algorithm to reno.
- Receives the second half of the file and measures the time taken.
- Sends authentication to the sender.
- Repeats the process based on sender's instruction or exits.
### Notes
- Ensure the file test.txt exists in the same directory as the sender.c program.
- The server (receiver) runs on 127.0.0.1 and listens on port 10003.
- Modify the SERVER_IP_ADDRESS and SERVER_PORT definitions in both programs if necessary.
### License
- This project is licensed under the MIT License.
