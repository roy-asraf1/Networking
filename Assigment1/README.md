# Computer-Networking-1
----Send packets to yourself using TCP protocols----

In this project we read a file with a size close to 1MB , the file must be inside the project folder and name given in the code itself.
We use a buffer to send it to the receiver that slowly reads the file , we start measuring the time before we start receiving the first half of the message
then we change the congestion control algorithm from its default and measure the time it took to receive the second half.

Finally we output to the user the time it took to receive each half using the different algorithms and the average amount of time it took.

Note: the amount of times we resend the same package cannot be greater then 7
