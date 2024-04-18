WIREVIEW - PROJECT #1
---------------------

To compile the program use "make" or "make all". This should result in the program compiling. 

To remove the executable file run "make clean". This should remove the executable file. 

RUNNING THE PROGRAM:
To run the program follow this format: ./wireview <pcap_file_name>.pcap

After running this program the results will print in the terminal. 

The results should appear like the format that is shown below:
===============================================================
Start date and time of packet capture: 2007-01-23 04:14:14
Duration of packet capture: 0.076439 seconds 
Total number of packets: 4
Average packet size: 196.25 bytes
Minimum packet size: 0 bytes 
Maximum packet size: 366 bytes 

Ethernet Senders:
MAC Address        | Packet Count      | Type
------------------------------------------------
0:16:6f:42:56:7    | 2                 | Sender
0:14:bf:37:97:cd   | 2                 | Sender

Ethernet Receivers:
MAC Address        | Packet Count      | Type
------------------------------------------------
0:14:bf:37:97:cd   | 2                 | Receiver
0:16:6f:42:56:7    | 2                 | Receiver

IP Senders:
IP Address      | Packet Count    | Type
------------------------------------------------
192.168.1.102   | 2               | Sender
74.128.18.212   | 2               | Sender

IP Receivers:
IP Address      | Packet Count    | Type
------------------------------------------------
74.128.18.212   | 2               | Receiver
192.168.1.102   | 2               | Receiver

ARP Machines:
MAC Address        | IP Address     
---------------------------------

UDP Source Ports:
Port       | Packet Count
-------------------------
1319       | 2
53         | 2

UDP Destination Ports:
Port       | Packet Count
-------------------------
53         | 2
1319       | 2

IPv6 Senders:
MAC Address        | Packet Count     
------------------------------------------------

IPv6 Receivers:
MAC Address        | Packet Count     
------------------------------------------------

===============================================================

It can be seen that there are no entries for ARP Machines, nor IPv6 Senders and Receivers, this is because there are no packets which follow these protocols. 

IN THIS PROGRAM IF THERE ARE CERTAIN PROTOCOLS THAT AREN'T FOLLOWED THEN EMPTY TABLES ARE PRINTED. 

IMPORTANT NOTE:
In the event that the appropriate numbers are not printed then open wireview.c and change the following values by a factor of *2.

#define MAX_SENDERS 10000
#define MAX_RECEIVERS 10000
#define MAX_ENTRIES 10000
#define MAX_PORTS 10000
#define MAX_IPV6_ENTRIES 10000

After this the correct number of entries should be printed. I wanted to implement dynamic resizing in C but was getting segmentation faults and other errors when running my program with large file sizes. 

If there are any issues with the program please let me know. 