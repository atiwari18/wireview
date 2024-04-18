#include <stdio.h>
#include <pcap.h>
#include <sys/time.h>
#include <limits.h>
#include <time.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <string.h>
#include <netinet/udp.h>

#define MAX_SENDERS 10000
#define MAX_RECEIVERS 10000
#define MAX_ENTRIES 10000
#define MAX_PORTS 10000
#define MAX_IPV6_ENTRIES 10000

struct network_entry {
    char mac[25]; // MAC address in hex-colon notation
    char ip[INET_ADDRSTRLEN]; // IP address in dotted decimal notation
    int count; // Packet count
};

struct arp_entry {
    char mac[25]; // MAC address in hex-colon notation
    char ip[INET_ADDRSTRLEN]; // IP address in dotted decimal notation
};

struct port_entry {
    int port_number;
    int count;
};

struct ipv6_entry {
    char mac[25]; // MAC address in hex-colon notation
    int count; // Packet count
};

struct statistics {
    double start_time;
    double end_time;
    int total_packets;
    long long total_size;
    int min_size;
    int max_size;
    struct network_entry senders_eth[MAX_SENDERS];
    struct network_entry receivers_eth[MAX_RECEIVERS];
    struct network_entry senders_ip[MAX_SENDERS];
    struct network_entry receivers_ip[MAX_RECEIVERS];
    struct arp_entry arp_machines[MAX_ENTRIES];
    int num_senders_eth;
    int num_receivers_eth;
    int num_senders_ip;
    int num_receivers_ip;
    int num_arp_machines;
    struct port_entry source_ports[MAX_PORTS];
    struct port_entry dest_ports[MAX_PORTS];
    int num_source_ports;
    int num_dest_ports;
    struct ipv6_entry ipv6_senders[MAX_IPV6_ENTRIES];
    struct ipv6_entry ipv6_receivers[MAX_IPV6_ENTRIES];
    int num_ipv6_senders;
    int num_ipv6_receivers;
};

void process_ethernet_ip(struct statistics *stats, const struct pcap_pkthdr *header, const u_char *packet) {
    // Parse Ethernet header
    struct ether_header *eth_header = (struct ether_header *)packet;

    // Convert sender MAC address to ASCII
    char sender_mac[18];
    sprintf(sender_mac, "%s", ether_ntoa((struct ether_addr *)eth_header->ether_shost));

    // Convert receiver MAC address to ASCII
    char receiver_mac[18];
    sprintf(receiver_mac, "%s", ether_ntoa((struct ether_addr *)eth_header->ether_dhost));

    // Check if the packet contains an IPv4 header
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        // Parse IP header
        struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));

        // Convert sender IP address to ASCII
        char sender_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_header->ip_src), sender_ip, INET_ADDRSTRLEN);

        // Convert receiver IP address to ASCII
        char receiver_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_header->ip_dst), receiver_ip, INET_ADDRSTRLEN);

        // Check if entry already exists in the Ethernet sender list
        int entry_index = -1;
        for (int i = 0; i < stats->num_senders_eth; i++) {
            if (strcmp(stats->senders_eth[i].mac, sender_mac) == 0) {
                entry_index = i;
                break;
            }
        }
        if (entry_index == -1 && stats->num_senders_eth < MAX_SENDERS) {
            // Add new entry for sender in Ethernet sender list
            strcpy(stats->senders_eth[stats->num_senders_eth].mac, sender_mac);
            stats->senders_eth[stats->num_senders_eth].count = 1;
            stats->num_senders_eth++;
        } else if (entry_index != -1) {
            // Increment count for existing sender in Ethernet sender list
            stats->senders_eth[entry_index].count++;
        }

        // Check if entry already exists in the Ethernet receiver list
        entry_index = -1;
        for (int i = 0; i < stats->num_receivers_eth; i++) {
            if (strcmp(stats->receivers_eth[i].mac, receiver_mac) == 0) {
                entry_index = i;
                break;
            }
        }
        if (entry_index == -1 && stats->num_receivers_eth < MAX_RECEIVERS) {
            // Add new entry for receiver in Ethernet receiver list
            strcpy(stats->receivers_eth[stats->num_receivers_eth].mac, receiver_mac);
            stats->receivers_eth[stats->num_receivers_eth].count = 1;
            stats->num_receivers_eth++;
        } else if (entry_index != -1) {
            // Increment count for existing receiver in Ethernet receiver list
            stats->receivers_eth[entry_index].count++;
        }

        // Check if entry already exists in the IP sender list
        entry_index = -1;
        for (int i = 0; i < stats->num_senders_ip; i++) {
            if (strcmp(stats->senders_ip[i].ip, sender_ip) == 0) {
                entry_index = i;
                break;
            }
        }
        if (entry_index == -1 && stats->num_senders_ip < MAX_SENDERS) {
            // Add new entry for sender in IP sender list
            strcpy(stats->senders_ip[stats->num_senders_ip].ip, sender_ip);
            stats->senders_ip[stats->num_senders_ip].count = 1;
            stats->num_senders_ip++;
        } else if (entry_index != -1) {
            // Increment count for existing sender in IP sender list
            stats->senders_ip[entry_index].count++;
        }

        // Check if entry already exists in the IP receiver list
        entry_index = -1;
        for (int i = 0; i < stats->num_receivers_ip; i++) {
            if (strcmp(stats->receivers_ip[i].ip, receiver_ip) == 0) {
                entry_index = i;
                break;
            }
        }
        if (entry_index == -1 && stats->num_receivers_ip < MAX_RECEIVERS) {
            // Add new entry for receiver in IP receiver list
            strcpy(stats->receivers_ip[stats->num_receivers_ip].ip, receiver_ip);
            stats->receivers_ip[stats->num_receivers_ip].count = 1;
            stats->num_receivers_ip++;
        } else if (entry_index != -1) {
            // Increment count for existing receiver in IP receiver list
            stats->receivers_ip[entry_index].count++;
        }
    }
}

void process_arp(struct statistics *stats, const struct pcap_pkthdr *header, const u_char *packet) {
    // Parse Ethernet header to check if it's an ARP packet
    struct ether_header *eth_header = (struct ether_header *)packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_ARP) {
        // Not an ARP packet, ignore
        return;
    }

    // Parse ARP header
    struct ether_arp *arp_header = (struct ether_arp *)(packet + sizeof(struct ether_header));

    // Convert sender MAC address to ASCII
    char sender_mac[18];
    sprintf(sender_mac, "%02x:%02x:%02x:%02x:%02x:%02x",
            arp_header->arp_sha[0], arp_header->arp_sha[1], arp_header->arp_sha[2],
            arp_header->arp_sha[3], arp_header->arp_sha[4], arp_header->arp_sha[5]);

    // Convert target MAC address to ASCII
    char target_mac[18];
    sprintf(target_mac, "%02x:%02x:%02x:%02x:%02x:%02x",
            arp_header->arp_tha[0], arp_header->arp_tha[1], arp_header->arp_tha[2],
            arp_header->arp_tha[3], arp_header->arp_tha[4], arp_header->arp_tha[5]);

    // Convert sender IP address to ASCII
    char sender_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, arp_header->arp_spa, sender_ip, INET_ADDRSTRLEN);

    // Convert target IP address to ASCII
    char target_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, arp_header->arp_tpa, target_ip, INET_ADDRSTRLEN);

    // Check if entry already exists in the ARP list for sender
    int entry_index = -1;
    for (int i = 0; i < stats->num_arp_machines; i++) {
        if (strcmp(stats->arp_machines[i].mac, sender_mac) == 0 && strcmp(stats->arp_machines[i].ip, sender_ip) == 0) {
            entry_index = i;
            break;
        }
    }
    if (entry_index == -1 && stats->num_arp_machines < MAX_ENTRIES) {
        // Add new entry for sender in ARP list
        strcpy(stats->arp_machines[stats->num_arp_machines].mac, sender_mac);
        strcpy(stats->arp_machines[stats->num_arp_machines].ip, sender_ip);
        stats->num_arp_machines++;
    }

    // Check if entry already exists in the ARP list for target
    entry_index = -1;
    for (int i = 0; i < stats->num_arp_machines; i++) {
        if (strcmp(stats->arp_machines[i].mac, target_mac) == 0 && strcmp(stats->arp_machines[i].ip, target_ip) == 0) {
            entry_index = i;
            break;
        }
    }
    if (entry_index == -1 && stats->num_arp_machines < MAX_ENTRIES) {
        // Add new entry for target in ARP list
        strcpy(stats->arp_machines[stats->num_arp_machines].mac, target_mac);
        strcpy(stats->arp_machines[stats->num_arp_machines].ip, target_ip);
        stats->num_arp_machines++;
    }
}

void process_udp(struct statistics *stats, const struct pcap_pkthdr *header, const u_char *packet) {
    // Parse Ethernet header
    struct ether_header *eth_header = (struct ether_header *)packet;

    // Parse IP header
    struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
    int ip_header_len = ip_header->ip_hl * 4; // IP header length in bytes

    // Check if the packet contains an IP header and if the IP protocol is UDP
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP && ip_header->ip_p == IPPROTO_UDP) {
        // Parse UDP header
        struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + ip_header_len);

        // Extract source and destination port numbers
        int source_port = ntohs(udp_header->source);
        int dest_port = ntohs(udp_header->dest);

        // Update source port
        int found_source = 0;
        for (int i = 0; i < stats->num_source_ports; i++) {
            if (stats->source_ports[i].port_number == source_port) {
                stats->source_ports[i].count++;
                found_source = 1;
                break;
            }
        }
        if (!found_source && stats->num_source_ports < MAX_PORTS) {
            stats->source_ports[stats->num_source_ports].port_number = source_port;
            stats->source_ports[stats->num_source_ports].count = 1;
            stats->num_source_ports++;
        }

        // Update destination port
        int found_dest = 0;
        for (int i = 0; i < stats->num_dest_ports; i++) {
            if (stats->dest_ports[i].port_number == dest_port) {
                stats->dest_ports[i].count++;
                found_dest = 1;
                break;
            }
        }
        if (!found_dest && stats->num_dest_ports < MAX_PORTS) {
            stats->dest_ports[stats->num_dest_ports].port_number = dest_port;
            stats->dest_ports[stats->num_dest_ports].count = 1;
            stats->num_dest_ports++;
        }
    }
}

void process_ipv6(struct statistics *stats, const struct pcap_pkthdr *header, const u_char *packet) {
    // Parse Ethernet header
    struct ether_header *eth_header = (struct ether_header *)packet;

    // Check if the packet contains an IPv6 header
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IPV6) {
        // For IPv6 packets, we only process the Ethernet portion before aborting
        // Update IPv6 senders and receivers accordingly

        // Convert sender MAC address to ASCII
        char sender_mac[18];
        sprintf(sender_mac, "%s", ether_ntoa((struct ether_addr *)eth_header->ether_shost));

        // Convert receiver MAC address to ASCII
        char receiver_mac[18];
        sprintf(receiver_mac, "%s", ether_ntoa((struct ether_addr *)eth_header->ether_dhost));

        // Check if entry already exists in the IPv6 sender list
        int entry_index = -1;
        for (int i = 0; i < stats->num_ipv6_senders; i++) {
            if (strcmp(stats->ipv6_senders[i].mac, sender_mac) == 0) {
                entry_index = i;
                break;
            }
        }
        if (entry_index == -1 && stats->num_ipv6_senders < MAX_IPV6_ENTRIES) {
            // Add new entry for sender in IPv6 sender list
            strcpy(stats->ipv6_senders[stats->num_ipv6_senders].mac, sender_mac);
            stats->ipv6_senders[stats->num_ipv6_senders].count = 1;
            stats->num_ipv6_senders++;
        } else if (entry_index != -1) {
            // Increment count for existing sender in IPv6 sender list
            stats->ipv6_senders[entry_index].count++;
        }

        // Check if entry already exists in the IPv6 receiver list
        entry_index = -1;
        for (int i = 0; i < stats->num_ipv6_receivers; i++) {
            if (strcmp(stats->ipv6_receivers[i].mac, receiver_mac) == 0) {
                entry_index = i;
                break;
            }
        }
        if (entry_index == -1 && stats->num_ipv6_receivers < MAX_IPV6_ENTRIES) {
            // Add new entry for receiver in IPv6 receiver list
            strcpy(stats->ipv6_receivers[stats->num_ipv6_receivers].mac, receiver_mac);
            stats->ipv6_receivers[stats->num_ipv6_receivers].count = 1;
            stats->num_ipv6_receivers++;
        } else if (entry_index != -1) {
            // Increment count for existing receiver in IPv6 receiver list
            stats->ipv6_receivers[entry_index].count++;
        }

        // Abort processing for IPv6 packets
        return;
    }
}

void process_packet(struct statistics *stats, const struct pcap_pkthdr *header, const u_char *packet) {
    // Update total packet count
    stats->total_packets++;

    // Update total size
    stats->total_size += header->len;

    // Update minimum and maximum packet sizes
    if (header->len < stats->min_size) {
        stats->min_size = header->len;
    }

    if (header->len > stats->max_size) {
        stats->max_size = header->len;
    }

    // Update end time
    stats->end_time = header->ts.tv_sec + ((double)header->ts.tv_usec / 1000000);

    // Set start time
    if (stats->total_packets == 1) {
        stats->start_time = stats->end_time;
    }

    // Process Ethernet and IP information
    process_ethernet_ip(stats, header, packet);

    //Process ARP
    process_arp(stats, header, packet);

    //Proces UDP
    process_udp(stats, header, packet);

    //Process IPv6
    process_ipv6(stats, header, packet);
}

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct statistics stats;

    if (argc != 2) {
        printf("Usage %s <pcap_file>\n", argv[0]);
        return 1;
    }

    // Open the file for reading
    handle = pcap_open_offline(argv[1], errbuf);

    if (handle == NULL) {
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        return 1;
    }

    // Initialize Statistics
    memset(&stats, 0, sizeof(struct statistics));

    // Loop through packets and process each one
    pcap_loop(handle, -1, (pcap_handler)process_packet, (u_char *)&stats);

    // Calculate start time to human-readable format
    time_t start_time_seconds = (time_t)stats.start_time;
    struct tm *start_time_info = gmtime(&start_time_seconds);
    char start_time_str[20];
    strftime(start_time_str, sizeof(start_time_str), "%Y-%m-%d %H:%M:%S", start_time_info);

    // Calculate start date and time.
    printf("Start date and time of packet capture: %s\n", start_time_str);

    // Calculate duration
    printf("Duration of packet capture: %.6f seconds \n", stats.end_time - stats.start_time);

    // Total number of packets
    printf("Total number of packets: %d\n", stats.total_packets);

    // Print average, minimum, and maximum packet sizes.
    printf("Average packet size: %.2f bytes\n", (double)stats.total_size / stats.total_packets);
    printf("Minimum packet size: %d bytes \n", stats.min_size);
    printf("Maximum packet size: %d bytes \n", stats.max_size);

    // Printing senders and receivers
    printf("\nEthernet Senders:\n");
    printf("%-18s | %-17s | %s\n", "MAC Address", "Packet Count", "Type");
    printf("------------------------------------------------\n");
    for (int i = 0; i < stats.num_senders_eth; i++) {
        printf("%-18s | %-17d | %s\n", stats.senders_eth[i].mac, stats.senders_eth[i].count, "Sender");
    }

    printf("\nEthernet Receivers:\n");
    printf("%-18s | %-17s | %s\n", "MAC Address", "Packet Count", "Type");
    printf("------------------------------------------------\n");
    for (int i = 0; i < stats.num_receivers_eth; i++) {
        printf("%-18s | %-17d | %s\n", stats.receivers_eth[i].mac, stats.receivers_eth[i].count, "Receiver");
    }

    printf("\nIP Senders:\n");
    printf("%-15s | %-15s | %s\n", "IP Address", "Packet Count", "Type");
    printf("------------------------------------------------\n");
    for (int i = 0; i < stats.num_senders_ip; i++) {
        printf("%-15s | %-15d | %s\n", stats.senders_ip[i].ip, stats.senders_ip[i].count, "Sender");
    }

    printf("\nIP Receivers:\n");
    printf("%-15s | %-15s | %s\n", "IP Address", "Packet Count", "Type");
    printf("------------------------------------------------\n");
    for (int i = 0; i < stats.num_receivers_ip; i++) {
        printf("%-15s | %-15d | %s\n", stats.receivers_ip[i].ip, stats.receivers_ip[i].count, "Receiver");
    }

    // Print ARP machines
    printf("\nARP Machines:\n");
    printf("%-18s | %-15s\n", "MAC Address", "IP Address");
    printf("---------------------------------\n");
    for (int i = 0; i < stats.num_arp_machines; i++) {
        printf("%-18s | %-15s\n", stats.arp_machines[i].mac, stats.arp_machines[i].ip);
    }

    // Printing UDP port statistics
    printf("\nUDP Source Ports:\n");
    printf("%-10s | %s\n", "Port", "Packet Count");
    printf("-------------------------\n");
    for (int i = 0; i < stats.num_source_ports; i++) {
        printf("%-10d | %d\n", stats.source_ports[i].port_number, stats.source_ports[i].count);
    }

    printf("\nUDP Destination Ports:\n");
    printf("%-10s | %s\n", "Port", "Packet Count");
    printf("-------------------------\n");
    for (int i = 0; i < stats.num_dest_ports; i++) {
        printf("%-10d | %d\n", stats.dest_ports[i].port_number, stats.dest_ports[i].count);
    }

    //Printing IPv6 Statistics
    printf("\nIPv6 Senders:\n");
    printf("%-18s | %-17s\n", "MAC Address", "Packet Count");
    printf("------------------------------------------------\n");
    for (int i = 0; i < stats.num_ipv6_senders; i++) {
        printf("%-18s | %-17d\n", stats.ipv6_senders[i].mac, stats.ipv6_senders[i].count);
    }

    printf("\nIPv6 Receivers:\n");
    printf("%-18s | %-17s\n", "MAC Address", "Packet Count");
    printf("------------------------------------------------\n");
    for (int i = 0; i < stats.num_ipv6_receivers; i++) {
        printf("%-18s | %-17d\n", stats.ipv6_receivers[i].mac, stats.ipv6_receivers[i].count);
    }


    // Close the pcap file
    pcap_close(handle);

    return 0;
}
