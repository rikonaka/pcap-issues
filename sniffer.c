#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pcap.h>
#include <signal.h>

const char *TARGET_IP_STR = "192.168.5.152";

volatile sig_atomic_t keep_running = 1;

void signal_handler(int signum)
{
    if (signum == SIGINT)
    {
        // printf("\n[Signal] Received Ctrl+C (SIGINT). Setting exit flag...\n");
        keep_running = 0;
    }
}

void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
    struct iphdr *ip_hdr;
    unsigned int ip_header_len;
    unsigned short sport;

    ip_hdr = (struct iphdr *)(bytes + 14);
    ip_header_len = ip_hdr->ihl * 4;

    in_addr_t target_saddr = inet_addr(TARGET_IP_STR);
    if (ip_hdr->saddr == target_saddr)
    {
        if (ip_hdr->protocol == IPPROTO_TCP)
        {
            struct tcphdr *tcp_hdr = (struct tcphdr *)(bytes + 14 + ip_header_len);
            unsigned short source_port = ntohs(tcp_hdr->th_sport);
            unsigned short dest_port = ntohs(tcp_hdr->th_dport);
            printf("%u,", source_port);
        }
    }
}

int main()
{

    if (signal(SIGINT, signal_handler) == SIG_ERR)
    {
        perror("Cannot set signal handler");
        return 1;
    }

    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    char filter_exp[] = "src host 192.168.5.152";
    bpf_u_int32 net, mask;

    pcap_if_t *alldevs, *d;
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        return 1;
    }

    if (alldevs == NULL)
    {
        fprintf(stderr, "No devices found: %s\n", errbuf);
        return 1;
    }

    dev = alldevs->name;
    // printf("Using device: %s\n", dev);

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
    {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }

    handle = pcap_create(dev, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "Error creating pcap handle: %s\n", errbuf);
        return 2;
    }

    int buffer_size = 16 * 1024 * 1024; // 10MB
    // int buffer_size = 2147483647; // max
    pcap_set_buffer_size(handle, buffer_size);
    pcap_set_snaplen(handle, 65535);
    pcap_set_promisc(handle, 1);
    pcap_set_timeout(handle, 1000);

    if (pcap_activate(handle) != 0)
    {
        fprintf(stderr, "Error activating pcap handle: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }
    // printf("Pcap handle activated. Starting loop...\n");

    // handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    // if (handle == NULL)
    // {
    //     fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
    //     return 2;
    // }

    // if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
    // {
    //     fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
    //     return 2;
    // }
    // if (pcap_setfilter(handle, &fp) == -1)
    // {
    //     fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
    //     return 2;
    // }

    // printf("Listening on %s, filtering packets from 192.168.5.152...\n", dev);

    // pcap_loop(handle, -1, packet_handler, NULL);
    int total_packets = 0;

    while (keep_running)
    {
        int packets_read = pcap_dispatch(handle, 0, packet_handler, (u_char *)&total_packets);
        if (packets_read == -1)
        {
            fprintf(stderr, "[Main] Error during dispatch: %s\n", pcap_geterr(handle));
            break;
        }
    }

    // struct pcap_stat stats;
    // if (pcap_stats(handle, &stats) != 0)
    // {
    //     fprintf(stderr, "Error getting stats: %s\n", pcap_geterr(handle));
    // }
    // else
    // {
    //     printf("========================================\n");
    //     printf("         Capture Statistics             \n");
    //     printf("========================================\n");
    //     printf("  1. Packets received by filter: %u\n", stats.ps_recv);
    //     printf("  2. Packets dropped by kernel: %u\n", stats.ps_drop);
    //     printf("  3. Packets dropped by interface: %u\n", stats.ps_ifdrop);
    //     printf("========================================\n");
    // }

    pcap_close(handle);

    pcap_freealldevs(alldevs);

    return 0;
}
