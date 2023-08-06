#include "../includes/ft_nmap.h"
#include "../includes/includes.h"
#include "../includes/define.h"

static void pcap_handler_udp(u_char *user_data, const struct pcap_pkthdr *header, const u_char *packet) 
{
	(void)user_data;
	(void)header;

    struct ip *ip_header = (struct ip *)(packet + ETH_HLEN); 
    u_char ip_header_length = ip_header->ip_hl * 4;

    if (ip_header->ip_p == IPPROTO_UDP) 
	{
        struct udphdr *udp_header = (struct udphdr *)(packet + ETH_HLEN + ip_header_length);
        printf("Received UDP packet from port %d\n", ntohs(udp_header->dest));
    } 
	else if (ip_header->ip_p == IPPROTO_ICMP) 
	{
        struct icmphdr *icmp_header = (struct icmphdr *)(packet + ETH_HLEN + ip_header_length);

        if (icmp_header->type == ICMP_DEST_UNREACH) 
            printf("ICMP Destination Unreachable received, port is closed\n");
		else 
            printf("Received ICMP type %d. Further analysis needed.\n", icmp_header->type);

    } 
	else 
        printf("Received unexpected packet type. Skipping...\n");
}


bool udp_test_port(pcap_t **handle_pcap, struct sockaddr_in *addr, char *ip_dest, int port)
{
	(void)addr;
	t_udp_vars *udp_vars;

	udp_vars = init_udp_packet(ip_dest, port);
	if (!udp_vars || !send_udp_packet(udp_vars))
		return false;

	int rtn = pcap_dispatch(*handle_pcap, 2, pcap_handler_udp, NULL);
	if (rtn == PCAP_ERROR)
	{
		pcap_geterr(*handle_pcap); 
		pcap_breakloop(*handle_pcap);
		return false;
	}
	pcap_breakloop(*handle_pcap);

	return true;
}