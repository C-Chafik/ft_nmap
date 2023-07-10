#include "../includes/ft_nmap.h"
#include "../includes/includes.h"
#include "../includes/define.h"

void pcap_handler_fn(u_char *user, const struct pcap_pkthdr *header, const u_char *packet)
{
	(void)user;
	(void)header;

	const u_char *ip_header = NULL;
	const u_char *tcp_header = NULL;

	int ethernet_header_length = 14;
	int ip_header_length = 0;
	int tcp_header_length = 0;

	debug_print_full_packet(header, packet);

	ip_header = packet + ethernet_header_length;
	ip_header_length = ((*ip_header) & 0x0F);
	ip_header_length = ip_header_length * 4;

	u_char protocol = *(ip_header + 9);
	if (protocol != IPPROTO_TCP)
	{
		printf(ANSI_COLOR_RED "Not a TCP packet. Skipping...\n" ANSI_COLOR_RESET);
		exit(1);
	}

	tcp_header = packet + ethernet_header_length + ip_header_length;
	tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;
	tcp_header_length = tcp_header_length * 4;

	// debug_print_tcp_header(tcp_header, tcp_header_length);
	debug_print_tcp_flags(tcp_header, tcp_header_length, packet);
	if (htons(*(unsigned *)(packet + 34)) != ((unsigned *)user)[4])
		return;
	user[1] = check_tcp_port_state(tcp_header, user[0]);

	return;
}

struct sockaddr_in *setup_record(pcap_t **handle_pcap, pcap_if_t *devs)
{
	char errbuf[PCAP_ERRBUF_SIZE] = {0};

	if (pcap_findalldevs(&devs, errbuf) == PCAP_ERROR)
	{
		fprintf(stderr, "%s\n", errbuf);
		exit(1);
	}

	char *name = NULL;
	struct sockaddr_in *addr = NULL;
	bool stop = false;

	for (pcap_if_t *tmp = devs; tmp != NULL && !stop; tmp = tmp->next)
	{
		if (tmp->flags != PCAP_IF_LOOPBACK)
		{
			for (struct pcap_addr *ad = tmp->addresses; ad; ad = ad->next){
				printf("\t%s | ", inet_ntoa(((struct sockaddr_in*)ad->addr)->sin_addr));
				printf(" family: %s\n", ((struct sockaddr_in*)ad->addr)->sin_family == AF_INET ? "AF_INET":"NOPE");
				if (((struct sockaddr_in*)ad->addr)->sin_family == AF_INET){
					name = tmp->name;
					addr = ((struct sockaddr_in*)ad->addr);
					stop = true;
					break;
				}
			}
		}
	}

	if (!name || !addr)
	{
		fprintf(stderr, "No (none loopback) interfaces\n");
		exit(1);
	}

	*handle_pcap = pcap_open_live(name, BUFSIZ, 0, 1500, errbuf); 
	if (!*handle_pcap)
	{
		fprintf(stderr, "%s\n", errbuf);
		pcap_close(*handle_pcap);
		exit(1);
	}

	return addr;
}

void setup_record_filter(pcap_t **handle_pcap, char *port)
{
	struct bpf_program filter = {0};
	char *filter_exp = ft_strjoin("tcp port ", port);

	if (pcap_compile(*handle_pcap, &filter, filter_exp, 0, 0) == PCAP_ERROR || pcap_setfilter(*handle_pcap, &filter) == PCAP_ERROR)
	{
		pcap_geterr(*handle_pcap);
		exit(1);
	}

	free(filter_exp);
}