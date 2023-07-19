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
		user[10] = 0;
		return;
	}

	tcp_header = packet + ethernet_header_length + ip_header_length;
	tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;
	tcp_header_length = tcp_header_length * 4;

	// debug_print_tcp_header(tcp_header, tcp_header_length);
	debug_print_tcp_flags(tcp_header, tcp_header_length, packet);
	if (htons(*(unsigned *)(packet + 34)) != ((unsigned *)user)[4])
		return;
	user[1] = check_tcp_port_state(tcp_header, user[0]);

	user[10] = 1;
	return;
}

struct sockaddr_in *setup_record(pcap_t **handle_pcap)
{
	char errbuf[PCAP_ERRBUF_SIZE] = {0};
	pcap_if_t *devs = NULL;
	struct sockaddr_in *rtn = NULL;
	rtn = malloc(sizeof(struct sockaddr_in));

	if (!rtn){
		perror("malloc alloc failed");
		return NULL;
	}

	/*
		Si valgrind affiche des uninitialised bytes ici,
		c'est que valgrind n'arrive pas a suivre la memoire qui est utilis car elle passe par le kernel
		pour regler le probleme il faudrait wrapper le call de la fonction avec des macro valgrind qui sont out of scope
		=========
		https://cs.swan.ac.uk/~csoliver/ok-sat-library/internet_html/doc/doc/Valgrind/3.8.1/html/dist.readme-missing.html
		https://chromium.googlesource.com/chromiumos/third_party/gcc/+/refs/heads/factory-ryu-6486.B/libsanitizer/sanitizer_common/sanitizer_common_syscalls.inc
	*/
	if (pcap_findalldevs(&devs, errbuf) == PCAP_ERROR)
	{
		fprintf(stderr, "%s\n", errbuf);
		free(rtn);
		return NULL;
	}

	char *name = NULL;
	bool stop = false;

	for (pcap_if_t *tmp = devs; tmp != NULL && !stop; tmp = tmp->next)
	{
		if (tmp->flags != PCAP_IF_LOOPBACK)
		{
			for (struct pcap_addr *ad = tmp->addresses; ad; ad = ad->next){
				// printf("\t%s | ", inet_ntoa(((struct sockaddr_in*)ad->rtn)->sin_addr));
				// printf(" family: %s\n", ((struct sockaddr_in*)ad->rtn)->sin_family == AF_INET ? "AF_INET":"NOPE");
				if (((struct sockaddr_in*)ad->addr)->sin_family == AF_INET){
					name = tmp->name;
					ft_memcpy(rtn, (struct sockaddr_in*)ad->addr, sizeof(struct sockaddr_in));
					stop = true;
					break;
				}
			}
		}
	}

	if (!name || !rtn)
	{
		fprintf(stderr, "No (none loopback) interfaces\n");
		pcap_freealldevs(devs);
		free(rtn);
		return NULL;
	}

	*handle_pcap = pcap_open_live(name, BUFSIZ, 0, 1500, errbuf); 
	if (!*handle_pcap)
	{
		pcap_freealldevs(devs);
		fprintf(stderr, "%s\n", errbuf);
		free(rtn);
		return NULL;
	}

	pcap_freealldevs(devs);
	return rtn;
}

bool setup_record_filter(pcap_t **handle_pcap, char *port)
{
	struct bpf_program filter = {0};
	char *filter_exp = NULL;
	filter_exp = ft_strjoin("tcp port ", port);

	if (pcap_compile(*handle_pcap, &filter, filter_exp, 0, 0) == PCAP_ERROR || pcap_setfilter(*handle_pcap, &filter) == PCAP_ERROR)
	{
		pcap_geterr(*handle_pcap);
		free(port);
		free(filter_exp);
		return false;
	}


	free(port);
	free(filter_exp);
	pcap_freecode(&filter);
	return true;
}