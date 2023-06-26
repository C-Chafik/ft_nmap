#include "./includes/ft_nmap.h"
#include "./includes/struct.h"

// u_char flags =  FIN | PSH | URG;

void debug_print_full_packet(const struct pcap_pkthdr *header, const u_char *packet)
{
	fprintf(stdout, ANSI_COLOR_GREEN "full payload: [ 0x ");
	for (bpf_u_int32 i = 0, j = 1; i < header->caplen; ++i, ++j)
	{
		fprintf(stdout, "%02x", packet[i]);
		if (j == 2)
		{
			fprintf(stdout, " ");
			j = 0;
		}
	}
	fprintf(stdout, " ]\n" ANSI_COLOR_RESET);
}

void debug_print_tcp_header(const u_char *tcp_header, int tcp_header_length)
{
	printf(ANSI_COLOR_MAGENTA "TCP header length in bytes: %x\n[ 0x ", tcp_header_length);
	for (int i = 0, j = 1; i < tcp_header_length; ++i, ++j)
	{
		fprintf(stdout, "%02x", tcp_header[i]);
		if (j == 2)
		{
			fprintf(stdout, " ");
			j = 0;
		}
	}
	fprintf(stdout, " ]\n" ANSI_COLOR_RESET);
}

void debug_print_tcp_flags(const u_char *tcp_header, int tcp_header_length, const u_char *packet)
{
	if (tcp_header_length > 12)
	{
		printf(ANSI_COLOR_BLUE "TCP FLAG: ");
		if (*(tcp_header + 13) & FIN)
			printf("FIN ");
		if (*(tcp_header + 13) & SYN)
			printf("SYN ");
		if (*(tcp_header + 13) & RST)
			printf("RST ");
		if (*(tcp_header + 13) & PSH)
			printf("PSH ");
		if (*(tcp_header + 13) & ACK)
			printf("ACK ");
		if (*(tcp_header + 13) & URG)
			printf("URG ");
		printf("( 0x%02x )\n" ANSI_COLOR_RESET, *(tcp_header + 13));

		printf(ANSI_COLOR_BLUE "TCP SRC: %u\n" ANSI_COLOR_RESET, htons(*(unsigned *)(packet + 34)));
		printf(ANSI_COLOR_BLUE "TCP DST: %u\n" ANSI_COLOR_RESET, htons(*(unsigned *)(packet + 36)));
		printf(ANSI_COLOR_BLUE "==================\n" ANSI_COLOR_RESET);
	}
}

short check_tcp_port_state(const u_char *tcp_header, u_char flags)
{
	if (flags == (FIN | PSH | URG)) // XMAS
	{
		if (*(tcp_header + 13) & RST || *(tcp_header + 13) == 0 || *(tcp_header + 13) & FIN)
		{
			return CLOSE;
		}
		else
		{
			return OPEN | FILTERED;
		}
	}
	return CLOSE;
}

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
	u_char state = check_tcp_port_state(tcp_header, user[0]);

	if (state == CLOSE)
		printf(ANSI_COLOR_MAGENTA "CLOSE\n" ANSI_COLOR_RESET);
	else if (state == (OPEN | FILTERED))
		printf(ANSI_COLOR_MAGENTA "OPEN | FILTERED\n" ANSI_COLOR_RESET);

	return;
}

void setup_record(pcap_t **handle_pcap)
{
	char errbuf[PCAP_ERRBUF_SIZE] = {0};
	pcap_if_t *devs = NULL;

	if (pcap_findalldevs(&devs, errbuf) == PCAP_ERROR)
	{
		fprintf(stderr, "%s\n", errbuf);
		exit(1);
	}

	*handle_pcap = pcap_open_live(devs->name, BUFSIZ, 0, 1500, errbuf);
	if (!*handle_pcap)
	{
		fprintf(stderr, "%s\n", errbuf);
		pcap_close(*handle_pcap);
		exit(1);
	}

	pcap_freealldevs(devs);
}

void setup_record_filter(pcap_t **handle_pcap, char *port1, char *port2)
{
	(void)port1;
	(void)port2;
	struct bpf_program filter = {0};
	// char *filter_exp = ft_strjoin("tcp port ", port1);
	// char *tmp = ft_strjoin(filter_exp, " and tcp port ");
	// free(filter_exp);
	// filter_exp = ft_strjoin(tmp, port2);
	// free(tmp);

	// if (pcap_compile(*handle_pcap, &filter, filter_exp, 0, 0) == PCAP_ERROR || pcap_setfilter(*handle_pcap, &filter) == PCAP_ERROR)
	if (pcap_compile(*handle_pcap, &filter,  "tcp dst port 6675 and tcp src port 6677", 0, 0) == PCAP_ERROR || pcap_setfilter(*handle_pcap, &filter) == PCAP_ERROR)
	{
		pcap_geterr(*handle_pcap);
		exit(1);
	}

	// free(filter_exp);
}

unsigned short csum(unsigned short *ptr, int nbytes)
{
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum = 0;
	while (nbytes > 1)
	{
		sum += *ptr++;
		nbytes -= 2;
	}
	if (nbytes == 1)
	{
		oddbyte = 0;
		*((u_char *)&oddbyte) = *(u_char *)ptr;
		sum += oddbyte;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum = sum + (sum >> 16);
	answer = (short)~sum;

	return (answer);
}

void init_ip_header(struct iphdr **iph, char *datagram, char *source_ip, in_addr_t s_addr)
{
	(*iph)->ihl = 5;
	(*iph)->version = 4;
	(*iph)->tos = 0;
	(*iph)->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
	(*iph)->id = htonl(54321); // id of this packet
	(*iph)->frag_off = 0;
	(*iph)->ttl = 255;
	(*iph)->protocol = IPPROTO_TCP;
	(*iph)->check = 0;
	(*iph)->saddr = inet_addr(source_ip);
	(*iph)->daddr = s_addr;
	(*iph)->check = csum((unsigned short *)datagram, (*iph)->tot_len);
}

void init_tcp_header(struct tcphdr **tcph, int port_src, int port_dest, u_char flags)
{
	(*tcph)->source = htons(port_src);
	(*tcph)->dest = htons(port_dest);
	(*tcph)->seq = 0;
	(*tcph)->ack_seq = 0;
	(*tcph)->doff = 5;
	(*tcph)->fin = !!(flags & FIN);
	(*tcph)->syn = !!(flags & SYN);
	(*tcph)->rst = !!(flags & RST);
	(*tcph)->psh = !!(flags & PSH);
	(*tcph)->ack = !!(flags & ACK);
	(*tcph)->urg = !!(flags & URG);
	// tcph->window = htons (5840);
	(*tcph)->check = 0;
	(*tcph)->urg_ptr = 0;
}

typedef struct tcp_vars
{
	char datagram[4096];
	char source_ip[32];
	char *pseudogram;
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct sockaddr_in sin;
	struct pseudo_header psh;
	int psize;
	int sock;
} t_tcp_vars;


t_tcp_vars init_tcp_packet(char *addr_src, int port_src, char *addr_dest, int port_dest, u_char flags)
{
	t_tcp_vars tcp_vars = {0};
	ft_bzero(tcp_vars.datagram, 4096);

	tcp_vars.sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	tcp_vars.iph = (struct iphdr *)tcp_vars.datagram;
	tcp_vars.tcph = (struct tcphdr *)(tcp_vars.datagram + sizeof(struct ip));

	ft_strlcpy(tcp_vars.source_ip, addr_src, 11);
	tcp_vars.sin.sin_family = AF_INET;
	tcp_vars.sin.sin_port = htons(port_dest);
	tcp_vars.sin.sin_addr.s_addr = inet_addr(addr_dest);

	init_ip_header(&tcp_vars.iph, tcp_vars.datagram, tcp_vars.source_ip, tcp_vars.sin.sin_addr.s_addr);
	init_tcp_header(&tcp_vars.tcph, port_src, port_dest, flags);

	tcp_vars.psh.source_address = inet_addr(tcp_vars.source_ip);
	tcp_vars.psh.dest_address = tcp_vars.sin.sin_addr.s_addr;
	tcp_vars.psh.placeholder = 0;
	tcp_vars.psh.protocol = IPPROTO_TCP;
	tcp_vars.psh.tcp_length = htons(sizeof(struct tcphdr));

	tcp_vars.psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
	tcp_vars.pseudogram = malloc(tcp_vars.psize);

	memcpy(tcp_vars.pseudogram, (char *)&tcp_vars.psh, sizeof(struct pseudo_header));
	memcpy(tcp_vars.pseudogram + sizeof(struct pseudo_header), tcp_vars.tcph, sizeof(struct tcphdr));

	tcp_vars.tcph->check = csum((unsigned short *)tcp_vars.pseudogram, tcp_vars.psize);

	int one = 1;
	const int *val = &one;

	if (setsockopt(tcp_vars.sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
	{
		perror("Error setting IP_HDRINCL");
		free(tcp_vars.pseudogram);
		close(tcp_vars.sock);
		exit(0);
	}

	return tcp_vars;
}

void send_tcp_packet(t_tcp_vars tcp_vars){
	struct timeval timeout = {0, 15000};
	if (setsockopt(tcp_vars.sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0)
	{
		perror("setsockopt");
		free(tcp_vars.pseudogram);
		close(tcp_vars.sock);
		exit(0);
	}

	if (sendto(tcp_vars.sock, tcp_vars.datagram, tcp_vars.iph->tot_len, 0, (struct sockaddr *)&tcp_vars.sin, sizeof(tcp_vars.sin)) < 0)
	{
		free(tcp_vars.pseudogram);
		close(tcp_vars.sock);
		perror("sendto failed");
	}

	free(tcp_vars.pseudogram);
	close(tcp_vars.sock);
}

static void *thread_start(void *arg)
{
	t_tcp_vars tcp_vars = init_tcp_packet("172.17.0.2", 6675, "172.17.0.3", 6677, ((u_char *)arg)[0]);
	send_tcp_packet(tcp_vars);

	return NULL;
}

void tcp_test_port(pcap_t **handle_pcap)
{
	u_char user[BUFSIZ];
	user[0] = FIN | PSH | URG;

	pthread_t thread_id = {0};
	if (pthread_create(&thread_id, NULL, &thread_start, user) != 0)
		return;
	
	if (pcap_dispatch(*handle_pcap, 65535, pcap_handler_fn, user) == PCAP_ERROR)
	{
		pcap_geterr(*handle_pcap);
		pcap_breakloop(*handle_pcap);
		pcap_close(*handle_pcap);
		exit(1);
	}
	pcap_breakloop(*handle_pcap);
	pcap_close(*handle_pcap);

	pthread_join(thread_id, NULL);
}

void tcp_tester()
{
	pcap_t *handle_pcap = NULL;

	setup_record(&handle_pcap);
	setup_record_filter(&handle_pcap, "6675", "6677");
	tcp_test_port(&handle_pcap);
}
