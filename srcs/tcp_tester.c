#include "./includes/ft_nmap.h"
#include "./includes/struct.h"

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
	struct bpf_program filter = {0};
	char *filter_exp = ft_strjoin("tcp port ", port1);
	char *tmp = ft_strjoin(filter_exp, " and tcp port ");
	free(filter_exp);
	filter_exp = ft_strjoin(tmp, port2);
	free(tmp);

	if (pcap_compile(*handle_pcap, &filter, filter_exp, 0, 0) == PCAP_ERROR || pcap_setfilter(*handle_pcap, &filter) == PCAP_ERROR)
	{
		pcap_geterr(*handle_pcap);
		exit(1);
	}

	free(filter_exp);
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

void init_tcp_packet(char *addr_src, int port_src, char *addr_dest, int port_dest)
{
	char datagram[4096], source_ip[32], *pseudogram;
	ft_bzero(datagram, 4096);

	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	struct iphdr *iph = (struct iphdr *)datagram;
	struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct ip));

	struct sockaddr_in sin;
	struct pseudo_header psh;

	ft_strlcpy(source_ip, addr_src, 11);
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port_dest);
	sin.sin_addr.s_addr = inet_addr(addr_dest);

	init_ip_header(&iph, datagram, source_ip, sin.sin_addr.s_addr);
	init_tcp_header(&tcph, port_src, port_dest, FIN | PSH | URG);

	psh.source_address = inet_addr(source_ip);
	psh.dest_address = sin.sin_addr.s_addr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons(sizeof(struct tcphdr));

	int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
	pseudogram = malloc(psize);

	memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
	memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));

	tcph->check = csum((unsigned short *)pseudogram, psize);

	int one = 1;
	const int *val = &one;

	if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
	{
		perror("Error setting IP_HDRINCL");
		free(pseudogram);
		close(sock);
		exit(0);
	}

	if (sendto(sock, datagram, iph->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
	{
		free(pseudogram);
		close(sock);
		perror("sendto failed");
	}

	free(pseudogram);
	close(sock);
}

void send_to_tcp_port()
{
	init_tcp_packet("172.17.0.2", 6675, "172.17.0.3", 6677);
}

static void *thread_start(void *arg)
{
	(void)arg;
	send_to_tcp_port();

	return NULL;
}

void tcp_test_port(pcap_t **handle_pcap)
{
	u_char user[BUFSIZ];

	pthread_t thread_id = {0};
	int s = pthread_create(&thread_id, NULL, &thread_start, 0);

	if (s == 0)
	{
		if (pcap_dispatch(*handle_pcap, 65535, pcap_handler_fn, user) == PCAP_ERROR)
		{
			pcap_geterr(*handle_pcap);
			pcap_breakloop(*handle_pcap);
			pcap_close(*handle_pcap);
			exit(1);
		}
		pcap_breakloop(*handle_pcap);
		pcap_close(*handle_pcap);
	}

	pthread_join(thread_id, NULL);
}

void tcp_tester()
{
	pcap_t *handle_pcap = NULL;

	setup_record(&handle_pcap);
	setup_record_filter(&handle_pcap, "6675", "6677");
	tcp_test_port(&handle_pcap);
}
