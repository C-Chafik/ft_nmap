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
		printf(ANSI_COLOR_RED "Not a TCP packet. Skipping...\n\n" ANSI_COLOR_RESET);
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

	*handle_pcap = pcap_open_live(devs->name, BUFSIZ, 0, 10000, errbuf);
	if (!*handle_pcap)
	{
		fprintf(stderr, "%s\n", errbuf);
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

void send_to_tcp_port()
{
	struct sockaddr_in serv_addr, send_addr;
	bzero(&(serv_addr.sin_zero), 8);
	bzero(&(send_addr.sin_zero), 8);

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = inet_addr("172.17.0.2");
	serv_addr.sin_port = htons(6675);

	send_addr.sin_family = AF_INET;
	send_addr.sin_addr.s_addr = inet_addr("172.17.0.3");
	send_addr.sin_port = htons(6677);


	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == -1)
	{
		fprintf(stderr, "%s\n", strerror(errno));
		close(sock);
		exit(1);
	}

	if (bind(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1)
	{
		fprintf(stderr, "%s\n", strerror(errno));
		close(sock);
		exit(1);
	}

	struct timeval timeout = {0, 250000};
	if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0)
	{
		fprintf(stderr, "%s\n", strerror(errno));
		close(sock);
		exit(1);
	}

	if (connect(sock, (struct sockaddr *)&send_addr, sizeof(send_addr)) == -1)
	{
		fprintf(stderr, "%s\n", strerror(errno));
		close(sock);
		exit(1);
	}

	if (sendto(sock, NULL, 0, 0, (struct sockaddr *)&send_addr, sizeof(struct sockaddr)) == -1)
	{
		fprintf(stderr, "%s\n", strerror(errno));
		close(sock);
		exit(1);
	}

	close(sock);
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
			exit(1);
		}
	}

	pthread_join(thread_id, NULL);
}

void tcp_tester()
{
	pcap_t *handle_pcap = NULL;

	setup_record(&handle_pcap);
	// setup_record_filter(&handle_pcap, "80", "39582");
	tcp_test_port(&handle_pcap);

	pcap_breakloop(handle_pcap);
	pcap_close(handle_pcap);
}
