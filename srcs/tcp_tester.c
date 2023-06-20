#include "./includes/ft_nmap.h"

void pcap_handler_fn(u_char *user, const struct pcap_pkthdr *header, const u_char *packet)
{
	(void)user;
	(void)header;

	const u_char *ip_header = NULL;
	const u_char *tcp_header = NULL;

	int ethernet_header_length = 14; /* Doesn't change */
	int ip_header_length = 0;
	int tcp_header_length = 0;

	fprintf(stdout, ANSI_COLOR_GREEN "full payload: [ 0x");
	for (bpf_u_int32 i = 0; i < header->len; ++i)
	{
		fprintf(stdout, "%x", packet[i]);
	}
	fprintf(stdout, " ]\n"ANSI_COLOR_RESET);

	fprintf(stdout, ANSI_COLOR_YELLOW "ethernet_header: [ 0x");
	for (int i = 0; i < ethernet_header_length; ++i)
	{
		fprintf(stdout, "%x", packet[i]);
	}
	fprintf(stdout, " ]\n"ANSI_COLOR_RESET);
	ip_header = packet + ethernet_header_length;
	ip_header_length = ((*ip_header) & 0x0F);
	ip_header_length = ip_header_length * 4;
	printf(ANSI_COLOR_BLUE "IP header length (IHL) in packet: %d\nip header: [ 0x", ip_header_length);
	for (int i = 0; i < ip_header_length; ++i)
	{
		fprintf(stdout, "%x", ip_header[i]);
	}
	fprintf(stdout, " ]\n"ANSI_COLOR_RESET);

	u_char protocol = *(ip_header + 9);
	if (protocol != IPPROTO_TCP)
	{
		printf(ANSI_COLOR_RED"Not a TCP packet. Skipping...\n\n"ANSI_COLOR_RESET);
		exit(1);
	}

	tcp_header = packet + ethernet_header_length + ip_header_length;
	tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;
	tcp_header_length = tcp_header_length * 4;
	printf(ANSI_COLOR_MAGENTA  "TCP header length in bytes: %x\n[ 0x", tcp_header_length);
	for (int i = 0; i < tcp_header_length; ++i)
	{
		fprintf(stdout, "%x", tcp_header[i] /*& 0x1*/);
	}
	fprintf(stdout, " ]\n" ANSI_COLOR_RESET);

	return;
}

void tcp_tester()
{
	pcap_if_t *devs = NULL;
	char errbuf[PCAP_ERRBUF_SIZE] = {0};

	if (pcap_findalldevs(&devs, errbuf) == PCAP_ERROR)
	{
		fprintf(stderr, "%s\n", errbuf);
		exit(1);
	}

	int selector_counter = 0;
	pcap_if_t *step = devs;
	fprintf(stdout, "==DEBUG==\n");
	while (step != NULL)
	{
		fprintf(stdout, "%d. %15s | description: %s\n", selector_counter, step->name, step->description);
		step = step->next;
		++selector_counter;
	}
	// fprintf(stdout, "==DEBUG END==\n");

	fprintf(stdout, "Listen to %s\n", devs->name);
	pcap_t *handle_pcap = pcap_open_live(devs->name, BUFSIZ, 0, 10000, errbuf);
	if (!handle_pcap)
	{
		fprintf(stderr, "%s\n", errbuf);
		exit(1);
	}

	u_char user[BUFSIZ];

	if (pcap_dispatch(handle_pcap, 65535, pcap_handler_fn, user) == PCAP_ERROR)
	{
		pcap_geterr(handle_pcap);
		exit(1);
	}

	pcap_breakloop(handle_pcap);
	pcap_close(handle_pcap);
	pcap_freealldevs(devs);
}

