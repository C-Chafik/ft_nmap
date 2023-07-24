#include "../includes/ft_nmap.h"
#include "../includes/includes.h"
#include "../includes/define.h"


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
		if (*(tcp_header + TCP_RSP_FLAG_OFF) & FIN)
			printf("FIN ");
		if (*(tcp_header + TCP_RSP_FLAG_OFF) & SYN)
			printf("SYN ");
		if (*(tcp_header + TCP_RSP_FLAG_OFF) & RST)
			printf("RST ");
		if (*(tcp_header + TCP_RSP_FLAG_OFF) & PSH)
			printf("PSH ");
		if (*(tcp_header + TCP_RSP_FLAG_OFF) & ACK)
			printf("ACK ");
		if (*(tcp_header + TCP_RSP_FLAG_OFF) & URG)
			printf("URG ");
		printf("( 0x%02x )\n" ANSI_COLOR_RESET, *(tcp_header + TCP_RSP_FLAG_OFF));

		printf(ANSI_COLOR_BLUE "TCP SRC: %u\n" ANSI_COLOR_RESET, htons(*(unsigned *)(packet + PORT_SRC_OFF)));
		printf(ANSI_COLOR_BLUE "TCP DST: %u\n" ANSI_COLOR_RESET, htons(*(unsigned *)(packet + PORT_DST_OFF)));
		printf(ANSI_COLOR_BLUE "==================\n" ANSI_COLOR_RESET);
	}
}