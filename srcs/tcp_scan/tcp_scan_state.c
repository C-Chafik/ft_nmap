#include "../includes/ft_nmap.h"
#include "../includes/includes.h"
#include "../includes/define.h"


short check_tcp_port_state(const u_char *tcp_header, u_char flags)
{
	if (flags == N_XMAS || flags == N_NULL || flags == N_FIN){
		if (*(tcp_header + 13) & RST)
			return CLOSE;
	}
	else if (flags == N_SYN){
		if (*(tcp_header + 13) == (SYN | ACK))
			return OPEN;
		else if (*(tcp_header + 13))
			return CLOSE;
	}

	return FILTERED;
}

void tcp_test_port(pcap_t **handle_pcap, struct sockaddr_in *addr, char *ip_dest, int port)
{
	u_char user[BUFSIZ];
	user[0] = N_SYN; //*SEND FLAG
	((unsigned*)user)[4] = port;

	t_tcp_vars tcp_vars = init_tcp_packet(addr, ip_dest, port, user[0]);
	send_tcp_packet(tcp_vars);

	int rtn = pcap_dispatch(*handle_pcap, 65535, pcap_handler_fn, user) ;

	if (rtn == PCAP_ERROR || !user[10])
	{
		pcap_geterr(*handle_pcap);
		pcap_breakloop(*handle_pcap);
		pcap_close(*handle_pcap);
		exit(1);
	}
	else if (rtn == 1){//* TIMEOUT
		if (user[0] == N_XMAS || user[0] == N_FIN || user[0] == N_NULL)
			printf(ANSI_COLOR_MAGENTA "OPEN | FILTERED\n" ANSI_COLOR_RESET);
		if (user[0] == N_SYN || user[0] == N_ACK)
			printf(ANSI_COLOR_MAGENTA "FILTERED\n" ANSI_COLOR_RESET);
	}
	else {
		if (user[0]  == N_ACK){
			printf(ANSI_COLOR_MAGENTA "UNFILTERED\n" ANSI_COLOR_RESET);
		}
		else{
			if (user[1] == CLOSE)
				printf(ANSI_COLOR_MAGENTA "CLOSE\n" ANSI_COLOR_RESET);
			else if (user[1] == OPEN)
				printf(ANSI_COLOR_MAGENTA "OPEN\n" ANSI_COLOR_RESET);
		}
	}

	pcap_breakloop(*handle_pcap);
	pcap_close(*handle_pcap);
}
