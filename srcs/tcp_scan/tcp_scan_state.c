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

void print_result(int rtn, u_char *user){
	char s_port[5] = "PORT";
	char s_state[6] = "STATE";
	char s_service[8] = "SERVICE";
	char s_proto[5] = "/tcp";
	char *state = NULL;
	
	if (rtn == 1){//* TIMEOUT
		if (user[0] == N_XMAS || user[0] == N_FIN || user[0] == N_NULL)
			state = ft_strdup("open | filtered");
		if (user[0] == N_SYN || user[0] == N_ACK)
			state = ft_strdup("filtered");
	}
	else {
		if (user[0]  == N_ACK){
			state = ft_strdup("unfiltered");
		}
		else{
			if (user[1] == CLOSE)
				state = ft_strdup("close");
			else if (user[1] == OPEN)
				state = ft_strdup("open");
		}
	}
	if (!state){
		fprintf(stderr, "Fail to malloc the string for the state");
		return;
	}
	printf("%-15s %-15s %-15s\n% 5d%-10s %-15s\tservice\n", s_port, s_state, s_service, ((unsigned *)user)[4], s_proto, state);
	free(state);
}

bool tcp_test_port(pcap_t **handle_pcap, struct sockaddr_in *addr, char *ip_dest, int port)
{
	u_char user[BUFSIZ];
	user[0] = N_SYN; //*SEND FLAG
	((unsigned*)user)[4] = port;

	t_tcp_vars *tcp_vars = init_tcp_packet(addr, ip_dest, port, user[0]);
	if (!tcp_vars){
		pcap_close(*handle_pcap);
		return false;
	}
	send_tcp_packet(tcp_vars);

	int rtn = pcap_dispatch(*handle_pcap, 65535, pcap_handler_fn, user);
	if (rtn == PCAP_ERROR)
	{
		pcap_geterr(*handle_pcap);
		pcap_breakloop(*handle_pcap);
		pcap_close(*handle_pcap);
		return false;
	}

	print_result(rtn, user);

	pcap_breakloop(*handle_pcap);
	pcap_close(*handle_pcap);
	free(tcp_vars);
	return true;
}
