#include "../includes/ft_nmap.h"
#include "../includes/includes.h"
#include "../includes/define.h"


short check_tcp_port_state(const u_char tcp_header, u_char flags)
{
	if (flags == N_XMAS || flags == N_NULL || flags == N_FIN){
		if (tcp_header & RST)
			return CLOSE;
	}
	else if (flags == N_SYN){
		if (tcp_header == (SYN | ACK))
			return OPEN;
		else if (tcp_header)
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
		if (user[U_SCAN_TYPE] == N_XMAS || user[U_SCAN_TYPE] == N_FIN || user[U_SCAN_TYPE] == N_NULL)
			state = ft_strdup("open | filtered");
		if (user[U_SCAN_TYPE] == N_SYN || user[U_SCAN_TYPE] == N_ACK)
			state = ft_strdup("filtered");
	}
	else {
		short rtn_state = check_tcp_port_state(user[U_TCP_RTN], user[U_SCAN_TYPE]);
		if (user[U_SCAN_TYPE]  == N_ACK){
			state = ft_strdup("unfiltered");
		}
		else{
			if (rtn_state == CLOSE)
				state = ft_strdup("close");
			else if (rtn_state == OPEN)
				state = ft_strdup("open");
		}
	}
	if (!state){
		fprintf(stderr, "Fail to malloc the string for the state");
		return;
	}
	printf("%-15s %-15s %-15s\n% 5d%-10s %-15s\tservice\n", s_port, s_state, s_service, ((unsigned *)user)[U_SCANNED_PORT], s_proto, state);
	free(state);
}

bool tcp_test_port(pcap_t **handle_pcap, struct sockaddr_in *addr, char *ip_dest, int port)
{
	u_char user[BUFSIZ];
	user[U_SCAN_TYPE] = N_SYN; //*SEND FLAG
	((unsigned*)user)[U_SCANNED_PORT] = port;

	t_tcp_vars *tcp_vars = init_tcp_packet(addr, ip_dest, port, user[U_SCAN_TYPE]);
	if (!tcp_vars || !send_tcp_packet(tcp_vars))
		return false;

	int rtn = pcap_dispatch(*handle_pcap, 65535, pcap_handler_fn, user);
	if (rtn == PCAP_ERROR)
	{
		pcap_geterr(*handle_pcap);
		pcap_breakloop(*handle_pcap);
		return false;
	}

	print_result(rtn, user);

	pcap_breakloop(*handle_pcap);
	free(tcp_vars);
	return true;
}
