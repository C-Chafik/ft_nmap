#include "../includes/ft_nmap.h"
#include "../includes/includes.h"
#include "../includes/define.h"

u_char which_scan(char *scan_type){
	if (!ft_strncmp(scan_type, "SYN", 3))
		return N_SYN;
	else if (!ft_strncmp(scan_type, "NULL", 4))
		return N_NULL;
	else if (!ft_strncmp(scan_type, "ACK", 3))
		return N_ACK;
	else if (!ft_strncmp(scan_type, "FIN", 3))
		return N_FIN;
	else if (!ft_strncmp(scan_type, "XMAS", 4))
		return N_XMAS;
	else if (!ft_strncmp(scan_type, "UDP", 3))
		return N_UDP;
	else
		return 127;
}

short check_tcp_port_state(const u_char tcp_response_flags, u_char scan_type)
{
	if (scan_type == N_XMAS || scan_type == N_NULL || scan_type == N_FIN){
		if (tcp_response_flags & RST)
			return CLOSE;
		else
			return OPEN | FILTERED;
	}
	else if (scan_type == N_SYN){
		if (tcp_response_flags == (SYN | ACK))
			return OPEN;
		else if (tcp_response_flags)
			return CLOSE;
	}

	return FILTERED;
}

void print_result(int rtn, u_char *user, char *scan_type){
	char s_port[5] = "PORT";
	char s_state[6] = "STATE";
	char s_service[8] = "SERVICE";
	char s_scan[5] = "SCAN";
	char s_proto[5] = "/tcp";
	char *state = NULL;

	int port = ((unsigned *)user)[U_SCANNED_PORT];
	struct servent *serv;
	serv = getservbyport(htons(port), "tcp");
	
	if (rtn == 1){//* TIMEOUT
		if (user[U_SCAN_TYPE] == N_XMAS || user[U_SCAN_TYPE] == N_FIN || user[U_SCAN_TYPE] == N_NULL)
			state = ft_strdup("open | filtered");
		if (user[U_SCAN_TYPE] == N_SYN || user[U_SCAN_TYPE] == N_ACK)
			state = ft_strdup("filtered");
			// state = NULL;//! same as nmap
	}
	else {
		short rtn_state = check_tcp_port_state(user[U_TCP_RTN], user[U_SCAN_TYPE]);
		if (user[U_SCAN_TYPE]  == N_ACK){
			state = ft_strdup("unfiltered");
		}
		else{
			if (rtn_state == CLOSE)
				state = ft_strdup("close");
				// state = /*ft_strdup("close")*/NULL;//! same as nmap
			else if (rtn_state == OPEN)
				state = ft_strdup("open");
			else if (rtn_state == (OPEN | FILTERED))
				state = ft_strdup("open | filtered");
			else{//TIMEOUT
				// if (user[U_SCAN_TYPE] == N_XMAS || user[U_SCAN_TYPE] == N_FIN || user[U_SCAN_TYPE] == N_NULL)
				// 	state = ft_strdup("open | filtered");
				// if (user[U_SCAN_TYPE] == N_SYN || user[U_SCAN_TYPE] == N_ACK)
				// 	state = ft_strdup("filtered");
				printf("AGAIN!? (rtn: %d)\n", rtn_state);
			}
		}
	}
	// if (!state){
	// 	fprintf(stderr, ANSI_COLOR_RED"Fail to malloc the string for the state\n"ANSI_COLOR_RESET);
	// 	return;
	// }
	if (state){
		printf("%-15s %-15s %-15s %-15s\n% 5d%-10s %-15s %-15s %-15s\n\n",
			s_port, s_state, s_service, s_scan, ((unsigned *)user)[U_SCANNED_PORT], s_proto, state, serv ? serv->s_name : "undefined", scan_type);
		free(state);
	}
}

bool tcp_test_port(pcap_t **handle_pcap, struct sockaddr_in *addr, char *ip_dest, int port, char *scan_type, int sock) 
{
	u_char user[BUFSIZ] = {0};
	user[U_SCAN_TYPE] = which_scan(scan_type);
	if (user[0] == 127)
		return false;
	((unsigned*)user)[U_SCANNED_PORT] = port;

	t_tcp_vars *tcp_vars = init_tcp_packet(sock, addr, ip_dest, port, user[U_SCAN_TYPE]);
	if (!tcp_vars || !send_tcp_packet(tcp_vars))
		return false;

	int rtn = pcap_dispatch(*handle_pcap, 65535, pcap_handler_fn, user);
	if (rtn == PCAP_ERROR)
	{
		pcap_geterr(*handle_pcap);
		pcap_breakloop(*handle_pcap);
		return false;
	}

	print_result(rtn, user, scan_type);

	free(scan_type);
	pcap_breakloop(*handle_pcap);
	free(tcp_vars);
	return true;
}
