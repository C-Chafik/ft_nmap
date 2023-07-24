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

short check_tcp_port_state(const u_char *tcp_header, u_char flags)
{
	if (flags == N_XMAS || flags == N_NULL || flags == N_FIN){
		if (*(tcp_header + TCP_RSP_FLAG_OFF) & RST)
			return CLOSE;
	}
	else if (flags == N_SYN){
		if (*(tcp_header + TCP_RSP_FLAG_OFF) == (SYN | ACK))
			return OPEN;
		else if (*(tcp_header + TCP_RSP_FLAG_OFF))
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
	char static_service[8] = "service";
	char *state = NULL;

	printf("rtn: %d\n", rtn);
	if (rtn == -2){//* TIMEOUT
		if (user[U_SCAN_TYPE] == N_XMAS || user[U_SCAN_TYPE] == N_FIN || user[U_SCAN_TYPE] == N_NULL)
			state = ft_strdup("open | filtered");
		if (user[U_SCAN_TYPE] == N_SYN || user[U_SCAN_TYPE] == N_ACK)
			state = ft_strdup("filtered");
	}
	else {
		if (user[U_SCAN_TYPE] == N_ACK){
			state = ft_strdup("unfiltered");
		}
		else{
			if (user[U_PORT_STATE] == CLOSE)
				state = ft_strdup("close");
			else if (user[U_PORT_STATE] == OPEN)
				state = ft_strdup("open");
			else{
				printf("SCAN TYPE = %d | PORT STATE = %d\n", user[U_SCAN_TYPE], user[U_PORT_STATE]);
			}
		}
	}
	if (!state){
		fprintf(stderr, ANSI_COLOR_RED"Fail to malloc the string for the state\n"ANSI_COLOR_RESET);
		return;
	}
	printf("%-15s %-15s %-15s %-15s\n% 5d%-10s %-15s %-15s %-15s\n\n",
		s_port, s_state, s_service, s_scan, ((unsigned *)user)[U_SCANNED_PORT], s_proto, state, static_service, scan_type);
	free(state);
}

t_tcp_vars *tcp_vars = NULL;
pcap_t *handle_pcap_cpy = NULL;
u_char user[BUFSIZ] = {0};

static void handle_alarm_to(int sig, siginfo_t *si, void *unused){
	(void)sig;
	(void)si;
	(void)unused;
	printf("> %s <\n", sig == SIGALRM ? "SIGALRM" : "WRONG SIGNAL");
	pcap_breakloop(handle_pcap_cpy);
}

bool tcp_test_port(pcap_t **handle_pcap, struct sockaddr_in *addr, char *ip_dest, int port, char *scan_type)
{
	user[U_SCAN_TYPE] = which_scan(scan_type);
	if (user[U_SCAN_TYPE] == 127)
		return false;
	((unsigned*)user)[U_SCANNED_PORT] = port;

	tcp_vars = init_tcp_packet(addr, ip_dest, port, user[U_SCAN_TYPE]);
	if (!tcp_vars || !send_tcp_packet(tcp_vars))
		return false;

	handle_pcap_cpy = *handle_pcap;
	struct sigaction sa = {0};
	sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = handle_alarm_to;
	if (sigaction(SIGALRM, &sa, NULL) == -1){
		perror("sigaction");
		pcap_breakloop(*handle_pcap);
		free(tcp_vars);
	}
	alarm(2);
	int rtn = pcap_dispatch(*handle_pcap, 65535, pcap_handler_fn, user);
	alarm(0);
	if (rtn == PCAP_ERROR)
	{
		pcap_geterr(*handle_pcap);
		pcap_breakloop(*handle_pcap);
		return false;
	}

	print_result(rtn, user, scan_type);

	pcap_breakloop(*handle_pcap);
	free(tcp_vars);
	return true;
}
