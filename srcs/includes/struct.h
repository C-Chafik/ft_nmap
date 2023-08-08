#ifndef STRUCT_H
# define STRUCT_H

# include "./includes.h"

enum e_scan_type
{
	SCAN_SYN,
	SCAN_NULL,
	SCAN_ACK,
	SCAN_FIN,
	SCAN_XMAS,
	SCAN_UDP,
	SCAN_COUNT
};

enum e_tcp_flags
{
	URG = 32,
	ACK = 16,
	PSH = 8,
	RST = 4,
	SYN = 2,
	FIN = 1
};

enum e_nmap_flags
{
	N_NULL = 0,
	N_SYN = SYN,
	N_ACK = ACK,
	N_FIN = FIN,
	N_XMAS = (FIN | PSH | URG),
	N_UDP
};

enum e_port_state
{
	FILTERED = 1,
	OPEN = 2,
	CLOSE = 4
};

struct pseudo_header
{
	u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t tcp_length;
};

typedef struct s_thread_info
{
	char *target_hostname;
	char *output;
	int port;
	int scan_type;
} t_thread_info;

typedef struct s_target
{
	char *hostname;
} t_target;

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

typedef struct s_context
{
	t_target *targets;		// All the host to configuration
	t_thread_info *workers; // Pointer to all the threads
	int target_count;
	int thread_count;
	int port_count;
	int *ports;					  // Port given alone
	char *scan_types[SCAN_COUNT]; // Tout les types de scan a proceder
	char **hostnames;			  // All the hostname to map
} t_context;

struct socket_info{
	int fd;
	pcap_t **handle_pcap;
	struct sockaddr_in *addr;
	char *final_hostname;
	int port;
	char *scan_types;
	struct socket_info *next;
};

#endif