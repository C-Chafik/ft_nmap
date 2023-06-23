#ifndef STRUCT_H
#define STRUCT_H

#include "./includes.h"

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

typedef struct s_context
{
	t_target *targets;		// All the host to configuration
	t_thread_info *workers; // Pointer to all the threads
	int target_count;
	int thread_count;
	int port_count;
	int *ports;				   // Port given alone
	int scan_types[MAX_SCANS]; // Tout les types de scan a proceder
	char *file_path;		   // File path to all the hostnames
	char **hostnames;		   // All the hostname to map
} t_context;

#endif

// ./ft_nmap --help
// Help Screen
// ft_nmap [OPTIONS]
// --help Print this help screen
// --ports ports to scan (eg: 1-10 or 1,2,3 or 1,5-15)
// --ip ip addresses to scan in dot format
// --file File name containing IP addresses to scan,
// --speedup [250 max] number of parallel threads to use
// --scan SYN/NULL/FIN/XMAS/ACK/UDP