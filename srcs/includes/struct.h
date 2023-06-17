#ifndef STRUCT_H
# define STRUCT_H

# include "./define.h"

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


typedef struct s_thread_info
{
	char		*target_hostname;
	char		*output;
	int 		port;
	int			scan_type;
}   			t_thread_info;

typedef struct s_target
{
	char 			*hostname;
	int				*ports;
}   				t_target;


typedef struct s_context
{
    t_target   		*targets; // All the host to configuration
	t_thread_info 	*workers; // Pointer to all the threads
    int         	target_count;
    int         	thread_count;
	int				port_count;
	int             *stock_port; // Port given alone
	int				scan_types[MAX_SCANS]; // Tout les types de scan a proceder
    char            *ranged_port; // Port given in a range
	char			*file_path; // File path to all the hostnames
	char			**hostnames; // All the hostname to map
}   				t_context;

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