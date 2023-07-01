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


typedef struct s_thread_info
{
	char		*target_hostname;
	char		*output;
	int 		port;
	char		*scan_type;
}   			t_thread_info;

typedef struct s_target
{
	char 			*hostname;
}   				t_target;


typedef struct s_context
{
    t_target   		*targets; // All the host to configuration
	t_thread_info 	*workers; // Pointer to all the threads
    int         	target_count;
    int         	thread_count;
	int				port_count;
	int             *ports; // Port given alone
	char			*scan_types[SCAN_COUNT]; // Tout les types de scan a proceder
	char			**hostnames; // All the hostname to map
}   				t_context;

#endif