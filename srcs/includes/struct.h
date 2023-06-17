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
	int 		port;
	int			scan_type;
}   t_thread_info;

typedef struct s_target
{
    char             *ranged_port;
	char 			*hostname;
	int				scan_types[MAX_SCANS];
	int             *stock_port;
	int				*all_ports;
}   t_target;


typedef struct s_context
{
    t_target   *targets; // Un tableau de cibles
	t_thread_info 	*workers;
    int         target_count; // Nombre de cibles
    int         thread_count;

}   t_context;

#endif