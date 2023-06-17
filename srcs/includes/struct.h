#ifndef STRUCT_H
# define STRUCT_H

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

typedef struct s_target
{
	char 		*hostname;
	int 		port;
	scan_type_t	scan_type;
}   t_target;

typedef struct s_thread_info
{
    pthread_t   thread;
    target_t    target;
}   t_thread_info;

typedef struct s_context
{
    target_t    *targets; // Un tableau de cibles
    int         target_count; // Nombre de cibles
    int         thread_count;
    scan_type_t scan_types[SCAN_COUNT];
    // Autres informations...
}   t_context;

global_config_t g_config;

#endif