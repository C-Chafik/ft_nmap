#include "./includes/ft_nmap.h"

static void init_scan_types(int *scan_types)
{
	scan_types[SCAN_SYN] = SCAN_SYN;
	scan_types[SCAN_NULL] = SCAN_NULL;
	scan_types[SCAN_ACK] = SCAN_ACK;
	scan_types[SCAN_FIN] = SCAN_FIN;
	scan_types[SCAN_XMAS] = SCAN_XMAS;
	scan_types[SCAN_UDP] = SCAN_UDP;
}

static void init_context(t_context *context)
{
	context->targets = NULL;
	context->workers = NULL;
	context->target_count = 0;
	context->thread_count = 0;
	context->port_count = 0;
	context->ports = NULL;
	context->file_path = NULL;
	context->hostnames = NULL;
	init_scan_types(context->scan_types);
}

int main(int ac, char **av)
{
	t_context   context;
	int         exit_code;

	if ( ac < 2 )
		return 1;

	init_context(&context);

	exit_code = init_parsing(&context, ac, av);
	if (exit_code > 0)
	{
		free_context(&context);
		return exit_code;
	}

	tcp_tester();

	free_context(&context);
	return 0;
}