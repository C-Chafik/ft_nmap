#include "./includes/ft_nmap.h"

static void init_scan_types(char **scan_types)
{
    scan_types[SCAN_SYN] = "SYN";
    scan_types[SCAN_NULL] = "NULL";
    scan_types[SCAN_ACK] = "ACK";
    scan_types[SCAN_FIN] = "FIN";
    scan_types[SCAN_XMAS] = "XMAS";
    scan_types[SCAN_UDP] = "UDP";
    scan_types[SCAN_COUNT] = NULL;
}

static void init_context(t_context *context)
{
    context->targets = NULL;
    context->workers = NULL;
    context->target_count = 0;
    context->thread_count = 0;
    context->port_count = 0;
    context->ports = NULL;
    context->hostnames = NULL;
    init_scan_types(context->scan_types);
}

int main(int ac, char **av)
{
    t_context   context;
    int         exit_code;

    if ( ac < 2 )
        return EXIT_FAILURE;

    init_context(&context);

    exit_code = init_parsing(&context, ac, av);
    if (exit_code < 0)
    {
        free_context(&context);
        return EXIT_FAILURE;
    }

    print_parsing_results(&context);

    free_context(&context);
    return EXIT_SUCCESS;
}