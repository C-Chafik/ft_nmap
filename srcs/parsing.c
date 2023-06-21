#include "./includes/ft_nmap.h"

/*

    PARSING - HANDLER

*/

static int handle_help_menu(void)
{
    fprintf(stdout, "Print help and exit the program whatever other argument there are.\n");
    return 0;
}

/*

    PARSING - PARSER

*/


static int count_ports(char *av)
{
    int count = 0;

    char **raw_ports = ft_split(av, ',');
    if (!raw_ports)
    {
        perror("Failed to allocate memory for raw_ports array.\n");
        return -1;
    }

    for (int i = 0; raw_ports[i]; i++)
    {
        if (ft_strchr(raw_ports[i], '-'))
        {
            // The part is a range, count the number of ports in the range
            char **range_ports = ft_split(raw_ports[i], '-');
            if (!range_ports)
            {
                perror("Failed to allocate memory for range_ports array.\n");
                free_tab(raw_ports);
                return -1;
            }
            if (d_ptrlen(range_ports) != 2)
            {
                fprintf(stderr, "Range ports given is invalid: %s\n", raw_ports[i]);
                free_tab(range_ports);
                free_tab(raw_ports);
                return -1;
            }
            if (is_number(range_ports[0]) == -1 || is_number(range_ports[1]) == -1)
            {
                fprintf(stderr, "Invalid port number in range: %s\n", raw_ports[i]);
                free_tab(range_ports);
                free_tab(raw_ports);
                return -1;
            }
            int start = atoi(range_ports[0]);
            int end = atoi(range_ports[1]);

            // Check if the range is valid
            if (start > end)
            {
                fprintf(stderr, "Invalid ranged port given: %s\n", raw_ports[i]);
                free_tab(range_ports);
                free_tab(raw_ports);
                return -1;
            }
            
            // Check if the start and end ports are within valid range
            if (start < 0 || end < 0 || start > 65535 || end > 65535)
            {
                fprintf(stderr, "Ports must be in the range 0-65535: %s\n", raw_ports[i]);
                free_tab(range_ports);
                free_tab(raw_ports);
                return -1;
            }

            count += end - start + 1;
            free_tab(range_ports);
        }
        else
        {
            if (is_number(raw_ports[i]) == -1)
            {
                fprintf(stderr, "Invalid port number: %s\n", raw_ports[i]);
                free_tab(raw_ports);
                return -1;
            }
            int port = ft_atoi(raw_ports[i]);

            // Check if the port is within valid range
            if (port < 0 || port > 65535)
            {
                fprintf(stderr, "Ports must be in the range 0-65535: %s\n", raw_ports[i]);
                free_tab(raw_ports);
                return -1;
            }

            count++;
        }
    }

    free_tab(raw_ports);
    return count;
}

void sort_and_tag_duplicate(int *tab, int len)
{
    for (int i = 0; i < len; i++)
        for (int j = i + 1; j < len ; j++)
            if (tab[j] == tab[i])
                tab[j] = 65536;
    ft_sort_int_tab(tab, len);
}

int parse_ports(t_context *context, char *av)
{
    char **raw_ports = ft_split(av, ',');
    if (!raw_ports)
    {
        perror("Failed to allocate memory for raw_ports array.\n");
        return -1;
    }
    int total_ports = count_ports(av);

    if (total_ports == -1)
    {
        free_tab(raw_ports);
        return -1;
    }

    context->ports = malloc(sizeof(int) * total_ports);
    if (!context->ports)
    {
        perror("Failed to allocate memory for all_ports array.\n");
        free_tab(raw_ports);
        return -1;
    }

    int ports_index = 0;

    for (int i = 0; raw_ports[i]; i++)
    {
        if (ft_strchr(raw_ports[i], '-'))
        {
            // The part is a range, count the number of ports in the range
            char **range_ports = ft_split(raw_ports[i], '-');
            if (!range_ports)
            {
                perror("Failed to allocate memory for range_ports array.\n");
                free(context->ports);
                free_tab(raw_ports);
                return -1;
            }
            int start = atoi(range_ports[0]);
            int end = atoi(range_ports[1]);
            free_tab(range_ports);

            for (int port = start; port <= end; port++)
                context->ports[ports_index++] = port;
        }
        else
            context->ports[ports_index++] = atoi(raw_ports[i]);
    }
    free_tab(raw_ports);


    sort_and_tag_duplicate(context->ports, total_ports);

    int duplicate_count = 0;

    for (int i = 0; i < total_ports; i++)
    {
        if (context->ports[i] == 65536)
            duplicate_count++;
    }

    total_ports -= duplicate_count;
    context->port_count = total_ports;
    return 0;
}

static int parse_file(t_context *context, char *av)
{
    (void)av;
    (void)context;
    printf("%s\n", av);
    return 0;
}

static int parse_thread_count(t_context *context, char *av)
{
    (void)context;
    (void)av;
    printf("%s\n", av);
    return 0;
}

static int parse_scan_type(t_context *context, char *av)
{
    (void)context;
    (void)av;
    printf("%s\n", av);
    return 0;
}

static int parse_ip(t_context *context, char *av)
{
     /*
        In the case of the --ip option, since we accept only one argument, only one allocation is made.
    */

    if (context->hostnames != NULL) 
    {
        fprintf(stderr, "Multiple --ip or --file arguments provided. Only one is allowed.\n");
        return -1;
    }

    context->hostnames = (char**)malloc(2 * sizeof(char*));
    if (context->hostnames == NULL)
    {
        perror("Failed to allocate memory for hostnames array.\n");
        return -1;
    }

    context->hostnames[0] = ft_strdup(av);
    if (context->hostnames[0] == NULL)
    {
        perror("Failed to allocate memory for hostname.\n");
        free_tab(context->hostnames);
        return -1;
    }

    context->hostnames[1] = NULL; // Double pointer NULL terminator
    return 0;
}

static int parse_arguments(t_context *context, char **av, int *i)
{
    if (ft_strncmp(av[*i], "--ports", ft_strlen(av[*i])) == 0)
        return parse_ports(context, av[*i + 1]);
    else if (ft_strncmp(av[*i], "--file", ft_strlen(av[*i]))== 0)
        return parse_file(context, av[*i + 1]);
    else if (ft_strncmp(av[*i], "--speedup", ft_strlen(av[*i])) == 0)
        return parse_thread_count(context, av[*i + 1]);
    else if (ft_strncmp(av[*i], "--scan", ft_strlen(av[*i])) == 0)
        return parse_scan_type(context, av[*i + 1]);
    else if (ft_strncmp(av[*i], "--ip", ft_strlen(av[*i])) == 0)
        return parse_ip(context, av[*i + 1]);
    else
    {
        fprintf(stderr, "ft_nmap: unrecognized option '%s'", av[*i]);
        return -1;
    }

    return 0;
}


/*

    PARSING - CHECKER

*/

static int check_help_menu(int ac, char **av)
{
    int i;

    i = 1;
    while ( i < ac )
    {
        if (ft_strncmp(av[i], "--help", ft_strlen(av[1])) == 0)
            return handle_help_menu();
        i++;
    }

    return -1;
}

static int check_arguments_validity(char *arg)
{
    if (ft_strncmp(arg, "--ports", ft_strlen(arg)) == 0)
        return 0;
    else if (ft_strncmp(arg, "--file", ft_strlen(arg))== 0)
        return 0;
    else if (ft_strncmp(arg, "--speedup", ft_strlen(arg)) == 0)
        return 0;
    else if (ft_strncmp(arg, "--scan", ft_strlen(arg)) == 0)
        return 0;
    else if (ft_strncmp(arg, "--ip", ft_strlen(arg)) == 0)
        return 0;
    return -1;
}

static int check_arguments(t_context *context, int ac, char **av)
{
    int i;

    i = 1;
    while (i < ac)
    {
        if (i + 1 < ac)
        {
            if (parse_arguments(context, av, &i) == -1)
                return -1;
            i = i + 1;
        }
        else if (check_arguments_validity(av[i]) == -1)
        {
            fprintf(stderr, "ft_nmap: unrecognized option '%s'", av[i]);
            return -1;
        }
        else
        {
            fprintf(stderr, "ft_nmap: option '%s' require an argument...\n", av[i]);
            return -1;
        }
        i++;
    }
    return 0;
}

/*

    PARSING - INIT

*/

int init_parsing(t_context *context, int ac, char **av)
{
    if (check_help_menu(ac, av) == 0)
        exit(EXIT_SUCCESS);
    if (check_arguments(context, ac, av) == -1)
        return -1;
    return 0;
}