#include "./includes/ft_nmap.h"

/*

    PARSING - HANDLER

*/

/*
Help Screen
ft_nmap [OPTIONS]
--help Print this help screen
--ports ports to scan (eg: 1-10 or 1,2,3 or 1,5-15)
--ip ip addresses to scan in dot format
--file File name containing IP addresses to scan,
--speedup [250 max] number of parallel threads to use
--scan SYN/NULL/FIN/XMAS/ACK/UDP
*/


static int handle_help_menu(void)
{
    printf("ft_nmap [OPTIONS]\n");
    printf("--help Print this help screen\n");
    printf("--ports ports to scan (eg: 1-10 or 1,2,3 or 1,5-15)\n");
    printf("--ip ip addresses to scan in dot format\n");
    printf("--file File name containing IP addresses to scan,\n");
    printf("--speedup [250 max] number of parallel threads to use\n");
    printf("--scan SYN/NULL/FIN/XMAS/ACK/UDP\n");
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
    int fd;

    fd = 0;
    if (context->hostnames != NULL) 
    {
        fprintf(stderr, "Multiple --ip or --file arguments provided. Only one is allowed.\n");
        return -1;
    }
    else if (ft_strncmp(av, "/dev/", 5) == 0)
    {
        fprintf(stderr, "Please put a valid file and be kind\n");
        return -1;
    }

    fd = open(av, O_RDONLY);
    if (fd < 0)
    {
        perror("Failed to open file");
        return -1;
    }

    char *ptr = NULL;
    char *buff = NULL;
    char *file_content = ft_strdup("");

    while ((buff = get_next_line(fd)))
    {
        ptr = file_content;
        file_content = ft_strjoin(file_content, buff);
        if (buff)
            free(buff);
        if (ptr)
            free(ptr);
    }

    context->hostnames = ft_split(file_content, '\n');
    if (!context->hostnames)
    {
        perror("Failed to allocate memory for context->hostnames array.\n");
        if (file_content)
            free(file_content);
        close(fd);
        return -1;
    }

    if (file_content)
        free(file_content);
    close(fd);
    return 0;
}

static int parse_thread_count(t_context *context, char *av)
{
    int thread_count;

    thread_count = ft_atoi(av);

    if (thread_count <= 0 || thread_count > 250) 
    {
        fprintf(stderr, "Invalid speedup number. speed must be between 1 and 250.\n");
        return -1;
    }
    
    context->thread_count = thread_count;
    return 0;
}

static int parse_scan_type(t_context *context, char *av)
{

    // Initially set all scans to false (assuming 0 is false)
    for (int i = 0; i < SCAN_COUNT; ++i) 
        context->scan_types[i] = NULL;

    char **scan_types = NULL;

    scan_types = ft_split(av, '/');
    if (!scan_types)
    {
        perror("Failed to allocate memory for scan_types array.\n");
        return -1;
    }

    if (d_ptrlen(scan_types) == 0)
    {
        free_tab(scan_types);
        fprintf(stderr, "Invalid scan type\n");
        return -1;
    }

    for (int i = 0; scan_types[i] != NULL; i++)
    {
        if (ft_strncmp(scan_types[i], "SYN", 3) == 0) 
            context->scan_types[SCAN_SYN] = "SYN";
        else if (ft_strncmp(scan_types[i], "NULL", 4) == 0) 
            context->scan_types[SCAN_NULL] = "NULL";
        else if (ft_strncmp(scan_types[i], "FIN", 3) == 0) 
            context->scan_types[SCAN_FIN] = "FIN";
        else if (ft_strncmp(scan_types[i], "XMAS", 4) == 0) 
            context->scan_types[SCAN_XMAS] = "XMAS";
        else if (ft_strncmp(scan_types[i], "ACK", 3) == 0) 
            context->scan_types[SCAN_ACK] = "ACK";
        else if (ft_strncmp(scan_types[i], "UDP", 3) == 0) 
            context->scan_types[SCAN_UDP] = "UDP";
        else
        {
            fprintf(stderr, "Invalid scan type: %s\n", scan_types[i]);
            free_tab(scan_types);
            return -1;
        }
    }

    free_tab(scan_types);
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

int check_results(t_context *context)
{
    if (!context->ports)
    {
        fprintf(stderr, "No port to map were given.\n");
        return -1;
    }
    else if (!context->hostnames)
    {
        fprintf(stderr, "No hostnames to map were given.\n");
        return -1;
    }
    else if (!context->scan_types)
    {
        fprintf(stderr, "No scans to perform were given.\n");
        return -1;
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
    if (check_results(context) == -1)
        return -10;
    return 0;
}