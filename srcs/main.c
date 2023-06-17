#include "./includes/ft_nmap.h"
#include <string.h>

int check_arguments(char **av, int *i)
{
     if (strcmp(argv[*i], "--ports") == 0)
        return parse_ports(argv[*i]);
    else if (strcmp(argv[*i], "--file") == 0)
        return parse_file(argv[*i]);
    else if (strcmp(argv[*i], "--speedup") == 0)
        return parse_thread_count(argv[*i]);
    else if (strcmp(argv[*i], "--scan") == 0)
        return parse_scan_type(argv[*i]);
    else if (strcmp(argv[*i], "--ip") == 0)
        return parse_ip(argv[*i]);
    else
    {
        fprintf(stderr, "ft_nmap: unrecognized option '%s'", av[i]);
        return 1;
    }
    return 0;
}

void check_help_menu(int ac, char **av)
{
    int i;

    i = 1;
    // First we are checking if the --help menu is specified
    // If it is we just print the help menu and quit the program whatever other flags are specified
    while ( i < ac )
    {
        if (ft_strncmp(av[i], "--help", ft_strlen(av[1])) == 0)
        {
            fprintf(stdout, "Print help and exit the program whatever other argument there are.\n");
            // Call the help function there
            exit(0);
        }
        i++;
    }
}

int init_parsing(int ac, char **av)
{
    int i;

    i = 1;
    check_help_menu(ac, av);

    while (i < ac)
    {
        if (i + 1 < argc)
            if (check_arguments(av, &i) == 1)
                return 1;
        else
        {
            printf(stderr, "ft_nmap: option '%s' require an argument.\n", av[i]);
            return 1;
        }
        i++;
    }

    return 0;
}

int main(int ac, char **av)
{
    int exit_code;

    if ( ac < 2 )
        return 1;

    exit_code = init_parsing(ac, av);
    if (exit_code > 0)
        return exit_code;

    return 0;
}