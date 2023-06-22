#include "./includes/ft_nmap.h"

void print_parsing_results(t_context *context)
{
	printf(" === PARSING RESULT ===\n");
	printf("HOSTNAMES :\n");
	if (context->hostnames)
	{
		for (int i = 0; context->hostnames[i]; i++)
			printf(" | %s", context->hostnames[i]);
	}
	printf("\n");
	printf("PORTS :\n");
	if (context->ports)
	{
		for (int i = 0; i < context->port_count; i++)
			printf(" | %d", context->ports[i]);
	}
	printf("\n");
	printf("THREAD_COUNT :\n");
	if (context->thread_count)
		printf(" | %d\n", context->thread_count);
	printf("SCAN_TYPES :\n");
	if (context->scan_types)
	{
		for (int i = 0; i < SCAN_COUNT; i++)
			if (context->scan_types[i])
				printf(" | %s", context->scan_types[i]);
	}
	printf("\n");
	printf(" === PARSING RESULT ===\n");
}

static void ft_swap(int	*a, int	*b)
{
	int	temp;

	temp = *a;
	*a = *b;
	*b = temp;
}

void	ft_sort_int_tab(int *tab, int size)
{
	int	d;
	int	f;

	d = 0;
	f = 0;
	while (d < size)
	{
		f = d + 1;
		while (f < size)
		{
			if (tab[d] > tab[f])
			{
				ft_swap(&tab[f], &tab[d]);
			}
			f++;
		}
		d++;
	}
}

int d_ptrlen(char **d_ptr)
{
    int len = 0;

    while (d_ptr[len])
        ++len;

    return len;
}

int is_number(const char *str)
{
    for (int i = 0; str[i]; i++)
    {
        if (!ft_isdigit(str[i]))
            return -1;
    }
    return 0;
}