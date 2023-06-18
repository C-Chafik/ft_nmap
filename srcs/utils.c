#include "./includes/ft_nmap.h"

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
            return 1;
    }
    return 0;
}