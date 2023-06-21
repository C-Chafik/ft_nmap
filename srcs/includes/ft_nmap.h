#ifndef FT_NMAP_H
# define FT_NMAP_H

# include "./define.h"
# include "./struct.h"
# include "./includes.h"


int init_parsing(t_context *context, int ac, char **av);


void print_parsing_results(t_context *context);
void    free_tab(char **d_ptr);
int     d_ptrlen(char **d_ptr);
int     is_number(const char *str);
void	ft_sort_int_tab(int *tab, int size);

void    free_context(t_context *context);

#endif