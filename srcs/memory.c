#include "./includes/ft_nmap.h"

void free_tab(char **d_ptr)
{
    if (d_ptr)
    {
        for (int i = 0; d_ptr[i] != NULL; ++i)
        {
            free(d_ptr[i]);
        }
        free(d_ptr);
    }
}

void    free_context(t_context *context)
{
    if (context->ports)
        free(context->ports);
    if (context->hostnames)
        free_tab(context->hostnames);
}