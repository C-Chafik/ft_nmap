/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_itoa.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cmarouf <marvin@42.fr>                     +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/10 00:35:45 by cmarouf           #+#    #+#             */
/*   Updated: 2021/10/14 01:47:59 by cmarouf          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */
#include "libft.h"

void	putnbstr(char *str, long n, int i)
{
	if (n == 0)
	{
		str[0] = '0';
		str[1] = '\0';
		return ;
	}
	i--;
	if (n < 0)
		n = -n;
	while (n > 0)
	{
		str[i] = (n % 10) + 48;
		n = n / 10;
		i--;
	}
}

char	*ft_itoa(int n)
{
	int			i;
	long		nbr;
	char		*str;

	i = 0;
	nbr = n;
	if (nbr < 0)
	{
		i++;
		nbr = -nbr;
	}
	while (nbr > 0)
	{
		nbr = nbr / 10;
		i++;
	}
	str = malloc(sizeof(char) * (i + 1) + (n == 0));
	if (!str)
		return (NULL);
	if (n < 0)
		str[0] = '-';
	str[i] = '\0';
	putnbstr(str, (long)n, i);
	return (str);
}
