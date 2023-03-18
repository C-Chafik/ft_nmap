/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strnstr.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cmarouf <marvin@42.fr>                     +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/07 23:46:01 by cmarouf           #+#    #+#             */
/*   Updated: 2021/09/09 20:01:32 by cmarouf          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */
#include "libft.h"

char	*ft_strnstr(const char *big, const char *little, size_t len)
{
	long unsigned int	i;
	int					j;
	int					p;

	i = 0;
	if (little[0] == '\0' || little == NULL)
		return ((char *)big);
	while (big[i] != '\0' && i < len)
	{
		j = 0;
		p = i;
		while (big[p] == little[j] && i + j < len)
		{
			j++;
			p++;
			if (little[j] == '\0')
				return ((char *)&big[i]);
		}
		i++;
	}
	return (NULL);
}
