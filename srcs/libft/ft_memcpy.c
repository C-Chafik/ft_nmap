/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memcpy.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cmarouf <marvin@42.fr>                     +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/07 16:21:19 by cmarouf           #+#    #+#             */
/*   Updated: 2021/10/14 18:57:08 by cmarouf          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */
#include "libft.h"

void	*ft_memcpy(void *dest, const void *src, size_t n)
{
	long unsigned int	i;
	unsigned char		*dest1;
	const unsigned char	*src1;

	if (!src && !dest)
		return (NULL);
	src1 = src;
	dest1 = dest;
	i = 0;
	while (i < n)
	{
		dest1[i] = src1[i];
		i++;
	}
	return (dest);
}
