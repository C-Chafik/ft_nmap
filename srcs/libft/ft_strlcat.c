/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strlcat.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cmarouf <marvin@42.fr>                     +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/07 18:37:42 by cmarouf           #+#    #+#             */
/*   Updated: 2021/09/09 18:56:42 by cmarouf          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */
#include "libft.h"

size_t	ft_strlcat(char *dst, const char *src, size_t size)
{
	size_t			i;
	size_t			j;
	size_t			p;
	size_t			temp;

	p = ft_strlen(src);
	j = ft_strlen(dst);
	temp = j;
	i = 0;
	if (j >= size)
		return (p + size);
	while (temp < size - 1 && src[i])
	{
		dst[temp] = src[i];
		temp++;
		i++;
	}
	dst[temp] = '\0';
	return (p + j);
}
