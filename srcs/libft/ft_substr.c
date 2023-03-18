/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_substr.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cmarouf <marvin@42.fr>                     +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/09 20:52:44 by cmarouf           #+#    #+#             */
/*   Updated: 2021/10/14 05:22:40 by cmarouf          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */
#include "libft.h"

char	*ft_substr(char const *s, unsigned int start, size_t len)
{
	char	*dest;
	size_t	i;
	size_t	j;

	if (!s)
		return (NULL);
	i = -1;
	j = 0;
	if (ft_strlen(s) < start)
		return (ft_strdup(""));
	if (ft_strlen(&s[start]) < len)
		len = ft_strlen(&s[start]);
	dest = (char *)malloc(sizeof(char) * (len) + 1);
	if (!dest)
		return (NULL);
	while (s[++i])
	{
		if (i >= start && j < len)
		{
			dest[j] = s[i];
			j++;
		}
	}
	dest[j] = '\0';
	return (dest);
}
