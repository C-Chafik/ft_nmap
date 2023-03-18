/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_split.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cmarouf <marvin@42.fr>                     +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/09 23:02:30 by cmarouf           #+#    #+#             */
/*   Updated: 2021/09/10 00:29:28 by cmarouf          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */
#include "libft.h"

int	is_charset(char i, char c)
{
	if (i == c)
		return (1);
	return (0);
}

int	word_count(char const *s, char c)
{
	int		i;
	int		word;

	i = 0;
	word = 0;
	while (s[i])
	{
		if (is_charset(s[i], c) == 0)
		{
			if (i == 0)
				word++;
			else if (is_charset(s[i - 1], c) == 1)
				word++;
		}
		i++;
	}
	return (word);
}

char	*get_string(char const *s, char c)
{
	int		i;
	int		size;
	char	*tosplit;

	i = 0;
	size = 0;
	while (is_charset(s[i], c) == 0 && s[i])
	{
		size++;
		i++;
	}
	tosplit = malloc(sizeof(char) * (size + 1));
	i = 0;
	while (is_charset(s[i], c) == 0 && s[i])
	{
		tosplit[i] = s[i];
		i++;
	}
	tosplit[i] = '\0';
	return (tosplit);
}

char	**ft_split(char const *s, char c)
{
	int		i;
	int		j;
	char	**split;

	if (!s)
		return (NULL);
	i = -1;
	j = -1;
	split = malloc(sizeof(char *) * (word_count(s, c) + 1));
	if (!split)
		return (NULL);
	split[word_count(s, c)] = NULL;
	while (s[++i])
	{
		if (is_charset(s[i], c) == 0 && i == 0)
			split[++j] = get_string(&s[i], c);
		else if (is_charset(s[i], c) == 0 && is_charset(s[i - 1], c) == 1)
			split[++j] = get_string(&s[i], c);
	}
	return (split);
}
