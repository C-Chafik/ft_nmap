/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lstlast.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cmarouf <marvin@42.fr>                     +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/14 15:22:15 by cmarouf           #+#    #+#             */
/*   Updated: 2021/09/14 19:23:22 by cmarouf          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */
#include "libft.h"

t_list	*ft_lstlast(t_list *lst)
{
	t_list	*last;

	if (!lst)
		return (lst);
	while (lst && lst->next)
		lst = lst->next;
	last = lst;
	return (last);
}
/*int	main(void)
{
	t_list *a;
	t_list *b;
	t_list *c;

	a = ft_lstnew("1");
	b = ft_lstnew("2");
	c = ft_lstnew("3");
	a->next = b;
	b->next = c;
	printf("%s\n", (char *)c->content);
}*/
