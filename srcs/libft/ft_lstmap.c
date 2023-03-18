/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lstmap.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: cmarouf <marvin@42.fr>                     +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/14 18:30:29 by cmarouf           #+#    #+#             */
/*   Updated: 2021/10/14 04:59:04 by cmarouf          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */
#include "libft.h"

t_list	*ft_lstmap(t_list *lst, void*(*f)(void *), void (*del)(void *))
{
	t_list	*nlst;
	t_list	*nelem;

	if (!lst)
		return (NULL);
	nlst = NULL;
	while (lst)
	{
		nelem = ft_lstnew((*f)(lst->content));
		if (!nelem)
		{
			ft_lstclear(&nlst, (*del));
			return (NULL);
		}
		ft_lstadd_back(&nlst, nelem);
		lst = lst->next;
	}
	return (nlst);
}
