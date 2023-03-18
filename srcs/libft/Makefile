# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: cmarouf <marvin@42.fr>                     +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2021/09/16 15:16:01 by cmarouf           #+#    #+#              #
#    Updated: 2021/10/16 16:16:38 by cmarouf          ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

SRCS 		= ./ft_calloc.c 	\
			  ./ft_isdigit.c	\
			  ./ft_memcpy.c		\
			  ./ft_strdup.c		\
			  ./ft_strncmp.c	\
			  ./ft_toupper.c	\
			  ./ft_isalnum.c	\
			  ./ft_isprint.c	\
			  ./ft_memmove.c	\
			  ./ft_strlcat.c	\
			  ./ft_strnstr.c	\
			  ./ft_atoi.c		\
			  ./ft_isalpha.c	\
			  ./ft_memchr.c		\
			  ./ft_memset.c		\
			  ./ft_strlcpy.c	\
			  ./ft_strrchr.c	\
			  ./ft_bzero.c		\
			  ./ft_isascii.c	\
			  ./ft_memcmp.c		\
			  ./ft_strchr.c		\
			  ./ft_strlen.c		\
			  ./ft_tolower.c	\
			  ./ft_substr.c		\
			  ./ft_strjoin.c	\
			  ./ft_strtrim.c	\
			  ./ft_split.c		\
			  ./ft_itoa.c		\
			  ./ft_strmapi.c	\
			  ./ft_striteri.c	\
			  ./ft_putchar_fd.c	\
			  ./ft_putstr_fd.c	\
			  ./ft_putendl_fd.c	\
			  ./ft_putnbr_fd.c	\

BONUS		= ./ft_lstnew.c		\
			  ./ft_lstadd_front.c\
			  ./ft_lstsize.c	\
			  ./ft_lstlast.c	\
			  ./ft_lstadd_back.c\
			  ./ft_lstdelone.c	\
			  ./ft_lstclear.c	\
			  ./ft_lstiter.c	\
			  ./ft_lstmap.c		\

OBJS 		= ${SRCS:.c=.o}

OBJS_bonus	= ${BONUS:.c=.o}

RM 			= rm -f

CFLAGS 		= -Wall -Wextra -Werror

NAME		= libft.a

CC 			= gcc

.c.o:
					${CC} -I includes ${CFLAGS} -c $< -o ${<:.c=.o}

all:		$(NAME)

$(NAME): 	${OBJS}
					ar -rcs $(NAME) ${OBJS}

clean:
					${RM} ${OBJS} ${OBJS_bonus}

fclean:		clean
					${RM} $(NAME)

re:			fclean all

bonus: 		${OBJS} ${OBJS_bonus}
					ar -rcs $(NAME) ${OBJS} ${OBJS_bonus}
					
.PHONY: all clean fclean re bonus 
