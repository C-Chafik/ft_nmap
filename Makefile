SRCS =	./srcs/main.c \
		./srcs/parsing.c \
		./srcs/utils.c \
		./srcs/memory_utils.c \
		./srcs/tcp_tester.c \

OBJS =	${SRCS:.c=.o}

RM =	rm -rf

CC =	gcc

CFLAGS = -Wall -Wextra -Werror

PTHREADFLAG = -pthread

PCAPFLAG = -lpcap

NAME = ft_nmap

.c.o:
	${CC} -I includes ${CFLAGS} -g3 -c $< -o ${<:.c=.o}

all: $(NAME)

$(NAME): $(OBJS)
	make -C ./srcs/libft
	$(CC) $(CFLAGS) $(PTHREADFLAG) $(PCAPFLAG) -g3 $(OBJS) ./srcs/libft/libft.a -o $(NAME)

clean:
	$(RM) $(OBJS)

fclean: clean
	$(RM) $(NAME)

re: fclean all

.PHONY: all clean fclean re
.SILENT: clean