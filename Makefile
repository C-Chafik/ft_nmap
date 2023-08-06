SRCS =	./srcs/main.c \
		./srcs/parsing.c \
		./srcs/utils.c \
		./srcs/memory.c \
		./srcs/port_scanner.c \
		./srcs/resolve_host.c \
		./srcs/get_next_line/get_next_line.c \
		./srcs/get_next_line/get_next_line_utils.c \
		./srcs/tcp_scan/tcp_scan_debug.c \
		./srcs/tcp_scan/tcp_scan_headers.c \
		./srcs/tcp_scan/tcp_scan_packet_sender.c \
		./srcs/tcp_scan/tcp_scan_pcap.c \
		./srcs/tcp_scan/tcp_scan_state.c \
		./srcs/udp_scan/udp_scan_state.c \
		./srcs/udp_scan/udp_scan_pcap.c \
		./srcs/udp_scan/udp_scan_packet_sender.c \

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
	$(CC) $(CFLAGS) $(PTHREADFLAG) -g3 -O0  $(OBJS) ./srcs/libft/libft.a -o $(NAME) $(PCAPFLAG)

clean:
	$(RM) $(OBJS)

fclean: clean
	$(RM) $(NAME)

re: fclean all

.PHONY: all clean fclean re
.SILENT: clean