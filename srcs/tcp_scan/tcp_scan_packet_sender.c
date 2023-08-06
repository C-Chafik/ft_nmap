#include "../includes/ft_nmap.h"
#include "../includes/includes.h"
#include "../includes/define.h"

t_tcp_vars *init_tcp_packet(int sock, struct sockaddr_in *addr, char *addr_dest, int port_dest, u_char flags)
{
	t_tcp_vars *tcp_vars = NULL;
	if (!(tcp_vars = ft_calloc(1, sizeof(t_tcp_vars))))
		return NULL;
	ft_bzero(tcp_vars->datagram, 4096);
	// ft_bzero(tcp_vars->iph, sizeof(struct iphdr));

	tcp_vars->sock = sock;
	tcp_vars->iph = (struct iphdr *)tcp_vars->datagram;
	tcp_vars->tcph = (struct tcphdr *)(tcp_vars->datagram + sizeof(struct ip));

	// ft_strlcpy(tcp_vars->source_ip, addr->sin_addr.s_addr, 11);
	tcp_vars->sin.sin_family = AF_INET;
	tcp_vars->sin.sin_port = htons(port_dest);
	tcp_vars->sin.sin_addr.s_addr = inet_addr(addr_dest);

	init_ip_header(&tcp_vars->iph, tcp_vars->datagram, tcp_vars->sin.sin_addr.s_addr);
	init_tcp_header(&tcp_vars->tcph, port_dest, flags);

	tcp_vars->psh.source_address = addr->sin_addr.s_addr;
	tcp_vars->psh.dest_address = tcp_vars->sin.sin_addr.s_addr;
	tcp_vars->psh.placeholder = 0;
	tcp_vars->psh.protocol = IPPROTO_TCP;
	tcp_vars->psh.tcp_length = htons(sizeof(struct tcphdr));

	tcp_vars->psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
	tcp_vars->pseudogram = malloc(tcp_vars->psize);
	if (!tcp_vars->pseudogram)
		return NULL;

	memcpy(tcp_vars->pseudogram, (char *)&tcp_vars->psh, sizeof(struct pseudo_header));
	memcpy(tcp_vars->pseudogram + sizeof(struct pseudo_header), tcp_vars->tcph, sizeof(struct tcphdr));

	tcp_vars->tcph->check = csum((unsigned short *)tcp_vars->pseudogram, tcp_vars->psize);

	return tcp_vars;
}

bool send_tcp_packet(t_tcp_vars *tcp_vars)
{
	// struct timeval timeout = {0, 1500};
	// if (setsockopt(tcp_vars->sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0)
	// {
	// 	perror("setsockopt");
	// 	free(tcp_vars->pseudogram);
	// 	close(tcp_vars->sock);
	// 	return false;
	// }

	if (sendto(tcp_vars->sock, tcp_vars->datagram, tcp_vars->iph->tot_len, 0, (struct sockaddr *)&tcp_vars->sin, sizeof(tcp_vars->sin)) < 0)
	{
		free(tcp_vars->pseudogram);
		close(tcp_vars->sock);
		perror("sendto failed");
		return false;
	}

	free(tcp_vars->pseudogram);
	// close(tcp_vars->sock);
	return true;
}