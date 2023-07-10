#include "../includes/ft_nmap.h"
#include "../includes/includes.h"
#include "../includes/define.h"

t_tcp_vars init_tcp_packet(struct sockaddr_in *addr, char *addr_dest, int port_dest, u_char flags)//! change addr_dest to dynamic
{
	t_tcp_vars tcp_vars = {0};
	ft_bzero(tcp_vars.datagram, 4096);

	tcp_vars.sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	tcp_vars.iph = (struct iphdr *)tcp_vars.datagram;
	tcp_vars.tcph = (struct tcphdr *)(tcp_vars.datagram + sizeof(struct ip));

	// printf("%s\n", inet_ntoa(((struct sockaddr_in*)addr)->sin_addr));

	// ft_strlcpy(tcp_vars.source_ip, addr->sin_addr.s_addr, 11);
	tcp_vars.sin.sin_family = AF_INET;
	tcp_vars.sin.sin_port = htons(port_dest);
	tcp_vars.sin.sin_addr.s_addr = inet_addr(addr_dest);

	init_ip_header(&tcp_vars.iph, tcp_vars.datagram, tcp_vars.sin.sin_addr.s_addr);
	init_tcp_header(&tcp_vars.tcph, port_dest, flags);

	tcp_vars.psh.source_address = addr->sin_addr.s_addr;
	tcp_vars.psh.dest_address = tcp_vars.sin.sin_addr.s_addr;
	tcp_vars.psh.placeholder = 0;
	tcp_vars.psh.protocol = IPPROTO_TCP;
	tcp_vars.psh.tcp_length = htons(sizeof(struct tcphdr));

	tcp_vars.psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
	tcp_vars.pseudogram = malloc(tcp_vars.psize);

	memcpy(tcp_vars.pseudogram, (char *)&tcp_vars.psh, sizeof(struct pseudo_header));
	memcpy(tcp_vars.pseudogram + sizeof(struct pseudo_header), tcp_vars.tcph, sizeof(struct tcphdr));

	tcp_vars.tcph->check = csum((unsigned short *)tcp_vars.pseudogram, tcp_vars.psize);

	int one = 1;
	const int *val = &one;

	if (setsockopt(tcp_vars.sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
	{
		perror("Error setting IP_HDRINCL");
		free(tcp_vars.pseudogram);
		close(tcp_vars.sock);
		exit(0);
	}

	return tcp_vars;
}

void send_tcp_packet(t_tcp_vars tcp_vars)
{
	struct timeval timeout = {0, 15000};
	if (setsockopt(tcp_vars.sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0)
	{
		perror("setsockopt");
		free(tcp_vars.pseudogram);
		close(tcp_vars.sock);
		exit(0);
	}

	if (sendto(tcp_vars.sock, tcp_vars.datagram, tcp_vars.iph->tot_len, 0, (struct sockaddr *)&tcp_vars.sin, sizeof(tcp_vars.sin)) < 0)
	{
		free(tcp_vars.pseudogram);
		close(tcp_vars.sock);
		perror("sendto failed");
	}

	free(tcp_vars.pseudogram);
	close(tcp_vars.sock);
}