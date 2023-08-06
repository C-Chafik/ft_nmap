#include "../includes/ft_nmap.h"
#include "../includes/includes.h"
#include "../includes/define.h"

t_udp_vars  *init_udp_packet(char *addr_dest, int port_dest)
{
    t_udp_vars *udp_vars = NULL;
	if (!(udp_vars = ft_calloc(1, sizeof(t_udp_vars))))
		return NULL;
	ft_bzero(udp_vars->datagram, 4096);

    udp_vars->sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_vars->sock == -1) {
        perror("socket error");
        free(udp_vars);
        return NULL;
    }

    memset(&(udp_vars->sin), 0, sizeof(udp_vars->sin));
    udp_vars->sin.sin_family = AF_INET;
    udp_vars->sin.sin_port = htons(port_dest);
    inet_pton(AF_INET, addr_dest, &(udp_vars->sin.sin_addr));

    struct udphdr *udp_header = (struct udphdr *) udp_vars->datagram;
    udp_header->dest = htons(port_dest);
    udp_header->len = htons(sizeof(struct udphdr));
    udp_header->check = 0;


    return udp_vars;
}

bool    send_udp_packet(t_udp_vars *udp_vars) 
{
    if (sendto(udp_vars->sock, NULL, 0, 0, (struct sockaddr*)&(udp_vars->sin), sizeof(udp_vars->sin)) == -1) {
        close(udp_vars->sock);
        perror("sendto error");
        return false;
    }

    close(udp_vars->sock);
    return true;
}
