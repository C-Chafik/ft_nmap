#include "./includes/ft_nmap.h"
#include "./includes/includes.h"
#include "./includes/define.h"

unsigned short csum(unsigned short *ptr, int nbytes)
{
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum = 0;
	while (nbytes > 1)
	{
		sum += *ptr++;
		nbytes -= 2;
	}
	if (nbytes == 1)
	{
		oddbyte = 0;
		*((u_char *)&oddbyte) = *(u_char *)ptr;
		sum += oddbyte;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum = sum + (sum >> 16);
	answer = (short)~sum;

	return (answer);
}

void init_ip_header(struct iphdr **iph, char *datagram, char *source_ip, in_addr_t s_addr)
{
	(*iph)->ihl = 5;
	(*iph)->version = 4;
	(*iph)->tos = 0;
	(*iph)->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
	(*iph)->id = htonl(54321); // id of this packet
	(*iph)->frag_off = 0;
	(*iph)->ttl = 255;
	(*iph)->protocol = IPPROTO_TCP;
	(*iph)->check = 0;
	(void)source_ip;
	// (*iph)->saddr = inet_addr(source_ip);
	(*iph)->daddr = s_addr;
	(*iph)->check = csum((unsigned short *)datagram, (*iph)->tot_len);
}

void init_tcp_header(struct tcphdr **tcph, int port_src, int port_dest, u_char flags)
{
	(void)port_src;
	// (*tcph)->source = htons(port_src);
	(*tcph)->dest = htons(port_dest);
	(*tcph)->seq = 0;
	(*tcph)->ack_seq = 0;
	(*tcph)->doff = 5;
	(*tcph)->fin = !!(flags & FIN);
	(*tcph)->syn = !!(flags & SYN);
	(*tcph)->rst = !!(flags & RST);
	(*tcph)->psh = !!(flags & PSH);
	(*tcph)->ack = !!(flags & ACK);
	(*tcph)->urg = !!(flags & URG);
	// tcph->window = htons (5840);
	(*tcph)->check = 0;
	(*tcph)->urg_ptr = 0;
}