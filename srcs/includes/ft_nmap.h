#ifndef FT_NMAP_H
# define FT_NMAP_H

# include "./define.h"
# include "./struct.h"
# include "./includes.h"

// * # CORE # *

int             port_scanner(t_context *context);
int             init_parsing(t_context *context, int ac, char **av);
char            *resolve_host(const char *hostname);
unsigned short  csum(unsigned short *ptr, int nbytes);

// * # CORE # *


// * # PARSING / UTILS # *

int     d_ptrlen(char **d_ptr);
int		is_number(const char *str);
void    print_parsing_results(t_context *context);
void    free_tab(char **d_ptr);
void	ft_sort_int_tab(int *tab, int size);
void	free_context(t_context *context);

// * # PARSING / UTILS # *

// * # TCP # *

u_char  which_scan(char *scan_type);
bool    send_tcp_packet(t_tcp_vars *tcp_vars);
bool    tcp_test_port(pcap_t **handle_pcap, struct sockaddr_in *addr, char *ip_dest, int portt, char *scan_type);
bool    setup_tcp_record_filter(pcap_t **handle_pcap, char *port);
void    init_ip_header(struct iphdr **iph, char *datagram, in_addr_t s_addr);
void    init_tcp_header(struct tcphdr **tcph, int port_dest, u_char flags);
void    debug_print_tcp_header(const u_char *tcp_header, int tcp_header_length);
void    debug_print_tcp_flags(const u_char *tcp_header, int tcp_header_length, const u_char *packet);
void    pcap_handler_fn(u_char *user, const struct pcap_pkthdr *header, const u_char *packet);
void    debug_print_full_packet(const struct pcap_pkthdr *header, const u_char *packet);

t_tcp_vars  *init_tcp_packet(struct sockaddr_in *addr, char *addr_dest, int port_dest, u_char flags);
struct      sockaddr_in *setup_record(pcap_t **handle_pcap, int is_localhost);
short       check_tcp_port_state(const u_char tcp_header, u_char flags);

// * # TCP # *


// * # UDP # *

t_udp_vars *init_udp_packet(char *addr_dest, int port_dest);
bool    send_udp_packet(t_udp_vars *udp_vars); 
bool    setup_udp_record_filter(pcap_t **handle_pcap, struct sockaddr_in *addr, char *port);
bool    udp_test_port(pcap_t **handle_pcap, struct sockaddr_in *addr, char *ip_dest, int port);
void    udp_tester(t_context *context);

// * # UDP # *

#endif