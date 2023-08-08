#ifndef FT_NMAP_H
# define FT_NMAP_H

# include "./define.h"
# include "./struct.h"
# include "./includes.h"


int init_parsing(t_context *context, int ac, char **av);

void    print_parsing_results(t_context *context);
void    free_tab(char **d_ptr);
int     d_ptrlen(char **d_ptr);
int		is_number(const char *str);
void	ft_sort_int_tab(int *tab, int size);
void	free_context(t_context *context);

void    udp_tester(t_context *context);

int	tcp_tester();

void debug_print_full_packet(const struct pcap_pkthdr *header, const u_char *packet);
void debug_print_tcp_header(const u_char *tcp_header, int tcp_header_length);
void debug_print_tcp_flags(const u_char *tcp_header, int tcp_header_length, const u_char *packet);

void init_tcp_header(struct tcphdr **tcph, int port_dest, u_char flags);
void init_ip_header(struct iphdr **iph, char *datagram, in_addr_t s_addr);
unsigned short csum(unsigned short *ptr, int nbytes);

t_tcp_vars *init_tcp_packet(int sock, struct sockaddr_in *addr, char *addr_dest, int port_dest, u_char flags);
bool send_tcp_packet(t_tcp_vars *tcp_vars);

void pcap_handler_fn(u_char *user, const struct pcap_pkthdr *header, const u_char *packet);
struct sockaddr_in *setup_record(pcap_t **handle_pcap, int is_localhost);
bool setup_record_filter(pcap_t **handle_pcap, char *port);

short check_tcp_port_state(const u_char tcp_header, u_char flags);
bool tcp_test_port(struct socket_info *sockets_info, char *scan_type);

char *resolve_host(const char *hostname);

int create_socket();
void clean_list(struct socket_info *sockets_info);
void clean_in_thread(struct socket_info *sockets_info);
struct socket_info *init_list(t_context *context);
bool init_in_thread(struct socket_info *sockets_info, char *hostname, int port);

#endif