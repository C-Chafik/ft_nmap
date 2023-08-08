#include "../includes/ft_nmap.h"
#include "../includes/includes.h"
#include "../includes/define.h"

int tcp_tester(t_context *context)
{
	struct socket_info *sockets_info = init_list(context);
	if (!sockets_info)
		return 1;
	struct socket_info *sockets_info_cpy = sockets_info;

	sockets_info_cpy = sockets_info;
	for (int j = 0; context->hostnames[j]; j++)//enlever (s_fd)
	{
		for (int k = 0; k < context->port_count; k++, sockets_info_cpy = sockets_info_cpy->next)//enlever (s_fd)
		{
			if (!init_in_thread(sockets_info_cpy, context->hostnames[j], context->ports[k])){
				clean_list(sockets_info);
				return 2;
			}
			for (int i = 0; i < SCAN_COUNT - 1; i++){//! -1 cause of UDP
				if (!context->scan_types[i]){
					continue;
				}
				if (
					!setup_record_filter(sockets_info_cpy->handle_pcap, ft_itoa(context->ports[k])) ||
					// passer seulement sockets_info_cpy en parametres
					!tcp_test_port(
						sockets_info_cpy,
						ft_strdup(context->scan_types[i])
					))//! mutex sur scan type
				{
					clean_list(sockets_info);
					return 3;
				}
			}
			pcap_close(*sockets_info_cpy->handle_pcap);
			close(sockets_info_cpy->s_fd.fd);
			clean_in_thread(sockets_info_cpy);
		}
	}

	clean_list(sockets_info);
	return 0;
}
