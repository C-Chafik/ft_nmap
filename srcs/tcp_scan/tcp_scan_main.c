#include "../includes/ft_nmap.h"
#include "../includes/includes.h"
#include "../includes/define.h"

struct socket_info {
	pcap_t **handle_pcap;
	struct sockaddr_in *addr;
	char *final_hostname;
	t_tcp_vars *tcp_header;
	u_char user[BUFSIZ];
}

int tcp_tester(t_context *context)
{
	{
		struct socket_info *sockets_info = NULL;
		sockets_info = ft_calloc(sizeof(struct socket_info), context->target_count * context->port_count);

		int count = 0;
		bool error = false;
		for (int i = 0; context->hostnames[i] && !error; i++){
			char *final_hostname = resolve_host(context->hostnames[j]);
			if (!final_hostname)
			{
				printf("%s, Could not resolve hostname : %s\n", context->hostnames[i]);
				continue ;
			}
			for (int j = 0; j < context->port_count && !error; j++){
				if (!(sockets_info[count]->handle_pcap = malloc(sizeof(pcap_t *))))
					error = true; break;
				if (!(sockets_info[count]->addr = setup_record(sockets_info[count]->handle_pcap, ft_strncmp(context->hostnames[i], "localhost", 9))))
					error = true; break;
				sockets_info[count]->final_hostname = final_hostname;
				sockets_info[count]->tcp_header = init_tcp_packet(sockets_info[count]->addr, sockets_info[count]->final_hostname, context->port[j], which_scan(ft_strdup(context->scan_types[i])));
				++count;
			}
		}

		free(sockets_info);
	}
	// print_parsing_results(context);
	pcap_t **handle_pcap = NULL;
	struct sockaddr_in *addr = NULL;
 
 	/*
		Faire un tableau de struct avec:
			- hostname
			- socket
			- handle pcap
			- addr
			- char *user
		Commencer par creer un handle_pcap + addr + init_packet pour tous les ip:port possible
		Puis checker avec poll quand envoyer et listen les packets quand ready
		On peut faire tous les scans avec la meme socket
		Faire un init_tcp_packet qui ne init pas les flags pour utiliser la meme socket pour tous les types de scan
	*/

	handle_pcap = malloc(sizeof(pcap_t *));
	if (!handle_pcap)
		return 1;

	for (int i = 0; i < SCAN_COUNT - 1; i++){//! -1 cause of UDP
		if (!context->scan_types[i]){
			continue;
		}
		for (int j = 0; context->hostnames[j]; j++)
		{
			char *final_hostname = NULL;

			final_hostname = resolve_host(context->hostnames[j]);
			if (!final_hostname)
			{
				printf("%s, Could not resolve hostname : %s\n", context->scan_types[i], context->hostnames[j]);
				continue ;
			}

			for (int k = 0; k < context->port_count; k++)
			{
				addr = setup_record(handle_pcap, ft_strncmp(context->hostnames[j], "localhost", 9));
				if (!addr)
				{
					free(handle_pcap);
					return 2;
				}
				if (
					!setup_record_filter(handle_pcap, ft_itoa(context->ports[k])) ||
					!tcp_test_port(handle_pcap, addr, final_hostname, context->ports[k], ft_strdup(context->scan_types[i])))//! mutex sur scan type
				{
					free(handle_pcap);
					free(addr);
					return 3;
				}
				free(addr);
				pcap_close(*handle_pcap);
			}

			if (final_hostname)
				free(final_hostname);
		}
	}

	free(handle_pcap);
	return 0;
}
