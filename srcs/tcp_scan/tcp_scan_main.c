#include "../includes/ft_nmap.h"
#include "../includes/includes.h"
#include "../includes/define.h"

int create_socket(){
	int sock = -1;
	int one = 1;
	const int *val = &one;	
	if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1){
		perror("socket");
		return 0;
	}

	if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0){
		perror("setsockopt");
		return 0;
	}

	printf(">%d<\n", sock);
	return sock;
}

struct socket_info{
	int socket;
	pcap_t **handle_pcap;
	struct sockaddr_in *addr;
	char *final_hostname;
	int port;
	char *scan_types;
	struct socket_info *next;
};

int tcp_tester(t_context *context)
{
	// print_parsing_results(context);
	pcap_t **handle_pcap = NULL;
	struct sockaddr_in *addr = NULL;
 
	handle_pcap = malloc(sizeof(pcap_t *));
	if (!handle_pcap)
		return 1;

	/*
		avec les sockets:
			- handle_pcap
			- addr
			- final_hostname
			- context->ports[k]
			- ft_strdup(context->scan_types[i]
	*/
	struct socket_info *sockets_info = NULL;
	struct socket_info *sockets_info_cpy = sockets_info;
	// struct socket_info *sockets_info = malloc(context->target_count * context->port_count * sizeof(struct socket_info));
	// int *sockets = ft_calloc(context->target_count * context->port_count , sizeof(int));
	for (int j = 0; context->hostnames[j]; j++){
		for (int k = 0; k < context->port_count; k++){
			if (!sockets_info){
				sockets_info = ft_calloc(1, sizeof(struct socket_info));
				sockets_info_cpy = sockets_info;
			}else {
				sockets_info_cpy->next = ft_calloc(1, sizeof(struct socket_info));
				sockets_info_cpy = sockets_info_cpy->next;
			}
			sockets_info_cpy->socket = create_socket();
			printf("[ %d ]\n", sockets_info_cpy->socket);
		}
	}

	sockets_info_cpy = sockets_info;
	for (int j = 0; context->hostnames[j]; j++)
	{
		char *final_hostname = NULL;

		final_hostname = resolve_host(context->hostnames[j]);
		if (!final_hostname)
		{
			printf("Could not resolve hostname : %s\n", context->hostnames[j]);
			continue ;
		}

		for (int k = 0; k < context->port_count; k++, sockets_info_cpy = sockets_info_cpy->next)
		{
			for (int i = 0; i < SCAN_COUNT - 1; i++){//! -1 cause of UDP
				if (!context->scan_types[i]){
					continue;
				}
				addr = setup_record(handle_pcap, ft_strncmp(context->hostnames[j], "localhost", 9));
				if (!addr)
				{
					free(handle_pcap);
					return 2;
				}
				printf("= %d =\n", sockets_info_cpy->socket);
				if (
					!setup_record_filter(handle_pcap, ft_itoa(context->ports[k])) ||
					!tcp_test_port(
						handle_pcap,
						addr,
						final_hostname,
						context->ports[k],
						ft_strdup(context->scan_types[i]),
						sockets_info_cpy->socket
					))//! mutex sur scan type
				{
					free(handle_pcap);
					free(addr);
					return 3;
				}
				free(addr);
				pcap_close(*handle_pcap);
			}
		}

		if (final_hostname)
			free(final_hostname);
	}

	while (1){
		sockets_info_cpy = sockets_info->next;
		if (!sockets_info_cpy)
			break;
		free(sockets_info);
		sockets_info = sockets_info_cpy;
	}

	free(sockets_info);
	free(handle_pcap);
	return 0;
}
