#include "../includes/ft_nmap.h"
#include "../includes/includes.h"
#include "../includes/define.h"

int create_socket(){
	int sock = -1;
	int one = 1;
	const int *val = &one;	
	if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1 || setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0){
		perror("socket");
		return false;
	}

	return sock;
}

int tcp_tester(t_context *context)
{
	// print_parsing_results(context);
	pcap_t **handle_pcap = NULL;
	struct sockaddr_in *addr = NULL;
 
	handle_pcap = malloc(sizeof(pcap_t *));
	if (!handle_pcap)
		return 1;

	int *sockets = ft_calloc(context->target_count * context->port_count , sizeof(int));
	int count = 0;
	for (int j = 0; context->hostnames[j]; j++){
		for (int k = 0; k < context->port_count; k++){
			sockets[count] = create_socket();
			++count;
		}
	}

	count = 0;
	for (int j = 0; context->hostnames[j]; j++)
	{
		char *final_hostname = NULL;

		final_hostname = resolve_host(context->hostnames[j]);
		if (!final_hostname)
		{
			printf("Could not resolve hostname : %s\n", context->hostnames[j]);
			continue ;
		}

		for (int k = 0; k < context->port_count; k++)
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
				if (
					!setup_record_filter(handle_pcap, ft_itoa(context->ports[k])) ||
					!tcp_test_port(
						handle_pcap,
						addr,
						final_hostname,
						context->ports[k],
						ft_strdup(context->scan_types[i]),
						sockets[count]
					))//! mutex sur scan type
				{
					free(handle_pcap);
					free(addr);
					return 3;
				}
				free(addr);
				pcap_close(*handle_pcap);
				++count;
			}
		}

		if (final_hostname)
			free(final_hostname);
	}

	free(sockets);
	free(handle_pcap);
	return 0;
}
