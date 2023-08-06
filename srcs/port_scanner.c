#include "./includes/ft_nmap.h"
#include "./includes/includes.h"
#include "./includes/define.h"

int port_scanner(t_context *context)
{
	// print_parsing_results(context);
	pcap_t **handle_pcap = NULL;
	struct sockaddr_in *addr = NULL;
	handle_pcap = malloc(sizeof(pcap_t *));
	if (!handle_pcap)
		return 1;

	for (int i = 0; i < SCAN_COUNT; i++){
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
				if (ft_strncmp(context->scan_types[i], "UDP", 3) == 0)
				{
					if (
						!setup_udp_record_filter(handle_pcap, addr, ft_itoa(context->ports[k])) ||
						!udp_test_port(handle_pcap, addr, final_hostname, context->ports[k]))
					{
						free(handle_pcap);
						free(addr);
						return 3;
					}
				}
				else
				{
					if (
						!setup_tcp_record_filter(handle_pcap, ft_itoa(context->ports[k])) ||
						!tcp_test_port(handle_pcap, addr, final_hostname, context->ports[k], context->scan_types[i]))
					{
						free(handle_pcap);
						free(addr);
						return 3;
					}
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
