#include "../includes/ft_nmap.h"
#include "../includes/includes.h"
#include "../includes/define.h"

int tcp_tester(t_context *context)
{
	pcap_t **handle_pcap = NULL;
	struct sockaddr_in *addr = NULL;
	handle_pcap = malloc(sizeof(pcap_t *));
	if (!handle_pcap)
		return 1;

	addr = setup_record(handle_pcap);
	if (!addr)
	{
		free(handle_pcap);
		return 2;
	}


	for (int i = 0; i < SCAN_COUNT; i++){
		if (!context->scan_types[i])
			continue;
		for (int j = 0; context->hostnames[j]; j++)
		{
			for (int k = 0; k < context->port_count; k++)
			{
				if (
					!setup_record_filter(handle_pcap, ft_itoa(context->ports[k])) ||
					!tcp_test_port(handle_pcap, addr, context->hostnames[j], context->ports[k], context->scan_types[i]))
				{
					free(handle_pcap);
					free(addr);
					return 3;
				}
			}
		}
	}

	pcap_close(*handle_pcap);
	free(handle_pcap);
	free(addr);
	return 0;
}
