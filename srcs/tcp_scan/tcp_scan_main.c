#include "../includes/ft_nmap.h"
#include "../includes/includes.h"
#include "../includes/define.h"

void tcp_tester(t_context *context)
{
	pcap_t **handle_pcap = NULL;
	struct sockaddr_in *addr = NULL;
	handle_pcap = malloc(sizeof(pcap_t *));
	if (!handle_pcap)
		return;

	addr = setup_record(handle_pcap);
	if (!addr)
	{
		free(handle_pcap);
		free(addr);
		return;
	}

	for (int i = 0; context->hostnames[i]; i++)
	{
		for (int j = 0; j < context->port_count; j++)
		{
			if (
				!setup_record_filter(handle_pcap, ft_itoa(context->ports[j])) ||
				!tcp_test_port(handle_pcap, addr, context->hostnames[i], context->ports[j]))
			{
				free(handle_pcap);
				free(addr);
				return;
			}
		}
	}

	free(handle_pcap);
	free(addr);
}
