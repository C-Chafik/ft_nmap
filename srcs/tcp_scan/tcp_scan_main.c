#include "../includes/ft_nmap.h"
#include "../includes/includes.h"
#include "../includes/define.h"

void tcp_tester(t_context *context)
{
	pcap_t *handle_pcap = NULL;
	struct sockaddr_in *addr = NULL;
	pcap_if_t *devs = NULL;
	print_parsing_results(context);

	for (int i = 0; context->hostnames[i]; i++)
	{
		for (int j = 0; j < context->port_count; j++)
		{
			addr = setup_record(&handle_pcap, devs);
			setup_record_filter(&handle_pcap, ft_itoa(context->ports[j]));
			tcp_test_port(&handle_pcap, addr, context->hostnames[i], context->ports[j]);
		}
	}

	pcap_freealldevs(devs);
}

/*
	Pour filter et unfilter les ports d'un container:
	- run le container en briged avec:
		`--cap-add=NET_ADMIN`
	- utiliser les commandes suivantes dans le container:
		`iptables -P INPUT DROP`
		`iptables -P INPUT ALLOW`
*/
