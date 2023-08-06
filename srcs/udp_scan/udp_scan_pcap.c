#include "../includes/ft_nmap.h"
#include "../includes/includes.h"
#include "../includes/define.h"

bool setup_udp_record_filter(pcap_t **handle_pcap, struct sockaddr_in *addr, char *port)
{
	struct bpf_program filter = {0};
	char *filter_exp = NULL;

    filter_exp = ft_strjoin("(udp port ", port);
    filter_exp = ft_strjoin(filter_exp, " and not src host ");
    filter_exp = ft_strjoin(filter_exp, inet_ntoa(addr->sin_addr));
    filter_exp = ft_strjoin(filter_exp, ") or icmp");

	if (pcap_compile(*handle_pcap, &filter, filter_exp, 0, 0) == PCAP_ERROR || pcap_setfilter(*handle_pcap, &filter) == PCAP_ERROR)
	{
		pcap_geterr(*handle_pcap);
		free(port);
		free(filter_exp);
		return false;
	}


	free(port);
	free(filter_exp);
	pcap_freecode(&filter);
	return true;
}