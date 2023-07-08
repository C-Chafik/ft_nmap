#include "../includes/ft_nmap.h"
#include "../includes/includes.h"
#include "../includes/define.h"

void tcp_tester()
{
	pcap_t *handle_pcap = NULL;

	setup_record(&handle_pcap);
	setup_record_filter(&handle_pcap, "6675", "6677");
	tcp_test_port(&handle_pcap);
}

/*
	Pour filter et unfilter les ports d'un container:
	- run le container en briged avec:
		`--cap-add=NET_ADMIN`
	- utiliser les commandes suivantes dans le container:
		`iptables -P INPUT DROP`
		`iptables -P INPUT ALLOW`
*/
