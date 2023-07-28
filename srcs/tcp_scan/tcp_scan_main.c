#include "../includes/ft_nmap.h"
#include "../includes/includes.h"
#include "../includes/define.h"

#define TEST_INIT_LIST(X) if (!(X)) {perror("test fail! Syscall status"); \
	clean_list(sockets_info); \
	return NULL;}

#define TEST_INIT_LIST_TH(X) if (!(X)) {perror("test fail! Syscall status"); return false;}
#define FREE_IF_EXIST(X) if (X) {free(X);X = NULL;} 

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

	return sock;
}

void clean_list(struct socket_info *sockets_info){
	if (!sockets_info)
		return ;
	struct socket_info *sockets_info_cpy = NULL;\
	while (1){
		sockets_info_cpy = sockets_info->next;
		FREE_IF_EXIST(sockets_info->handle_pcap)
		FREE_IF_EXIST(sockets_info->addr)
		FREE_IF_EXIST(sockets_info->final_hostname)
		free(sockets_info);
		if (!sockets_info_cpy)
			break;
		sockets_info = sockets_info_cpy;
	}
}

void clean_in_thread(struct socket_info *sockets_info){
	FREE_IF_EXIST(sockets_info->handle_pcap)
	FREE_IF_EXIST(sockets_info->addr)
	FREE_IF_EXIST(sockets_info->final_hostname)
}

struct socket_info *init_list(t_context *context){
	struct socket_info *sockets_info = NULL;
	struct socket_info *sockets_info_cpy = sockets_info;

	for (int j = 0; context->hostnames[j]; j++){
		for (int k = 0; k < context->port_count; k++){
			if (!sockets_info){
				TEST_INIT_LIST(sockets_info = ft_calloc(1, sizeof(struct socket_info)))
				sockets_info_cpy = sockets_info;
			}else {
				TEST_INIT_LIST(sockets_info_cpy->next = ft_calloc(1, sizeof(struct socket_info)))
				sockets_info_cpy = sockets_info_cpy->next;
			}
			TEST_INIT_LIST(sockets_info_cpy->socket = create_socket())
			//! ne pas forcement tous init ici, utiliser la puissance des thread de + possible
			// => creer une autre fonction pour init de la meme facon ce qui n'est pas les sockets
		}
	}

	return sockets_info;
}

bool init_in_thread(struct socket_info *sockets_info, char *hostname, int port, char *final_hostname){
	TEST_INIT_LIST_TH(sockets_info->handle_pcap = ft_calloc(1, sizeof(pcap_t *)))
	TEST_INIT_LIST_TH(sockets_info->addr = setup_record(sockets_info->handle_pcap, ft_strncmp(hostname, "localhost", 9)))
	TEST_INIT_LIST_TH(sockets_info->final_hostname = final_hostname)
	TEST_INIT_LIST_TH(sockets_info->port = port)
	return true;
}

int tcp_tester(t_context *context)
{
	struct socket_info *sockets_info = init_list(context);
	if (!sockets_info)
		return 1;
	struct socket_info *sockets_info_cpy = sockets_info;

	sockets_info_cpy = sockets_info;
	for (int j = 0; context->hostnames[j]; j++)
	{
		char *final_hostname = NULL;
		final_hostname = resolve_host(context->hostnames[j]);
		for (int k = 0; k < context->port_count; k++, sockets_info_cpy = sockets_info_cpy->next)
		{
			if (!init_in_thread(sockets_info_cpy, context->hostnames[j], context->ports[k], ft_strdup(final_hostname))){
				clean_list(sockets_info);
				return 2;
			}
			for (int i = 0; i < SCAN_COUNT - 1; i++){//! -1 cause of UDP
				if (!context->scan_types[i]){
					continue;
				}
				if (
					!setup_record_filter(sockets_info_cpy->handle_pcap, ft_itoa(context->ports[k])) ||
					!tcp_test_port(
						sockets_info_cpy->handle_pcap,
						sockets_info_cpy->addr,
						sockets_info_cpy->final_hostname,
						sockets_info_cpy->port,
						ft_strdup(context->scan_types[i]),
						sockets_info_cpy->socket
					))//! mutex sur scan type
				{
					clean_list(sockets_info);
					return 3;
				}
				pcap_close(*sockets_info_cpy->handle_pcap);
			}
			clean_in_thread(sockets_info_cpy);
		}
		free(final_hostname);
	}

	clean_list(sockets_info);
	return 0;
}
