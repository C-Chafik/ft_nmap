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
			TEST_INIT_LIST(sockets_info_cpy->s_fd.fd = create_socket())
			sockets_info_cpy->s_fd.events = POLLOUT | POLLWRBAND;
		}
		TEST_INIT_LIST(sockets_info_cpy->final_hostname = resolve_host(context->hostnames[j]))
	}

	return sockets_info;
}

bool init_in_thread(struct socket_info *sockets_info, char *hostname, int port){
	TEST_INIT_LIST_TH(sockets_info->handle_pcap = ft_calloc(1, sizeof(pcap_t *)))
	TEST_INIT_LIST_TH(sockets_info->addr = setup_record(sockets_info->handle_pcap, ft_strncmp(hostname, "localhost", 9)))
	TEST_INIT_LIST_TH(sockets_info->port = port)
	return true;
}