#include "../includes/ft_nmap.h"
#include "../includes/includes.h"
#include "../includes/define.h"

struct thread_info {
	pthread_t thread_id;
	int thread_num;
	char *argv_string;
};

void *start_thread(void *arg){
	(void)arg;

	printf("ok");

	return NULL;
}

int tcp_tester(t_context *context)
{
	struct socket_info *sockets_info = init_list(context);
	if (!sockets_info)
		return 1;
	struct socket_info *sockets_info_cpy = sockets_info;
	sockets_info_cpy = sockets_info;

	// int hosts_count = count_hostnames(context->hostnames);
	struct thread_info *tinfo = ft_calloc(context->thread_count, sizeof(struct thread_info));
	if (!tinfo){
		clean_list(sockets_info);
			return 4;
	}

	for (int i = 0; i < context->thread_count; i++)
		pthread_create(&tinfo[i].thread_id, NULL, start_thread, NULL);

	for (int j = 0; context->hostnames[j]; j++)
	{
		for (int k = 0; k < context->port_count; k++, sockets_info_cpy = sockets_info_cpy->next)
		{
			if (!init_in_thread(sockets_info_cpy, context->hostnames[j], context->ports[k])){
				clean_list(sockets_info);
				return 2;
			}
			for (int i = 0; i < SCAN_COUNT - 1; i++){// -1 cause of UDP
				if (!context->scan_types[i]){
					continue;
				}
				if (
					!setup_record_filter(sockets_info_cpy->handle_pcap, ft_itoa(context->ports[k])) ||
					!tcp_test_port(
						sockets_info_cpy,
						ft_strdup(context->scan_types[i])
					))
				{
					clean_list(sockets_info);
					return 3;
				}
			}
			pcap_close(*sockets_info_cpy->handle_pcap);
			close(sockets_info_cpy->fd);
			clean_in_thread(sockets_info_cpy);
		}
	}

	for (int i = 0; i < context->thread_count; i++)
		pthread_join(tinfo[i].thread_id, NULL);
	free(tinfo);

	clean_list(sockets_info);
	return 0;
}
