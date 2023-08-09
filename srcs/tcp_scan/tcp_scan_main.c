#include "../includes/ft_nmap.h"
#include "../includes/includes.h"
#include "../includes/define.h"

struct thread_info {
	pthread_t thread_id;
	int thread_num;
	char *argv_string;
	struct socket_info *sockets_info;
	struct socket_info *sockets_info_cpy;
	t_context *context;
};
pthread_mutex_t lock_context;
pthread_mutex_t lock_list;
pthread_mutex_t lock_list_cpy;

void *start_thread(void *arg){
	struct thread_info* tinfo = (struct thread_info*)arg;

	printf("ok");
	for (int j = 0; tinfo->context->hostnames[j]; j++)
	{
		for (int k = 0; k < tinfo->context->port_count; k++, tinfo->sockets_info_cpy = tinfo->sockets_info_cpy->next)
		{
			if (!init_in_thread(tinfo->sockets_info_cpy, tinfo->context->hostnames[j], tinfo->context->ports[k])){
				clean_list(tinfo->sockets_info);
				return (void*)2;
			}
			for (int i = 0; i < SCAN_COUNT - 1; i++){// -1 cause of UDP
				if (!tinfo->context->scan_types[i]){
					continue;
				}
				if (
					!setup_record_filter(tinfo->sockets_info_cpy->handle_pcap, ft_itoa(tinfo->context->ports[k])) ||
					!tcp_test_port(
						tinfo->sockets_info_cpy,
						ft_strdup(tinfo->context->scan_types[i])
					))
				{
					clean_list(tinfo->sockets_info);
					return (void*)3;
				}
			}
			pcap_close(*tinfo->sockets_info_cpy->handle_pcap);
			close(tinfo->sockets_info_cpy->fd);
			clean_in_thread(tinfo->sockets_info_cpy);
		}
	}

	return NULL;
}

int tcp_tester(t_context *context)
{
	struct socket_info *sockets_info = init_list(context);
	if (!sockets_info)
		return 1;
	struct socket_info *sockets_info_cpy = sockets_info;
	sockets_info_cpy = sockets_info;

	struct thread_info *tinfo = ft_calloc(context->thread_count, sizeof(struct thread_info));
	if (!tinfo){
		clean_list(sockets_info);
			return 4;
	}

	pthread_mutex_init(&lock_context, NULL);
	pthread_mutex_init(&lock_list, NULL);
	pthread_mutex_init(&lock_list_cpy, NULL);

	for (int i = 0; i < context->thread_count; i++){
		tinfo[i].sockets_info = sockets_info;
		tinfo[i].sockets_info_cpy = sockets_info_cpy;
		tinfo[i].context = ft_calloc(1, sizeof(t_context));
		ft_memcpy(context, tinfo[i].context, sizeof(t_context));
		pthread_create(&tinfo[i].thread_id, NULL, start_thread, tinfo + i);
	}

	for (int i = 0; i < context->thread_count; i++){
		free(tinfo[i].context);
		pthread_join(tinfo[i].thread_id, NULL);
	}
	pthread_mutex_destroy(&lock_context);
	pthread_mutex_destroy(&lock_list);
	pthread_mutex_destroy(&lock_list_cpy);
	free(tinfo);

	clean_list(sockets_info);
	return 0;
}
