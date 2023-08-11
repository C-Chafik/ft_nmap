#include "../includes/ft_nmap.h"
#include "../includes/includes.h"
#include "../includes/define.h"

void *work_for_peer(struct thread_info *tinfo, int port){
	if (!init_in_thread(tinfo->sockets_info_cpy, tinfo->context->hostnames[*tinfo->host_i - 1], port)){
		clean_list(tinfo->sockets_info);
		return (void*)2;
	}
	for (int i = 0; i < SCAN_COUNT - 1; i++){// -1 cause of UDP
		if (!tinfo->context->scan_types[i]){
			continue;
		}
		if (
			!setup_record_filter(tinfo->sockets_info_cpy->handle_pcap, ft_itoa(port)) ||
			!tcp_test_port(
				tinfo->sockets_info_cpy,
				ft_strdup(tinfo->context->scan_types[i])
			)
		){
			clean_list(tinfo->sockets_info);
			return (void*)3;
		}
	}
	pcap_close(*tinfo->sockets_info_cpy->handle_pcap);
	close(tinfo->sockets_info_cpy->fd);
	clean_in_thread(tinfo->sockets_info_cpy);

	return NULL;
}

void *start_thread(void *arg){
	if (!arg)
		pthread_exit((void*)1);
	struct thread_info* tinfo = (struct thread_info*)arg;

	printf("ok (%ld)\n", tinfo->thread_id);

	pthread_mutex_lock(&tinfo->lock_host_i);
	while (tinfo->context->hostnames[*tinfo->host_i]){
		printf("%s (%ld)\n", tinfo->context->hostnames[*tinfo->host_i], tinfo->thread_id);
		*tinfo->host_i += 1;//to update in live
		pthread_mutex_unlock(&tinfo->lock_host_i);
		pthread_mutex_lock(&tinfo->lock_port_i);
		while (*tinfo->port_i < tinfo->context->port_count)
		{
			int arg_port = tinfo->context->ports[(*tinfo->port_i)++];
			pthread_mutex_unlock(&tinfo->lock_port_i);
			void *rtn = work_for_peer(tinfo, arg_port);
			if (rtn)
				return rtn;
			pthread_mutex_lock(&tinfo->lock_port_i);
			tinfo->sockets_info_cpy = tinfo->sockets_info_cpy->next;
		}
		pthread_mutex_unlock(&tinfo->lock_port_i);
		pthread_mutex_lock(&tinfo->lock_host_i);
	}
	pthread_mutex_unlock(&tinfo->lock_host_i);

	free_tinfo(tinfo);
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

	init_tinfo_thread(tinfo, context, sockets_info, sockets_info_cpy);

	for (int i = 0; i < context->thread_count; i++)
		pthread_join(tinfo[i].thread_id, NULL);
	free(tinfo);
	pthread_mutex_destroy(&tinfo->lock_host_i);

	clean_list(sockets_info);
	return 0;
}
