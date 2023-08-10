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

void *start_thread(void *arg){
	if (!arg)
		pthread_exit((void*)1);
	struct thread_info* tinfo = (struct thread_info*)arg;

	//! doit utiliser des mutex et pour partager l'avancement entre les threads (list chaine et increments)
	printf("ok (%ld)\n", tinfo->thread_id);
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

	for (int j = 0; tinfo->context->hostnames[j]; j++)
		free(tinfo->context->hostnames[j]);
	free(tinfo->context->hostnames);
	for (int k = 0; k < SCAN_COUNT; k++)
		if (tinfo->context->scan_types[k])
			free(tinfo->context->scan_types[k]);
	free(tinfo->context);
	return NULL;
}

int count_hosts(char **hosts){
	int count = 0;
	for (; hosts[count]; count++);
	return count;
}

void init_tinfo_thread(struct thread_info *tinfo, t_context *context, struct socket_info *sockets_info, struct socket_info *sockets_info_cpy){
	int host_count = count_hosts(context->hostnames);
	for (int i = 0; i < context->thread_count; i++){
		tinfo[i].sockets_info = sockets_info;
		tinfo[i].sockets_info_cpy = sockets_info_cpy;
		tinfo[i].context = (struct s_context *)ft_calloc(1, sizeof(struct s_context));
		tinfo[i].context->hostnames = ft_calloc(host_count + 1, sizeof(char*));
		for (int j = 0; context->hostnames[j]; j++)
			tinfo[i].context->hostnames[j] = ft_strdup(context->hostnames[j]);
		for (int k = 0; k < SCAN_COUNT; k++)
			tinfo[i].context->scan_types[k] = ft_strdup(context->scan_types[k]);
		pthread_create(&tinfo[i].thread_id, NULL, start_thread, tinfo + i);
	}
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

	for (int i = 0; i < context->thread_count; i++){
		fprintf(stderr, ">>%d<<\n", pthread_join(tinfo[i].thread_id, NULL));
	}
	free(tinfo);

	clean_list(sockets_info);
	return 0;
}
