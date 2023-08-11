#include "../includes/ft_nmap.h"
#include "../includes/includes.h"
#include "../includes/define.h"

void free_tinfo(struct thread_info *tinfo){
	for (int j = 0; tinfo->context->hostnames[j]; j++)
		free(tinfo->context->hostnames[j]);
	free(tinfo->context->hostnames);
	for (int k = 0; k < SCAN_COUNT; k++)
		if (tinfo->context->scan_types[k])
			free(tinfo->context->scan_types[k]);
	free(tinfo->context);
}

int count_hosts(char **hosts){
	int count = 0;
	for (; hosts[count]; count++);
	return count;
}

void init_tinfo_thread(struct thread_info *tinfo, t_context *context, struct socket_info *sockets_info, struct socket_info *sockets_info_cpy){
	int host_count = count_hosts(context->hostnames);
	int *host_i = ft_calloc(1, sizeof(int));
	*host_i = 0;
	int *port_i = ft_calloc(1, sizeof(int));
	*port_i = 0;
	pthread_mutex_t lock_host_i;

	pthread_mutex_init(&lock_host_i, NULL);
	for (int i = 0; i < context->thread_count; i++){

		//TMP
		tinfo[i].sockets_info = sockets_info;
		tinfo[i].sockets_info_cpy = sockets_info_cpy;
		//TMP

		tinfo[i].context = (struct s_context *)ft_calloc(1, sizeof(struct s_context));
		tinfo[i].context->hostnames = ft_calloc(host_count + 1, sizeof(char*));
		tinfo[i].context->ports = ft_calloc(1, sizeof(context->ports));

		for (int j = 0; context->hostnames[j]; j++)
			tinfo[i].context->hostnames[j] = ft_strdup(context->hostnames[j]);

		for (int j = 0; context->ports[j]; j++)
			tinfo[i].context->ports[j] = context->ports[j];

		for (int k = 0; k < SCAN_COUNT; k++)
			tinfo[i].context->scan_types[k] = ft_strdup(context->scan_types[k]);

		tinfo[i].host_i = host_i;
		tinfo[i].port_i = port_i;
		tinfo[i].context->port_count = context->port_count;
		tinfo[i].lock_host_i = lock_host_i;

		pthread_create(&tinfo[i].thread_id, NULL, start_thread, tinfo + i);
	}
}
