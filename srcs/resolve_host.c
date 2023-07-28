#include "./includes/ft_nmap.h"

char *resolve_host(const char *hostname) 
{
    struct  addrinfo hints, *res;
    int     status;
    char    *ipstr;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET; // On s'intéresse uniquement à l'IPv4 pour le moment

    if ((status = getaddrinfo(hostname, NULL, &hints, &res)) != 0) 
    {
        // fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
        printf("Could not resolve hostname : %s\n", hostname);
        return NULL;
    }

    struct sockaddr_in *ipv4 = (struct sockaddr_in *)res->ai_addr;
    ipstr = malloc(NI_MAXHOST);
    if (!ipstr)
    {
        fprintf(stderr, "Could not allocate ipstr, FATAL ERROR\n");
        return NULL;
    }
    if (!inet_ntop(res->ai_family, &(ipv4->sin_addr), ipstr, NI_MAXHOST)) 
    {
        perror("inet_ntop");
        free(ipstr);
        freeaddrinfo(res);
        return NULL;
    }

    freeaddrinfo(res);
    return ipstr;
}