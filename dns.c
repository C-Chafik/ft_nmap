#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

char *resolve_host(const char *hostname) {
    struct  addrinfo hints, *res;
    int     status;
    char    *ipstr;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET; // On s'intéresse uniquement à l'IPv4 pour le moment

    if ((status = getaddrinfo(hostname, NULL, &hints, &res)) != 0) 
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
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


int main()
{
    char *res;
    
    res = resolve_host("127.0.0.1");
    if (res)
        printf("%s\n", res);
    return 0;
}
