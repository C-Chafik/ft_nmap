#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void resolve_host(const char *hostname)
{
    struct addrinfo hints, *res;
    int errcode;
    char addrstr[100];
    void *ptr;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    errcode = getaddrinfo(hostname, NULL, &hints, &res);
    if (errcode != 0)
    {
        perror("getaddrinfo");
        return;
    }

    printf("Host: %s\n", hostname);
    while (res)
    {
        inet_ntop(res->ai_family, res->ai_addr->sa_data, addrstr, 100);

        switch (res->ai_family)
        {
        case AF_INET:
            ptr = &((struct sockaddr_in *) res->ai_addr)->sin_addr;
            break;
        case AF_INET6:
            ptr = &((struct sockaddr_in6 *) res->ai_addr)->sin6_addr;
            break;
        }
        inet_ntop(res->ai_family, ptr, addrstr, 100);
        printf("IPv%d address: %s\n", res->ai_family == PF_INET6 ? 6 : 4, addrstr);

        res = res->ai_next;
    }
}

int main()
{
    resolve_host("localhost");
    resolve_host("google.om");
    return 0;
}
