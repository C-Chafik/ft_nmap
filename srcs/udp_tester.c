#include "./includes/ft_nmap.h"
#include "./includes/struct.h"


void udp_tester(t_context *context)
{ (void)context;
    int sockfd;
    int numbytes;
    struct sockaddr_in target;

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) 
    {
        perror("Cannot create socket");
        exit(EXIT_FAILURE);
    }

    ft_bzero(&target, sizeof(target));
    target.sin_family = AF_INET;
    target.sin_port = htons(43603);
    target.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (target.sin_addr.s_addr == (in_addr_t)-1)
    {
        fprintf(stderr, "Cannot assign the hostname");
        exit(EXIT_FAILURE);
    }

    if ((numbytes = sendto(sockfd, "lol", ft_strlen("lol"), 0, (struct sockaddr *)&target, sizeof(struct sockaddr))) < 0)
    {
        perror("sendto");
        exit(EXIT_FAILURE);
    }

    printf("Envoyé %d octets à %s\n",numbytes, inet_ntoa(target.sin_addr));
}