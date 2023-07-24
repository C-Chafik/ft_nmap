# ft_nmap

The project is about rewriting a part of the nmap port scanner.

## Subject

[ft_nmap.pdf](https://github.com/C-Chafik/ft_nmap/files/11008768/ft_nmap.pdf)


## Authorised Functions

◦ alarm

◦ bind

◦ connect / close

◦ exit

◦ fflush, fileno, fopen, fwrite, fclose

◦ freeifaddrs, freeaddrinfo

◦ getservbyport, getaddrinfo, getifaddrs

◦ gettimeofday

◦ getuid

◦ htonl, htons, ntohs, ntohl

◦ inet_addr

◦ inet_ntoa, inet_ntop, inet_pton

◦ pcap_breakloop, pcap_close, pcap_compile, pcap_dispatch

◦ pcap_geterr, pcap_lookupnet, pcap_open_live

◦ pcap_findalldevs, pcap_freealldevs, pcap_findalldevs_ex

◦ pcap_setfilter

◦ perror, strerror, gai_strerror.

◦ poll

◦ pthread_create, pthread_exit, pthread_join

◦ pthread_mutex_init, pthread_mutex_lock, pthread_mutex_unlock

◦ sendto, recvfrom, recv

◦ setsockopt, socket

◦ sigaction, sigemptyset

◦ printf and its family.

## Usage

docker build -t ft_nmap .

docker run -v ./:/home/ -it ft_nmap bash

make

## Run docker network test

	Pour filter et unfilter les ports d'un container:
	- run le container en briged avec:
		`--cap-add=NET_ADMIN`
	- utiliser les commandes suivantes dans le container:
		`iptables -P INPUT DROP`
		`iptables -P INPUT ACCEPT`