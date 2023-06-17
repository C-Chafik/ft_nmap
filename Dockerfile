FROM debian:buster

RUN 	apt-get -y update; \
	apt-get -y install nmap;  \
 	apt-get -y install make; \
    apt-get -y install gcc; \
	apt-get -y install libpcap-dev


# USAGE
#  docker build ./ -t ft_nmap
#  docker run -it -v "$(pwd):/home/ft_nmap" ft_nmap
#  cd home/ft_nmap
#  make


# Will add more package (oh-my-zsh) later if its necessary