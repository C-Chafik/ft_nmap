 #! /bin/bash

RED='\x1b[31m'
GREEN='\x1b[32m'
YELLOW='\x1b[33m'
BLUE='\x1b[34m'
MAGENTA='\x1b[35m'
CYAN='\x1b[36m'
RESET='\x1b[0m'

 echo -e "${BLUE}REAL SYN: " && nmap -sS $1 -p $2 && echo -e "${RESET}" && \
 echo -e "${GREEN}FT   SYN: " && ./ft_nmap --ip $1 --ports $2 --scan SYN && echo -e "${RESET}" && \
 echo -e "${BLUE}NULL: " && nmap -sN $1 -p $2 && echo -e "${RESET}" && \
 echo -e "${GREEN}FT   NULL: " && ./ft_nmap --ip $1 --ports $2 --scan NULL && echo -e "${RESET}" && \
 echo -e "${BLUE}ACK: " && nmap -sA $1 -p $2 && echo -e "${RESET}" && \
 echo -e "${GREEN}FT   ACK: " && ./ft_nmap --ip $1 --ports $2 --scan ACK && echo -e "${RESET}" && \
 echo -e "${BLUE}FIN: " && nmap -sF $1 -p $2 && echo -e "${RESET}" && \
 echo -e "${GREEN}FT   FIN: " && ./ft_nmap --ip $1 --ports $2 --scan FIN && echo -e "${RESET}" && \
 echo -e "${BLUE}XMAS: " && nmap -sX $1 -p $2 && echo -e "${RESET}" #&& \
 echo -e "${GREEN}FT   XMAS: " && ./ft_nmap --ip $1 --ports $2 --scan XMAS && echo -e "${RESET}" && \
#  echo -e "${RED}UDP: " && nmap -sU $1 -p $2 && echo -e "${RESET}"
