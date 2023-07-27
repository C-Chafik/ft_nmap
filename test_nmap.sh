 #! /bin/bash

RED='\x1b[31m'
GREEN='\x1b[32m'
YELLOW='\x1b[33m'
BLUE='\x1b[34m'
MAGENTA='\x1b[35m'
CYAN='\x1b[36m'
RESET='\x1b[0m'

 echo -e "${BLUE}SYN: " && nmap -sS 172.17.0.3 -p1-1024 && echo -e "${RESET}" && \
 echo -e "${YELLOW}ACK: " && nmap -sA 172.17.0.3 -p1-1024 && echo -e "${RESET}" && \
 echo -e "${GREEN}NULL: " && nmap -sN 172.17.0.3 -p1-1024 && echo -e "${RESET}" && \
 echo -e "${MAGENTA}FIN: " && nmap -sF 172.17.0.3 -p1-1024 && echo -e "${RESET}" && \
 echo -e "${CYAN}XMAS: " && nmap -sX 172.17.0.3 -p1-1024 && echo -e "${RESET}" #&& \
#  echo -e "${RED}UDP: " && nmap -sU 172.17.0.3 -p1-1024 && echo -e "${RESET}"