#ifndef DEFINE_H
# define DEFINE_H

# include "includes.h"

# define ANSI_COLOR_RED "\x1b[31m"
# define ANSI_COLOR_GREEN "\x1b[32m"
# define ANSI_COLOR_YELLOW "\x1b[33m"
# define ANSI_COLOR_BLUE "\x1b[34m"
# define ANSI_COLOR_MAGENTA "\x1b[35m"
# define ANSI_COLOR_CYAN "\x1b[36m"
# define ANSI_COLOR_RESET "\x1b[0m"

# define U_IS_TCP 10
# define U_TCP_RTN 20
# define U_SCANNED_PORT 4
# define U_SCAN_TYPE 30
# define U_ICMP_RTN 78

#define U_IS_ICMP 40
#define ICMP_RSP_TYPE_OFF 34
#define ICMP_HEADER_LENGTH 8

# define PORT_SRC_OFF 34 
# define PORT_DST_OFF 36

#define TCP_RSP_FLAG_OFF 13

# define MAX_SCANS 6

typedef __u_char u_char;

#endif