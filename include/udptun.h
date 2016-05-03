/*
 * udptun.h
 *
 */

#ifndef INCLUDE_UDPTUN_H_
#define INCLUDE_UDPTUN_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include <stdarg.h>

/* buffer for reading from tun/tap interface, must be >= 1500 */
#define BUFSIZE 2000
#define CLIENT 0
#define SERVER 1
#define PORT 55555


//Represents a single tunnel, a unique local IP, remote IP tuple
//TODO: Separate server socket allocation from tunnel definition
typedef struct {
  int fd;
  struct sockaddr_in local, remote;
  char if_name[IFNAMSIZ];
  unsigned long int net2tun, tun2net;
  char remote_ip[16];            /* dotted quad IP string */
  unsigned short int port;
  //Tunnel key
  //Tunnel IV
  //Encryption enabled
  //Keepalive interval
  //State (UP, DOWN, UNKNOWN)
} udptun_def;



#endif /* INCLUDE_UDPTUN_H_ */
