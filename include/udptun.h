/*
 * udptun.h
 *
 */

#ifndef INCLUDE_UDPTUN_H_
#define INCLUDE_UDPTUN_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
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
#include <openssl/bio.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include "conf.h"


//Interface and socket for tunnels
typedef struct {
  char if_name[IFNAMSIZ];
  struct sockaddr_in local;
  unsigned short int port;
  bool mode;
  unsigned long int net2tun, tun2net;
} udptun_sock;


//Represents a single tunnel
typedef struct {
  bool admin_state;   //Shutdown / not shutdown
  uint8_t id;
  uint32_t spi_local;
  uint32_t spi_remote;
  unsigned long int net2tun, tun2net;
  struct sockaddr_in remote;
  char remote_ip[16];            /* dotted quad IP string */
  unsigned short int remote_port;
  char *key;    //Tunnel key, passed from client
  char * iv;    //Tunnel IV
  //Encryption enabled
  uint8_t ka;    // Keepalive interval
  //State (UP, DOWN, UNKNOWN)
} udptun_def;

udptun_def defs[256];

void udptun_init(udptun_sock* tun_sock);

#endif /* INCLUDE_UDPTUN_H_ */
