#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <pthread.h>
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

struct udptun_route {
  in_addr_t network;
  in_addr_t mask;
  uint32_t spi;
  struct udptun_route* next;
};
typedef struct udptun_route udptun_route;

//Represents a single tunnel
struct udptun_def {
  uint32_t spi;
  uint32_t local_seq, remote_seq;
  unsigned long int net2tun, tun2net;
  struct sockaddr_in remote;
  char remote_ip[16];            /* dotted quad IP string */
  unsigned short int remote_port;
  uint8_t key[32];  //256 bit
  uint8_t iv[16];   //128 bit
  char local_ip[16];
  char* route;
  bool ka;
  struct udptun_def* next;
};
typedef struct udptun_def udptun_def;

pthread_t udptun;
extern udptun_sock tun_sock;
extern pthread_mutex_t defs_lock;
extern udptun_def *defs;
extern udptun_route *routes;

void* udptun_init(void*);
udptun_def* udptun_lookup_spi(uint32_t spi);

