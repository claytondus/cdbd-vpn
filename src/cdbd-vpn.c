/**************************************************************************
 * cdbd-vpn.c															  *
 * Clayton Davis, Brandon Denton										  *
 *																		  *
 *************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
#include <sys/wait.h>
#include <errno.h>
#include <stdarg.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/conf.h>
#include "openssl_thread.h"
#include "udptun.h"
#include "debug.h"
#include "tls_server.h"
#include "tls_client.h"


char *progname;

char **confOpts;
char *certloc; char *route;




/**************************************************************************
 * usage: prints usage and exits.                                         *
 **************************************************************************/
void usage(void) {
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "%s -i <ifacename> [-s|-c <serverIP>] [-p <port>] [-u|-a] [-d]\n", progname);
  fprintf(stderr, "%s -h\n", progname);
  fprintf(stderr, "\n");
  fprintf(stderr, "-i <ifacename>: Name of interface to use (mandatory)\n");
  fprintf(stderr, "-s|-c <serverIP>: run in server mode (-s), or specify server address (-c <serverIP>) (mandatory)\n");
  fprintf(stderr, "-p <port>: port to listen on (if run in server mode) or to connect to (in client mode), default 55555\n");
  fprintf(stderr, "-a <ifaceIP>: tunnel interface IP (mandatory)\n");
  fprintf(stderr, "-d: outputs debug information while running\n");
  fprintf(stderr, "-h: prints this help text\n");
  exit(1);
}

char **read_config_file(const char *confile) {
  FILE* fp;
  int i = 0;
  char* line;
  char** confStuff = malloc(sizeof(char*)*3);
  ssize_t read;
  size_t len;

  fp = fopen(confile, "r");
  if(fp == NULL) {
    printf("Cannot open config file %s",confile);
    exit(1);
  }

  while((read = getline(&line, &len, fp) != -1)) {
    confStuff[i] = line;
    line = NULL;
    i++;
    if(i >= 3) break;
  }
  fclose(fp);
  return confStuff;
}


int cdbd_vpn_start(int argc, char *argv[])
{
  THREAD_setup();
  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
  OPENSSL_config(NULL);

  int option;    /* command line options, keepalive flag */
  uint16_t remote_port = PORT;
  char remote_ip[16];
  remote_ip[0] = '\0';
  char tun_ip[16];
  tun_ip[0] = '\0';

  pthread_mutex_init(&defs_lock,NULL);


  memset(&tun_sock, 0, sizeof(udptun_sock));
  tun_sock.mode = -1;
  tun_sock.port = PORT;

  progname = argv[0];

  /* Check command line options */
  while((option = getopt(argc, argv, "i:sc:p:hdf:a:")) > 0) {
	switch(option) {
	  case 'd':
		debug = 1;
		break;
	  case 'h':
		usage();
		break;
	  case 'i':
		strncpy(tun_sock.if_name,optarg, IFNAMSIZ-1);
		break;
	  case 's':
		tun_sock.mode = SERVER;
		break;
	  case 'c':
		tun_sock.mode = CLIENT;
		strncpy(remote_ip,optarg,15);
		break;
	  case 'p':
		remote_port = (uint16_t)strtoul(optarg, NULL, 0);
		tun_sock.port = (uint16_t)strtoul(optarg, NULL, 0);
		break;
	  case 'f':
		confOpts = read_config_file(optarg);
		certloc = confOpts[0];
		defs[0].route = confOpts[1];
		defs[0].ka = !!atoi(confOpts[2]);
	        break;
	  case 'a':
		strncpy(tun_ip,optarg,15);
		break;
	  default:
		my_err("Unknown option %c\n", option);
		usage();
	}
  }

  argv += optind;
  argc -= optind;

  if(argc > 0) {
	my_err("Too many options!\n");
	usage();
  }

  if(*tun_sock.if_name == '\0') {
	my_err("Must specify interface name!\n");
	usage();
  } else if(tun_sock.mode < 0) {
	my_err("Must specify client or server mode!\n");
	usage();
  } else if(tun_ip == '\0') {
	my_err("Must specify tunnel interface IP!\n");
	usage();
  } else if((tun_sock.mode == CLIENT)&&(remote_ip == '\0')) {
	my_err("Must specify server address!\n");
	usage();
  }

  if(tun_sock.mode == SERVER) {
      tls_server_init();
  } else {
      defs = calloc(1, sizeof(udptun_def));
      strncpy(defs[0].local_ip,tun_ip,15);
      strncpy(defs[0].remote_ip,remote_ip,15);
      defs[0].remote_port = remote_port;
      defs[0].remote.sin_family = AF_INET;
      defs[0].remote.sin_addr.s_addr = inet_addr(defs[0].remote_ip);
      defs[0].remote.sin_port = htons(defs[0].remote_port);
      routes = calloc(1, sizeof(udptun_route));
      tls_client_init();
  }

  return 0;

}

#ifndef UNITY_FIXTURES
int main(int argc, char *argv[]) {

  return cdbd_vpn_start(argc, argv);

}
#endif //UNITY_FIXTURES


