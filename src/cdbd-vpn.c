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
#include "udptun.h"
#include "debug.h"


char *progname;

udptun_sock tun_sock;

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
  fprintf(stderr, "-d: outputs debug information while running\n");
  fprintf(stderr, "-h: prints this help text\n");
  exit(1);
}

char **configTun(char *confile) {
  int fp;
  int done = 0; int i;
  char *line; char **confStuff;
  ssize_t read; size_t len = 0;

  fp = fopen(confile, "r");
  if(fp == NULL) {done = 1;}

  if(done != 1) {
	while((read = getline(&line, &len, fp) != -1)) {
      for(i = 0; i < 3; i++;) {
		confStuff[i] = (char *) malloc(sizeof(char)*sizeof(line) + 1);
	    strcpy(confStuff[i], line);
	  }
	  if(i >=3) break;
	}
  } return confStuff;
}


#ifndef UNITY_FIXTURES
int main(int argc, char *argv[])
{
  int option, ka;    /* command line options, keepalive flag */
  char **confOpts;
  char *certloc; char *route;
  memset(&tun_sock, 0, sizeof(udptun_sock));
  tun_sock.mode = -1;
  tun_sock.port = PORT;

  memset(&defs, 0, 256*sizeof(udptun_def));
  defs[0].remote_port = PORT;

  progname = argv[0];

  /* Check command line options */
  while((option = getopt(argc, argv, "i:s:c:p:hd")) > 0) {
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
		strncpy(defs[0].remote_ip,optarg,15);
		break;
	  case 'c':
		tun_sock.mode = CLIENT;
		strncpy(defs[0].remote_ip,optarg,15);
		break;
	  case 'p':
		defs[0].remote_port = atoi(optarg);
		tun_sock.port = atoi(optarg);
		break;
      case 'f':
	    confOpts = configTun("set.cnf");
		certloc = (char *) malloc(sizeof(confOpts[0] + 1);
		route = (char *) malloc(sizeof(confOpts[1] + 1);
		ka = atoi(confOpts[2]);
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
  } else if((tun_sock.mode == CLIENT)&&(*defs[0].remote_ip == '\0')) {
	my_err("Must specify server address!\n");
	usage();
  }

  if(!fork()) {
      //Child
      udptun_init(&tun_sock);
  } else {
      //Parent
      wait(NULL);
  }

}
#endif //UNITY_FIXTURES
