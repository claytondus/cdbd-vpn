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
#include <errno.h>
#include <stdarg.h>
#include "udptun.h"


char *progname;

udptun_def tundef;

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
  fprintf(stderr, "-u|-a: use TUN (-u, default) or TAP (-a)\n");
  fprintf(stderr, "-d: outputs debug information while running\n");
  fprintf(stderr, "-h: prints this help text\n");
  exit(1);
}


int main(int argc, char *argv[])
{
  int tap_fd, option;
  int flags = IFF_TUN;
  char if_name[IFNAMSIZ] = "";
  int maxfd;
  uint16_t nread, nwrite, plength;
  char buffer[BUFSIZE];
  struct sockaddr_in local, remote;
  char remote_ip[16] = "";            /* dotted quad IP string */
  unsigned short int port = PORT;
  int sock_fd, net_fd, optval = 1;
  socklen_t remotelen;
  int cliserv = -1;    /* must be specified on cmd line */
  unsigned long int tap2net = 0, net2tap = 0;

  progname = argv[0];

  /* Check command line options */
  while((option = getopt(argc, argv, "i:sc:p:uahd")) > 0) {
	switch(option) {
	  case 'd':
		debug = 1;
		break;
	  case 'h':
		usage();
		break;
	  case 'i':
		strncpy(if_name,optarg, IFNAMSIZ-1);
		break;
	  case 's':
		cliserv = SERVER;
		break;
	  case 'c':
		cliserv = CLIENT;
		strncpy(remote_ip,optarg,15);
		break;
	  case 'p':
		port = atoi(optarg);
		break;
	  case 'u':
		flags = IFF_TUN;
		break;
	  case 'a':
		flags = IFF_TAP;
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

  if(*if_name == '\0') {
	my_err("Must specify interface name!\n");
	usage();
  } else if(cliserv < 0) {
	my_err("Must specify client or server mode!\n");
	usage();
  } else if((cliserv == CLIENT)&&(*remote_ip == '\0')) {
	my_err("Must specify server address!\n");
	usage();
  }

  udptun_init(&tundef);
}
