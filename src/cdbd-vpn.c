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
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/conf.h>
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

#ifndef UNITY_FIXTURES
int main(int argc, char *argv[])
{
  int option;

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

  defs[0].remote.sin_family = AF_INET;
  defs[0].remote.sin_addr.s_addr = inet_addr(defs[0].remote_ip);
  defs[0].remote.sin_port = htons(defs[0].remote_port);
  defs[0].spi = 0xDEADBEEF;
  defs[0].seq = 0;
  memcpy(&defs[0].key,"01234567890123456789012345678901",32);
  memcpy(&defs[0].iv, "01234567890123456",16);
  defs[0].encryption = true;

  //if(!fork()) {
      //Child
      ERR_load_crypto_strings();
      OpenSSL_add_all_algorithms();
      OPENSSL_config(NULL);
      udptun_init(&tun_sock);
  //} else {
      //Parent
  //    wait(NULL);
  //}

}
#endif //UNITY_FIXTURES
