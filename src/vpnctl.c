#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <mqueue.h>
#include "debug.h"


char *progname;

void vpnctl_usage(void) {
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "%s [-s] [-k] [-i]\n", progname);
  fprintf(stderr, "%s -h\n", progname);
  fprintf(stderr, "\n");
  fprintf(stderr, "-s: sends shutdown command to server and terminates client\n");
  fprintf(stderr, "-i: sends re-IV command to server\n");
  fprintf(stderr, "-k: sends re-key command to server\n");
  fprintf(stderr, "-h: prints this help text\n");
  exit(1);
}


int vpnctl_init(int argc, char** argv) {

  int option;
  char command;
  int result;
  mqd_t mqd;
  struct mq_attr attr, *attrp;

  attrp = NULL;
  attr.mq_maxmsg = 10;
  attr.mq_msgsize = 1;
  attrp = &attr;

  progname = argv[0];

  /* Check command line options */
  while((option = getopt(argc, argv, "hskid")) > 0) {
      switch(option) {
	case 'd':
	      debug = true;
	      break;
	case 'h':
	      vpnctl_usage();
	      break;
	case 'i':
	      //IV
	      command = 0x01;
	      break;
	case 's':
	      //Stop
	      command = 0x02;
	      break;
	case 'k':
	      //Key
	      command = 0x00;
	      break;
	default:
	      my_err("Unknown option %c\n", option);
	      vpnctl_usage();
      }
  }

  argv += optind;
  argc -= optind;

  if(argc > 0) {
	my_err("Too many options!\n");
	vpnctl_usage();
  }

  mqd = mq_open("/cdbd-vpn", O_CREAT | O_RDWR, S_IRUSR | S_IWUSR, attrp);
  result = mq_send(mqd, &command, 1, 0);

  return result;
}

#ifndef UNITY_FIXTURES
int main(int argc, char** argv) {

  return vpnctl_init(argc, argv);

}
#endif
