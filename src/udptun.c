/**************************************************************************
 * udptun.c															  *
 * Clayton Davis, Brandon Denton										  *
 *																		  *
 * From simpletun.c                                                       *
 *                                                                        *
 * A simplistic, simple-minded, naive tunnelling program using tun/tap    *
 * interfaces and TCP. DO NOT USE THIS PROGRAM FOR SERIOUS PURPOSES.      *
 *                                                                        *
 * You have been warned.                                                  *
 *                                                                        *
 * (C) 2010 Davide Brini.                                                 *
 *                                                                        *
 * DISCLAIMER AND WARNING: this is all work in progress. The code is      *
 * ugly, the algorithms are naive, error checking and input validation    *
 * are very basic, and of course there can be bugs. If that's not enough, *
 * the program has not been thoroughly tested, so it might even fail at   *
 * the few simple things it should be supposed to do right.               *
 * Needless to say, I take no responsibility whatsoever for what the      *
 * program might do. The program has been written mostly for learning     *
 * purposes, and can be used in the hope that is useful, but everything   *
 * is to be taken "as is" and without any kind of warranty, implicit or   *
 * explicit. See the file LICENSE for further details.                    *
 *************************************************************************/ 

#include "debug.h"
#include "udptun.h"


int debug;

/**************************************************************************
 * tun_alloc: allocates or reconnects to a tun/tap device. The caller     *
 *            must reserve enough space in *dev.                          *
 **************************************************************************/
int tun_alloc(char *dev, int flags) {

  struct ifreq ifr;
  int fd, err;
  char *clonedev = "/dev/net/tun";

  if( (fd = open(clonedev , O_RDWR)) < 0 ) {
    perror("Opening /dev/net/tun");
    return fd;
  }

  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = flags;

  if (*dev) {
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  }

  if( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) {
    perror("ioctl(TUNSETIFF)");
    close(fd);
    return err;
  }

  strcpy(dev, ifr.ifr_name);

  return fd;
}

/**************************************************************************
 * cread: read routine that checks for errors and exits if an error is    *
 *        returned.                                                       *
 **************************************************************************/
int cread(int fd, char *buf, int n){
  
  int nread;

  if((nread=read(fd, buf, n)) < 0){
    perror("Reading data");
    exit(1);
  }
  return nread;
}

/**************************************************************************
 * cwrite: write routine that checks for errors and exits if an error is  *
 *         returned.                                                      *
 **************************************************************************/
int cwrite(int fd, char *buf, int n){
  
  int nwrite;

  if((nwrite=write(fd, buf, n)) < 0){
    perror("Writing data");
    exit(1);
  }
  return nwrite;
}

/**************************************************************************
 * read_n: ensures we read exactly n bytes, and puts them into "buf".     *
 *         (unless EOF, of course)                                        *
 **************************************************************************/
int read_n(int fd, char *buf, int n) {

  int nread, left = n;

  while(left > 0) {
    if ((nread = cread(fd, buf, left)) == 0){
      return 0 ;      
    }else {
      left -= nread;
      buf += nread;
    }
  }
  return n;  
}





void udptun_init(udptun_sock *tun_sock) {
  
  int tun_fd, option;
  int flags = IFF_TUN;
  int maxfd;
  uint16_t nread, nwrite;
  char buffer[BUFSIZE];
  int sock_fd, net_fd, optval = 1;
  uint32_t spi, spi_n;
  struct sockaddr_in recvd_ip;
  socklen_t recvd_ip_len;


  /* initialize tun/tap interface */
  if ( (tun_fd = tun_alloc(tun_sock->if_name, flags | IFF_NO_PI)) < 0 ) {
    my_err("Error connecting to tun/tap interface %s!\n", tun_sock->if_name);
    exit(1);
  }

  do_debug("Successfully connected to interface %s\n", tun_sock->if_name);

  if ( (sock_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    perror("socket()");
    exit(1);
  }

  if(tun_sock->mode == SERVER) {
    /* Server, need to bind to receive packets */

    /* avoid EADDRINUSE error on bind() */
    if(setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) < 0) {
      perror("setsockopt()");
      exit(1);
    }
    
    memset(&tun_sock->local, 0, sizeof(tun_sock->local));
    tun_sock->local.sin_family = AF_INET;
    tun_sock->local.sin_addr.s_addr = htonl(INADDR_ANY);
    tun_sock->local.sin_port = htons(tun_sock->port);
    if (bind(sock_fd, (struct sockaddr*) &tun_sock->local, sizeof(tun_sock->local)) < 0) {
      perror("bind()");
      exit(1);
    }
    
  }
  
  net_fd = sock_fd;

  /* use select() to handle two descriptors at once */
  maxfd = (tun_fd > net_fd)?tun_fd:net_fd;

  while(1) {
    int ret;
    fd_set rd_set;

    FD_ZERO(&rd_set);
    FD_SET(tun_fd, &rd_set);
    FD_SET(net_fd, &rd_set);

    ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);

    if (ret < 0 && errno == EINTR){
      continue;
    }

    if (ret < 0) {
      perror("select()");
      exit(1);
    }

    if(FD_ISSET(tun_fd, &rd_set)) {
      /* data from tun/tap: read it, determine which tunnel it belongs to, and write it to the network */
      
      //tun: 1 read, 1 packet
      nread = cread(tun_fd, buffer, BUFSIZE);

      tun_sock->tun2net++;
      do_debug("TUN2NET %lu: Read %d bytes from the tun interface\n", tun_sock->tun2net, nread);

      //Figure out which tunnel this belongs to
      spi = 0xDEADBEEF; //TODO: Replace with actual SPI from udptun_def

      //Set SPI, seq number

      //Encrypt if necessary
      //Calculate HMAC if necessary

      /* write packet */
      if ((nwrite = sendto(net_fd, buffer, BUFSIZE, 0, defs[0]->remote, sizeof(struct sockaddr_in))) == -1) {
          perror("sendto");
          exit(1);
      }
      
      do_debug("TUN2NET %lu: Written %d bytes to the network\n", tun_sock->tun2net, nwrite);
    }

    if(FD_ISSET(net_fd, &rd_set)) {
      /* data from the network: read it, and write it to the tun/tap interface. 
       */

      tun_sock->net2tun++;

      /* read packet */
      if ((nread = recvfrom(net_fd, buffer, BUFSIZE, 0, (struct sockaddr *)&recvd_ip, &recvd_ip_len)) == -1) {
          perror("recvfrom");
          exit(1);
      }
      do_debug("NET2TUN %lu: Read %d bytes from the network\n", tun_sock->net2tun, nread);

      //Get SPI, verify seq number

      //Verify HMAC if necessary
      //Decrypt if necessary


      /* now buffer[] contains a full packet or frame, write it into the tun/tap interface */ 
      nwrite = cwrite(tun_fd, buffer, nread);
      do_debug("NET2TUN %lu: Written %d bytes to the tap interface\n", tun_sock->net2tun, nwrite);
    }
  }

}