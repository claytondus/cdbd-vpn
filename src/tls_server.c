/* serv.cpp  -  Minimal ssleay server for Unix
   30.9.1996, Sampo Kellomaki <sampo@iki.fi> */


/* mangled to work with SSLeay-0.9.0b and OpenSSL 0.9.2b
   Simplified to be even more minimal
   12/98 - 4/99 Wade Scholine <wades@mail.cybg.com> */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <memory.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <openssl/rsa.h>       /* SSLeay stuff */
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "udptun.h"
#include "debug.h"

/* define HOME to be dir for key and cert files... */
#define HOME "./certs/"
/* Make these what you want for cert & key files */
#define CERTF  HOME "server.crt"
#define KEYF  HOME  "server.key"
#define CACERT HOME "ca.crt"


#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

void tls_server_init(void)
{
  int err;
  int listen_sd;
  int sd;
  struct sockaddr_in sa_serv;
  struct sockaddr_in sa_cli;
  size_t client_len;
  SSL_CTX* ctx;
  SSL*     ssl;
  X509*    client_cert;
  char*    str;
  uint8_t     buf [4096];
  const SSL_METHOD *meth;
  udptun_def *this_def, *prev_def, *next_def;
  uint32_t spi, spi_n;
  uint8_t* bufp;
  uint8_t msg_len, msg_type;
  udptun_route *this_route, *prev_route, *next_route;
  struct in_addr network, mask;

  /* SSL preliminaries. We keep the certificate and key with the context. */

  SSL_load_error_strings();
  OpenSSL_add_ssl_algorithms();

  pthread_create(&udptun, NULL, udptun_init, NULL);

  meth = TLSv1_2_server_method();
  ctx = SSL_CTX_new (meth);
  if (!ctx) {
    ERR_print_errors_fp(stderr);
    exit(2);
  }

  SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL); /* whether verify the certificate */
  SSL_CTX_load_verify_locations(ctx,CACERT,NULL);

  if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    exit(3);
  }
  if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    exit(4);
  }

  if (!SSL_CTX_check_private_key(ctx)) {
    fprintf(stderr,"Private key does not match the certificate public key\n");
    exit(5);
  }

  /* ----------------------------------------------- */
  /* Prepare TCP socket for receiving connections */

  listen_sd = socket (AF_INET, SOCK_STREAM, 0);   CHK_ERR(listen_sd, "socket");

  memset (&sa_serv, '\0', sizeof(sa_serv));
  sa_serv.sin_family      = AF_INET;
  sa_serv.sin_addr.s_addr = INADDR_ANY;
  sa_serv.sin_port        = htons(tun_sock.port);          /* Server Port number */

  err = bind(listen_sd, (struct sockaddr*) &sa_serv,
	     sizeof (sa_serv));                   CHK_ERR(err, "bind");

  /* Receive a TCP connection. */

  err = listen (listen_sd, 5);                    CHK_ERR(err, "listen");

  printf("Listening on %s, port %d\n", inet_ntoa(sa_serv.sin_addr), ntohs(sa_serv.sin_port));

  client_len = sizeof(sa_cli);

  while (1) {
    sd = accept(listen_sd, (struct sockaddr*)&sa_cli, (socklen_t*)&client_len);
    CHK_ERR(sd, "accept");

    printf ("Connection from %s, port %d\n", inet_ntoa(sa_cli.sin_addr), ntohs(sa_cli.sin_port));

    /* ----------------------------------------------- */
    /* TCP connection is ready. Do server side SSL. */

    ssl = SSL_new (ctx);                           CHK_NULL(ssl);
    SSL_set_fd (ssl, sd);
    err = SSL_accept (ssl);                        CHK_SSL(err);

    /* Get the cipher - opt */

    printf ("SSL connection using %s\n", SSL_get_cipher (ssl));

    /* Get client's certificate (note: beware of dynamic allocation) - opt */

    client_cert = SSL_get_peer_certificate (ssl);
    if (client_cert != NULL) {
      printf ("Client certificate:\n");

      str = X509_NAME_oneline (X509_get_subject_name (client_cert), 0, 0);
      CHK_NULL(str);
      printf ("\t subject: %s\n", str);
      OPENSSL_free (str);

      str = X509_NAME_oneline (X509_get_issuer_name  (client_cert), 0, 0);
      CHK_NULL(str);
      printf ("\t issuer: %s\n", str);
      OPENSSL_free (str);

      /* We could do all sorts of certificate verification stuff here before
	 deallocating the certificate. */

      X509_free (client_cert);
    } else {
      printf ("Client does not have certificate.\n");
      goto cleanup;
    }

    /* DATA EXCHANGE - Receive message and send reply. */

    //Handle messages from client
    err = SSL_read(ssl, buf, sizeof(buf));		          CHK_SSL(err);
    BIO_dump_fp(stdout, (const char*)buf, 512);

    bufp = buf;

    pthread_mutex_lock(&defs_lock);
    //Process the commands; loop until the magic number isn't there
    while((bufp[0] == 0xCD) && (bufp[1] == 0xBD)) {

      msg_type = bufp[2];
      msg_len = bufp[3];
      memcpy(&spi_n, bufp+4, 4);
      spi = ntohl(spi_n);

      //If this is a start command
      if(msg_type == 0x04) {

	  do_debug("Setting up new tunnel with SPI %x\n",spi);
	  //Allocate tunnel
	  this_def = calloc(1, sizeof(udptun_def));
	  if(defs != NULL) {
	      this_def->next = defs;
	  } else {
	      this_def->next = NULL;
	  }
	  memcpy(&this_def->remote, &sa_cli, sizeof(struct sockaddr_in));
	  memcpy(&this_def->remote.sin_port, bufp+8, 2);
	  this_def->spi = spi;
	  defs = this_def;
	  do_debug("SPI %x will send traffic to UDP port %s:%d\n", spi, inet_ntoa(this_def->remote.sin_addr), ntohs(this_def->remote.sin_port));

      } else {
	//Find a tunnel associated with the SPI
	for(this_def = defs; this_def != NULL; this_def = this_def->next) {
	    if (this_def->spi == spi) {
		break;
	    }
	}
      }

      //If this is a key command
      if(msg_type == 0x00) {
	  do_debug("Received new key on SPI %x\n",spi);
	  memcpy(&this_def->key, bufp+4, 32);
      }

      //If this is an IV command
      if(msg_type == 0x01) {
	  do_debug("Received new IV on SPI %x\n",spi);
	  memcpy(&this_def->iv, bufp+4, 16);
      }

      //If this is a route command
      if(msg_type == 0x03) {
	  do_debug("Received new route for SPI %xl\n",spi);
	  this_route = calloc(1, sizeof(udptun_route));
	  if(routes != NULL) {
	      this_route->next = routes;
	  } else {
	      this_route->next = NULL;
	  }
	  this_route->network = *(bufp+8);
	  this_route->mask = *(bufp+12);
	  this_route->spi = spi;

	  network.s_addr = this_route->network;
	  mask.s_addr = this_route->mask;
	  do_debug("Installed route %s %s to SPI %s", inet_ntoa(network), inet_ntoa(mask));
      }

      //If this is a stop command
      if(msg_type == 0x02) {
	  do_debug("Received stop request for SPI %x\n",spi);
	  //Delete routes
	  prev_route = NULL;
	  this_route = routes;
	  for(this_route = routes; this_route != NULL; ) {
	      if (this_route->spi == spi) {
		  if(prev_route == NULL) {  //delete at beginning of list
		      routes = this_route->next;
		  } else {   //join next to previous
		      prev_route->next = this_route->next;
		  }
		  next_route = this_route->next;
		  free(this_route);
		  this_route = next_route;
	      } else {
		  prev_route = this_route;
		  this_route = this_route->next;
	      }
	  }
	  //Delete tunnel definition
	  for(this_def = defs; this_def != NULL; ) {
	      if (this_def->spi == spi) {
		  if(prev_def == NULL) {  //delete at beginning of list
		      defs = this_def->next;
		  } else {   //join next to previous
		      prev_def->next = this_def->next;
		  }
		  next_def = this_def->next;
		  free(this_def);
		  this_def = next_def;
	      } else {
		  prev_def = this_def;
		  this_def = this_def->next;
	      }
	  }
      }


      bufp += (msg_len*4);  //32 bit words in msg_len
    }

    /* Clean up. */
  cleanup:
    do_debug("Command processing done\n");
    pthread_mutex_unlock(&defs_lock);
    close (sd);
    SSL_free (ssl);
    SSL_CTX_free (ctx);
  }

}
/* EOF - serv.cpp */
