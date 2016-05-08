/*
 * tls_client.c
 *
 */


/* cli.cpp  -  Minimal ssleay client for Unix
   30.9.1996, Sampo Kellomaki <sampo@iki.fi> */

/* mangled to work with SSLeay-0.9.0b and OpenSSL 0.9.2b
   Simplified to be even more minimal
   12/98 - 4/99 Wade Scholine <wades@mail.cybg.com> */

#include <unistd.h>
#include <stdio.h>
#include <memory.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <mqueue.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <mqueue.h>
#include "udptun.h"
#include "debug.h"

/* define HOME to be dir for key and cert files... */
#define HOME "./certs/"
/* Make these what you want for cert & key files */
#define CERTF HOME "client.crt"
#define KEYF HOME "client.key"
#define CACERT HOME "ca.crt"


#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }


SSL_CTX* ctx;
uint8_t* cmds[1024];
uint16_t cmds_len;


void getrandom(uint8_t* buf, uint8_t count) {
  FILE* fp = fopen("/dev/urandom", "r");
  fread(buf, 1, count, fp);
  fclose(fp);
}

void tls_client_cmd_key(void) {

  do_debug("TLS: Preparing session key command\n");
  uint8_t* this_cmd = (uint8_t*)cmds+cmds_len;
  this_cmd[0] = 0xCD;
  this_cmd[1] = 0xBD;
  this_cmd[2] = 0x00;  //Key command
  this_cmd[3] = 0x0A;

  uint32_t spi = htonl(defs[0].spi);
  memcpy(this_cmd+4, &spi, 4); //Add SPI

  getrandom(defs[0].key, 32);
  memcpy(this_cmd+8, defs[0].key, 32);

  cmds_len += 40;
}

void tls_client_cmd_iv(void) {

  do_debug("TLS: Preparing IV command\n");
  uint8_t* this_cmd = (uint8_t*)cmds+cmds_len;
  this_cmd[0] = 0xCD;
  this_cmd[1] = 0xBD;
  this_cmd[2] = 0x01;  //IV command
  this_cmd[3] = 0x06;

  uint32_t spi = htonl(defs[0].spi);
  memcpy(this_cmd+4, &spi, 4); //Add SPI

  getrandom(defs[0].iv, 16);
  memcpy(this_cmd+8, defs[0].iv, 16);

  cmds_len += 24;
}

void tls_client_cmd_start(void) {

  do_debug("TLS: Preparing start command\n");
  uint8_t* this_cmd = (uint8_t*)cmds+cmds_len;
  this_cmd[0] = 0xCD;
  this_cmd[1] = 0xBD;
  this_cmd[2] = 0x04;  //SPI/Start Command
  this_cmd[3] = 0x03;

  getrandom((uint8_t*)&defs[0].spi, 4);
  uint32_t spi = htonl(defs[0].spi);
  memcpy(this_cmd+4, &spi, 4); //Create SPI

  memcpy(this_cmd+8, &tun_sock.local.sin_port, 2);  //Add local UDP port
  //2 bytes padding

  cmds_len += 12;

  //Add default route for client side
  routes[0].network = inet_addr("0.0.0.0");
  routes[0].mask = inet_addr("0.0.0.0");
  routes[0].spi = defs[0].spi;
}

void tls_client_cmd_stop(void) {

  do_debug("TLS: Preparing stop command\n");
  uint8_t* this_cmd = (uint8_t*)cmds+cmds_len;
  this_cmd[0] = 0xCD;
  this_cmd[1] = 0xBD;
  this_cmd[2] = 0x02;  //Stop Command
  this_cmd[3] = 0x02;

  uint32_t spi = htonl(defs[0].spi);
  memcpy(this_cmd+4, &spi, 4); //Get SPI

  cmds_len += 8;
}

void tls_client_cmd_route(const char* network, const char* mask) {

  do_debug("TLS: Preparing route command\n");
  uint8_t* this_cmd = (uint8_t*)cmds+cmds_len;
  this_cmd[0] = 0xCD;
  this_cmd[1] = 0xBD;
  this_cmd[2] = 0x03;  //Route command
  this_cmd[3] = 0x04;

  uint32_t spi = htonl(defs[0].spi);
  memcpy(this_cmd+4, &spi, 4); //Add SPI

  in_addr_t local_ip = inet_addr(network);
  memcpy(this_cmd+8, &local_ip, 4);

  in_addr_t local_mask = inet_addr(mask);
  memcpy(this_cmd+12, &local_mask, 4);

  cmds_len += 16;
}



void tls_client_send(void) {

  int err;
  int sd;
  SSL*     ssl;
  X509*    server_cert;
  char*    str;

  /* ----------------------------------------------- */
  /* Create a socket and connect to server using normal socket calls. */

  sd = socket (AF_INET, SOCK_STREAM, 0);       CHK_ERR(sd, "socket");

  err = connect(sd, (struct sockaddr*) &defs[0].remote,
		sizeof(struct sockaddr_in));                   CHK_ERR(err, "connect");

  /* ----------------------------------------------- */
  /* Now we have TCP connection. Start SSL negotiation. */

  ssl = SSL_new (ctx);                         CHK_NULL(ssl);
  SSL_set_fd (ssl, sd);
  err = SSL_connect (ssl);                     CHK_SSL(err);

  /* Following two steps are optional and not required for
     data exchange to be successful. */

  /* Get the cipher - opt */

  printf ("SSL connection using %s\n", SSL_get_cipher (ssl));

  /* Get server's certificate (note: beware of dynamic allocation) - opt */

  server_cert = SSL_get_peer_certificate (ssl);       CHK_NULL(server_cert);
  printf ("Server certificate:\n");

  str = X509_NAME_oneline (X509_get_subject_name (server_cert),0,0);
  CHK_NULL(str);
  printf ("\t subject: %s\n", str);
  OPENSSL_free (str);

  str = X509_NAME_oneline (X509_get_issuer_name  (server_cert),0,0);
  CHK_NULL(str);
  printf ("\t issuer: %s\n", str);
  OPENSSL_free (str);

  /* We could do all sorts of certificate verification stuff here before
     deallocating the certificate. */


  if ((err = SSL_get_verify_result(ssl) != X509_V_OK)) {
      printf("Server certificate not verified");
  }

  X509_free (server_cert);

  /* --------------------------------------------------- */
  /* DATA EXCHANGE - Send a message and receive a reply. */

  //Send commands
  err = SSL_write(ssl, cmds, cmds_len);				  CHK_SSL(err);
  memset(cmds, 0, 1024);
  cmds_len = 0;

  SSL_shutdown (ssl);  /* send SSL/TLS close_notify */

  /* Clean up. */

  close (sd);
  SSL_free (ssl);

}


void tls_client_init(void)
{
  int err;

  const SSL_METHOD *meth;

  OpenSSL_add_ssl_algorithms();
  meth = TLSv1_2_client_method();
  SSL_load_error_strings();
  ctx = SSL_CTX_new (meth);                        CHK_NULL(ctx);

  CHK_SSL(err);


  SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL);
  SSL_CTX_set_verify_depth(ctx, 4);
  SSL_CTX_load_verify_locations(ctx,CACERT,NULL);



  if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0) {
	  ERR_print_errors_fp(stderr);
	  exit(-2);
  }

  if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0) {
	  ERR_print_errors_fp(stderr);
	  exit(-3);
  }

  if (!SSL_CTX_check_private_key(ctx)) {
	  printf("Private key does not match the certificate public key");
	  exit(-4);
  }

  //Send startup commands to server
  memset(cmds, 0, 1024);
  cmds_len = 0;

  pthread_mutex_lock(&defs_lock);

  tls_client_cmd_start();
  tls_client_cmd_route(defs[0].local_ip, "255.255.255.255");
  tls_client_send();

  pthread_mutex_unlock(&defs_lock);

  pthread_create(&udptun, NULL, udptun_init, NULL);

  struct mq_attr attr, *attrp;
  char command;
  attrp = NULL;
  attr.mq_maxmsg = 10;
  attr.mq_msgsize = 1;
  attrp = &attr;

  mqd_t mqd = mq_open("/cdbd-vpn", O_CREAT | O_RDWR, S_IRUSR | S_IWUSR, attrp);

  while(1) {

    mq_receive(mqd, &command, 1, NULL);

    pthread_mutex_lock(&defs_lock);
    switch(command) {
      case 0x00:
	tls_client_cmd_key();
	break;
      case 0x01:
	tls_client_cmd_iv();
	break;
      case 0x02:
	tls_client_cmd_stop();
	break;
      default:
	break;
    }
    tls_client_send();
    pthread_mutex_unlock(&defs_lock);

  }
}
