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


}

void tls_client_cmd_key(void) {

  do_debug("TLS: Preparing session key command\n");
  uint8_t* this_cmd = (uint8_t*)cmds+cmds_len;
  this_cmd[0] = 0xCD;
  this_cmd[1] = 0xBD;
  this_cmd[2] = 0x00;  //Key command
  this_cmd[3] = 0x08;  //256 bits, 32 bytes, 8 words

  FILE* fp = fopen("/dev/urandom", "r");
  fread(this_cmd+4, 1, 32, fp);
  fclose(fp);

  cmds_len += 36;
}

void tls_client_cmd_iv(void) {

  do_debug("TLS: Preparing IV command\n");
  uint8_t* this_cmd = (uint8_t*)cmds+cmds_len;
  this_cmd[0] = 0xCD;
  this_cmd[1] = 0xBD;
  this_cmd[2] = 0x01;  //IV command
  this_cmd[3] = 0x04;  //128 bits, 16 bytes, 4 words

  FILE* fp = fopen("/dev/urandom", "r");
  fread(this_cmd+4, 1, 16, fp);
  fclose(fp);

  cmds_len += 20;
}

void tls_client_cmd_spi(void) {

  do_debug("TLS: Preparing SPI command\n");
  uint8_t* this_cmd = (uint8_t*)cmds+cmds_len;
  this_cmd[0] = 0xCD;
  this_cmd[1] = 0xBD;
  this_cmd[2] = 0x04;  //SPI Command
  this_cmd[3] = 0x01;  //32 bits, 4 bytes, 1 word

  FILE* fp = fopen("/dev/urandom", "r");
  fread(this_cmd+4, 1, 4, fp);
  fclose(fp);

  cmds_len += 20;
}


void tls_client_send(void) {

  int err;
  int sd;
  SSL*     ssl;
  X509*    server_cert;
  char*    str;
  char     buf[4096];

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

  err = SSL_write (ssl, "Hello World!", strlen("Hello World!"));  CHK_SSL(err);

  err = SSL_read (ssl, buf, sizeof(buf) - 1);                     CHK_SSL(err);
  buf[err] = '\0';
  printf ("Got %d chars:'%s'\n", err, buf);

  //Send commands
  err = SSL_write(ssl, cmds, cmds_len);				  CHK_SSL(err);
  memset(cmds, 0, 1024);
  cmds_len = 0;

  SSL_shutdown (ssl);  /* send SSL/TLS close_notify */

  /* Clean up. */

  close (sd);
  SSL_free (ssl);

}

