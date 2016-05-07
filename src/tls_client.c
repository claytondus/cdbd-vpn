/*
 * tls_client.c
 *
 *  Created on: May 5, 2016
 *      Author: parallels
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
#include <openssl/rsa.h>    /* key exchange stuff */
#include <openssl/pem.h>

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

void tls_client_init(char *certloc)
{
  int err;
  int sd;
  struct sockaddr_in sa;
  SSL_CTX* ctx;
  SSL*     ssl;
  X509*    server_cert;
  char*    str;
  char     buf [4096];
  const SSL_METHOD *meth;
  char *rsakey;

  OpenSSL_add_ssl_algorithms();
  meth = TLSv1_2_client_method();
  SSL_load_error_strings();
  ctx = SSL_CTX_new (meth);                        CHK_NULL(ctx);

  CHK_SSL(err);


  SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL);
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
	  printf("Private key does not match the certificate public keyn");
	  exit(-4);
  }

  /* ----------------------------------------------- */
  /* Create a socket and connect to server using normal socket calls. */

  sd = socket (AF_INET, SOCK_STREAM, 0);       CHK_ERR(sd, "socket");

  memset (&sa, '\0', sizeof(sa));
  sa.sin_family      = AF_INET;
  sa.sin_addr.s_addr = inet_addr ("10.37.129.6");   /* Server IP */
  sa.sin_port        = htons     (1111);          /* Server Port number */

  err = connect(sd, (struct sockaddr*) &sa,
		sizeof(sa));                   CHK_ERR(err, "connect");

  /* ----------------------------------------------- */
  /* Now we have TCP connection. Start SSL negotiation. */

  ssl = SSL_new (ctx);                         CHK_NULL(ssl);
  SSL_set_fd (ssl, sd);
  err = SSL_connect (ssl);                     CHK_SSL(err);

  /* Following two steps are optional and not required for
     data exchange to be successful. */
  rsakey = keyExchange();    /* Get the cipher - opt */
  
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

  X509_free (server_cert);

  /* --------------------------------------------------- */
  /* DATA EXCHANGE - Send a message and receive a reply. */

  err = SSL_write (ssl, "Hello World!", strlen("Hello World!"));  CHK_SSL(err);

  err = SSL_read (ssl, buf, sizeof(buf) - 1);                     CHK_SSL(err);
  buf[err] = '\0';
  printf ("Got %d chars:'%s'\n", err, buf);
  SSL_shutdown (ssl);  /* send SSL/TLS close_notify */

  /* Clean up. */

  close (sd);
  SSL_free (ssl);
  SSL_CTX_free (ctx);

} 

char *keyExchange() {
  int keylen; char *pem_key;
  RSA *r = RSA_generate_key(1024, 65537, 0)    /* chose this instead of k=3 because security issue */
  
  BIO *bio = BIO_new(BIO_s_mem());
  PEM_write_bio_RSAPrivateKey(bio, r, NULL, NULL, 0, NULL, NULL);

  keylen = BIO_pending(bio);
  pem_key = calloc(keylen + 1, 1);
  BIO_read(bio, pem_key, keylen);
  BIO_free_all(bio);
  printf("%s", pem_key);
  
  return pem_key;
}
