/*
 * esp.c
 *
 * aes256_encrypt, aes256_decrypt from https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
 * sha256_hmac_sign, sha256_hmac_verify from https://wiki.openssl.org/index.php/EVP_Signing_and_Verifying
 */


#include "esp.h"
#include "debug.h"

typedef unsigned char byte;


void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}

int aes256_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int ciphertext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  /* Initialise the encryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleErrors();

  /* Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handleErrors();
  ciphertext_len = len;

  /* Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
  ciphertext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}


int aes256_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, unsigned char *plaintext)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int plaintext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  /* Initialise the decryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleErrors();

  /* Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    handleErrors();
  plaintext_len = len;

  /* Finalise the decryption. Further plaintext bytes may be written at
   * this stage.
   */
  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
  plaintext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}


int sha256_hmac_sign(const byte* msg, size_t mlen, byte** sig, size_t* slen, EVP_PKEY* pkey)
{
    /* Returned to caller */
    int result = -1;

    if(!msg || !mlen || !sig || !pkey) {
        assert(0);
        return -1;
    }

    if(debug) {
	printf("Message to sign is:\n");
	BIO_dump_fp(stdout, (const char *)msg, mlen);
    }

    if(*sig)
        OPENSSL_free(*sig);

    *sig = NULL;
    *slen = 0;

    EVP_MD_CTX* ctx = NULL;

    do
    {
        ctx = EVP_MD_CTX_create();
        assert(ctx != NULL);
        if(ctx == NULL) {
            printf("EVP_MD_CTX_create failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }

        const EVP_MD* md = EVP_get_digestbyname("SHA256");
        assert(md != NULL);
        if(md == NULL) {
            printf("EVP_get_digestbyname failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }

        int rc = EVP_DigestInit_ex(ctx, md, NULL);
        assert(rc == 1);
        if(rc != 1) {
            printf("EVP_DigestInit_ex failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }

        rc = EVP_DigestSignInit(ctx, NULL, md, NULL, pkey);
        assert(rc == 1);
        if(rc != 1) {
            printf("EVP_DigestSignInit failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }

        rc = EVP_DigestSignUpdate(ctx, msg, mlen);
        assert(rc == 1);
        if(rc != 1) {
            printf("EVP_DigestSignUpdate failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }

        size_t req = 0;
        rc = EVP_DigestSignFinal(ctx, NULL, &req);
        assert(rc == 1);
        if(rc != 1) {
            printf("EVP_DigestSignFinal failed (1), error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }

        assert(req > 0);
        if(!(req > 0)) {
            printf("EVP_DigestSignFinal failed (2), error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }

        *sig = OPENSSL_malloc(req);
        assert(*sig != NULL);
        if(*sig == NULL) {
            printf("OPENSSL_malloc failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }

        *slen = req;
        rc = EVP_DigestSignFinal(ctx, *sig, slen);
        assert(rc == 1);
        if(rc != 1) {
            printf("EVP_DigestSignFinal failed (3), return code %d, error 0x%lx\n", rc, ERR_get_error());
            break; /* failed */
        }

        assert(req == *slen);
        if(rc != 1) {
            printf("EVP_DigestSignFinal failed, mismatched signature sizes %ld, %ld", req, *slen);
            break; /* failed */
        }
        if(debug) {
            printf("Signature is:\n");
            BIO_dump_fp(stdout, (const char *)*sig, *slen);
        }

        result = 0;

    } while(0);

    if(ctx) {
        EVP_MD_CTX_destroy(ctx);
        ctx = NULL;
    }

    /* Convert to 0/1 result */
    return !!result;
}


int sha256_hmac_verify(const byte* msg, size_t mlen, const byte* sig, size_t slen, EVP_PKEY* pkey)
{
    /* Returned to caller */
    int result = -1;

    if(!msg || !mlen || !sig || !slen || !pkey) {
        assert(0);
        return -1;
    }

    if(debug) {
      printf("Signature to verify is:\n");
      BIO_dump_fp(stdout, (const char *)sig, slen);
      printf("Message to verify is:\n");
      BIO_dump_fp(stdout, (const char *)msg, mlen);
    }


    EVP_MD_CTX* ctx = NULL;

    do
    {
        ctx = EVP_MD_CTX_create();
        assert(ctx != NULL);
        if(ctx == NULL) {
            printf("EVP_MD_CTX_create failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }

        const EVP_MD* md = EVP_get_digestbyname("SHA256");
        assert(md != NULL);
        if(md == NULL) {
            printf("EVP_get_digestbyname failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }

        int rc = EVP_DigestInit_ex(ctx, md, NULL);
        assert(rc == 1);
        if(rc != 1) {
            printf("EVP_DigestInit_ex failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }

        rc = EVP_DigestSignInit(ctx, NULL, md, NULL, pkey);
        assert(rc == 1);
        if(rc != 1) {
            printf("EVP_DigestSignInit failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }

        rc = EVP_DigestSignUpdate(ctx, msg, mlen);
        assert(rc == 1);
        if(rc != 1) {
            printf("EVP_DigestSignUpdate failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }

        byte buff[EVP_MAX_MD_SIZE];
        size_t size = sizeof(buff);

        rc = EVP_DigestSignFinal(ctx, buff, &size);
        assert(rc == 1);
        if(rc != 1) {
            printf("EVP_DigestVerifyFinal failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }

        assert(size > 0);
        if(!(size > 0)) {
            printf("EVP_DigestSignFinal failed (2)\n");
            break; /* failed */
        }

        if(debug) {
            printf("Signature generated is:\n");
            BIO_dump_fp(stdout, (const char *)&buff, size);
        }


        const size_t m = (slen < size ? slen : size);
        result = !!CRYPTO_memcmp(sig, buff, m);

        if(debug && result) {
            printf("Signature is BAD\n");
        } else {
            printf("Signature is GOOD\n");
        }

        OPENSSL_cleanse(buff, sizeof(buff));

    } while(0);

    if(ctx) {
        EVP_MD_CTX_destroy(ctx);
        ctx = NULL;
    }

    /* Convert to 0/1 result */
    return !!result;
}



int esp_encode(uint8_t* pkt, uint32_t spi, uint32_t seq, uint8_t* data, uint16_t data_len, uint8_t* key, uint8_t* iv) {

  int ciphertext_len, pktlen = 0;
  byte *sig_actual = NULL;
  byte **sig = &sig_actual;
  size_t slen = 0;
  EVP_PKEY* pkey;
  uint32_t spi_n, seq_n;

  spi_n = htonl(spi);
  seq_n = htonl(seq);

  pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, 32);

  memset(pkt, 0, BUFSIZE);

  uint8_t* pktp = pkt;
  memcpy(pktp, &spi_n, 4);
  pktlen += 4;
  memcpy(pktp+pktlen, &seq_n, 4);
  pktlen += 4;

  ciphertext_len = aes256_encrypt(data, data_len, key, iv, pktp+pktlen);
  pktlen += ciphertext_len;


  if((sha256_hmac_sign(pktp, pktlen, sig, &slen, pkey))) {
      do_debug("sha256_hmac_sign failed\n");
      return -1;
  }
  memcpy(pktp+pktlen, *sig, slen);
  pktlen += slen;

  if(debug) {
      printf("ESP to send is:\n");
      BIO_dump_fp(stdout, (const char *)pktp, pktlen);
  }


  return pktlen;

}

int esp_decode(uint8_t* pkt, uint16_t pktlen, uint32_t* seq, uint8_t* data, uint16_t* data_len, uint8_t* key, uint8_t* iv) {

  int ciphertext_len = pktlen - 32 - 8; //SPI + sequence + HMAC
  int verify_len = pktlen - 32;
  int index = 0;
  uint32_t seq_n;
  EVP_PKEY* pkey;

  pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, 32);

  memset(data, 0, BUFSIZE);

  if(debug) {
      printf("ESP to process is:\n");
      BIO_dump_fp(stdout, (const char *)pkt, pktlen);
  }

  uint8_t* pktp = pkt;
  index += 4;
  memcpy(&seq_n, pktp+index, 4);
  *seq = ntohl(seq_n);
  index += 4;

  if((sha256_hmac_verify(pktp, verify_len, pktp+verify_len, 32, pkey))) {
      do_debug("sha256_hmac_verify failed\n");
      return -1;
  }

  *data_len = aes256_decrypt(pkt+index, ciphertext_len, key, iv, data);

  return 0;
}


