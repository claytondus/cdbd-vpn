#include "esp.h"
#include "unity.h"
#include "unity_fixture.h"

TEST_GROUP(esp);

TEST_SETUP(esp)
{

}

TEST_TEAR_DOWN(esp)
{

}

TEST(esp, EspCanEncode)
{
  /* A 256 bit key */
  unsigned char *key = (unsigned char *)"01234567890123456789012345678901";

  /* A 128 bit IV */
  unsigned char *iv = (unsigned char *)"01234567890123456";

  /* Message to be encrypted */
  unsigned char *plaintext =
                (unsigned char *)"The quick brown fox jumps over the lazy dog";

  /* Buffer for ciphertext. Ensure the buffer is long enough for the
   * ciphertext which may be longer than the plaintext, dependent on the
   * algorithm and mode
   */
  unsigned char pkt[BUFSIZE];

  int pkt_len;

  /* Encrypt the plaintext */
  pkt_len = esp_encode(pkt, 0xDEADBEEF, 0x3240, plaintext, strlen ((char *)plaintext), key, iv);
  TEST_ASSERT(pkt_len > 0);

  /* Do something useful with the ciphertext here */
  printf("Ciphertext is:\n");
  BIO_dump_fp (stdout, (const char *)pkt, pkt_len);

  uint32_t seq;
  uint8_t dec[BUFSIZE];
  uint16_t dec_len;

  /* Decrypt the ciphertext */
  int success = esp_decode(pkt, pkt_len, &seq, dec, &dec_len, key, iv);
  TEST_ASSERT(success == 0);

  /* Add a NULL terminator. We are expecting printable text */
  dec[dec_len] = '\0';

  /* Show the decrypted text */
  printf("Decrypted text is:\n");
  printf("%s\n", dec);


}
