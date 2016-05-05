#include "esp.h"
#include "unity_fixture.h"

static void RunAllTests(void)
{
  RUN_TEST_GROUP(esp);
}

int main(int argc, const char * argv[])
{
  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
  OPENSSL_config(NULL);
  return UnityMain(argc, argv, RunAllTests);
}
