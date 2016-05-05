/*
 * esp.h
 */

#ifndef INCLUDE_ESP_H_
#define INCLUDE_ESP_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
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
#include <errno.h>
#include <stdarg.h>
#include <assert.h>
#include <openssl/hmac.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include "conf.h"


int esp_encode(uint8_t* pkt, uint32_t spi, uint32_t seq, uint8_t* data, uint16_t data_len, uint8_t* key, uint8_t* iv);
int esp_decode(uint8_t* pkt, uint16_t pktlen, uint32_t* seq, uint8_t* data, uint16_t* data_len, uint8_t* key, uint8_t* iv);

#endif /* INCLUDE_ESP_H_ */
