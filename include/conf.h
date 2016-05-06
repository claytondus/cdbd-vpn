/*
 * conf.h
 *
 *  Created on: May 4, 2016
 *      Author: parallels
 */

#ifndef INCLUDE_CONF_H_
#define INCLUDE_CONF_H_

/* buffer for reading from tun/tap interface, must be >= 1500 */
#define BUFSIZE 2000
#define CLIENT 0
#define SERVER 1
#define PORT 55555

#define SHM_SIZE 65536
#define MAX_TUNDEFS 256
#define MAX_ROUTES 256


#endif /* INCLUDE_CONF_H_ */
