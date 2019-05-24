/* parprouted: ProxyARP routing daemon. 
 * (C) 2008 Vladimir Ivaschenko <vi@maks.net>
 * Copyright (C) 2019 Lenbrook Industries Limited
 *
 * This application is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#define PROC_ARP "/proc/net/arp"
#define ARP_LINE_LEN 255
#define ARP_TABLE_ENTRY_LEN 20
#define ARP_TABLE_ENTRY_TIMEOUT 60 /* seconds */
#define ROUTE_CMD_LEN 255
#define SLEEPTIME 1000000 /* ms */
#define REFRESHTIME 50 /* seconds */
#define MAX_IFACES 10

#define MAX_RQ_SIZE 50	/* maximum size of request queue */

#define VERSION "bluos_1.0"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>
#include <sys/wait.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <assert.h>
#include <libgen.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

extern int debug;
extern int verbose;

extern int g_perform_shutdown;

extern char * g_ifaces[MAX_IFACES];
extern int g_last_iface_idx;
extern int g_manage_routes;
extern int g_proxy_arp;

extern void *arp(void *arg);
extern void arp_req(const char *ifname, const struct in_addr remaddr, int gratuitous);
extern void manage_route(const struct in_addr address, const int ifx);
extern void remove_routes(int idx);

