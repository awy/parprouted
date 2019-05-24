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

#include <net/if.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <linux/if_packet.h>
#include <netinet/if_ether.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

#include "parprouted.h"


#ifndef arp_hrd /* should be in netinet/if_ether.h */
// ===================
/*
 * Ethernet Address Resolution Protocol.
 *
 * See RFC 826 for protocol description.  Structure below is adapted
 * to resolving internet addresses.  Field names used correspond to
 * RFC 826.
 */
struct	ether_arp {
	struct	arphdr ea_hdr;		/* fixed-size header */
	u_int8_t arp_sha[ETH_ALEN];	/* sender hardware address */
	u_int8_t arp_spa[4];		/* sender protocol address */
	u_int8_t arp_tha[ETH_ALEN];	/* target hardware address */
	u_int8_t arp_tpa[4];		/* target protocol address */
};
#define	arp_hrd	ea_hdr.ar_hrd
#define	arp_pro	ea_hdr.ar_pro
#define	arp_hln	ea_hdr.ar_hln
#define	arp_pln	ea_hdr.ar_pln
#define	arp_op	ea_hdr.ar_op
#endif

// ===============

typedef struct _ether_arp_frame { 
  struct ether_header ether_hdr;
  struct ether_arp arp;
} __attribute__ ((packed)) ether_arp_frame;

typedef struct _req_struct {
    ether_arp_frame req_frame;
    struct sockaddr_ll req_if;
    struct _req_struct *next;
} RQ_ENTRY;

/* shared across all theads */
RQ_ENTRY *req_queue = NULL;
RQ_ENTRY *req_queue_tail = NULL;
int req_queue_len = 0;
pthread_mutex_t req_queue_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Wait for an ARP packet */
int arp_recv(int sock, ether_arp_frame *frame) 
{
    char packet[4096];
    int nread;

    memset(frame, 0, sizeof(ether_arp_frame));
    
    nread=recv(sock, &packet, sizeof(packet), 0);
    
    if (nread < 0) return -1;

    if (nread > (int)sizeof(ether_arp_frame)) {
	nread=sizeof(ether_arp_frame);
    }
    
    if (nread >= 0) memcpy(frame, &packet, nread);

    return nread;
}

const char * format_eth_addr(char * to, const uint8_t * from)
{
    snprintf(to, 3*ETH_ALEN, "%2.02x:%2.02x:%2.02x:%2.02x:%2.02x:%2.02x",
	    from[0], from[1], from[2], from[3], from[4], from[5]);
    return to;
}

const char * format_ipv4_addr(char * to, const void * f)
{
    const uint8_t * from = f;
    snprintf(to, 4*4, "%d.%d.%d.%d",
	    from[0], from[1], from[2], from[3]);
    return to;
}

void log_arp_packet(const char *ifname, const ether_arp_frame *frame, int send)
{
    const struct ether_arp *arp = &frame->arp;

    char from[3*ETH_ALEN], to[3*ETH_ALEN], sha[3*ETH_ALEN], tha[3*ETH_ALEN];
    char spa[4*4], tpa[4*4];

    printf("%-6s %s %s %s -> %s: sha:%s tha:%s spa:%-15s tpa:%-15s\n", ifname,
	    send ? ">" : "<",
	    arp->arp_op == htons(ARPOP_REPLY) ? "RP" : "RQ",
	    format_eth_addr(from, frame->ether_hdr.ether_shost),
	    format_eth_addr(to, frame->ether_hdr.ether_dhost),
	    format_eth_addr(sha, arp->arp_sha),
	    format_eth_addr(tha, arp->arp_tha),
	    format_ipv4_addr(spa, arp->arp_spa),
	    format_ipv4_addr(tpa, arp->arp_tpa));
}

/* Send ARP is-at reply */

void arp_reply(ether_arp_frame *reqframe, struct sockaddr_ll *ifs)
{
  struct ether_arp *arp = &reqframe->arp;
  unsigned char ip[4];
  int sock;

  sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));

  if (bind(sock, (struct sockaddr *) ifs, sizeof(struct sockaddr_ll)) < 0) {
    fprintf(stderr, "arp_reply() bind: %s\n", strerror(errno));
    abort();
  }

  memcpy(&reqframe->ether_hdr.ether_dhost, &arp->arp_sha, ETH_ALEN);
  memcpy(&reqframe->ether_hdr.ether_shost, ifs->sll_addr, ETH_ALEN);

  memcpy(&arp->arp_tha, &arp->arp_sha, ETH_ALEN);
  memcpy(&arp->arp_sha, ifs->sll_addr, ETH_ALEN);

  memcpy(ip, &arp->arp_spa, 4);
  memcpy(&arp->arp_spa, &arp->arp_tpa, 4);
  memcpy(&arp->arp_tpa, ip, 4);

  arp->arp_op = htons(ARPOP_REPLY);

  sendto(sock, reqframe, sizeof(ether_arp_frame), 0, 
	 (struct sockaddr *)ifs, sizeof(struct sockaddr_ll));

  if (debug) {
      struct ifreq ifr;
      char ifname[IFNAMSIZ+1];

      ifr.ifr_ifindex = ifs->sll_ifindex;
      ioctl(sock, SIOCGIFNAME, &ifr);
      memcpy(ifname, ifr.ifr_name, IFNAMSIZ);
      ifname[IFNAMSIZ] = 0;

      log_arp_packet(ifname, reqframe, 1);
  }

  close(sock);
}

/* Send ARP who-has request */

void arp_req(const char *ifname, const struct in_addr remaddr, int gratuitous)
{
  ether_arp_frame frame;
  struct ether_arp *arp = &frame.arp;
  int sock;
  struct sockaddr_ll ifs;
  struct ifreq ifr;

  /* Make sure that interface is not empty */
  if (strcmp(ifname, "") == 0)
    return;
  
  sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));

  /* Get the hwaddr and ifindex of the interface */
  memset(ifr.ifr_name, 0, IFNAMSIZ);
  strncpy(ifr.ifr_name, (char *) ifname, IFNAMSIZ);
  if(ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
    syslog(LOG_ERR, "error in arp_req(): ioctl SIOCGIFHWADDR for %s: %s\n", (char *) ifname, strerror(errno));
    abort();
  }

  memset(ifs.sll_addr, 0, ETH_ALEN);
  memcpy(ifs.sll_addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

  if(ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
	syslog(LOG_ERR, "error in arp_req(): ioctl SIOCGIFINDEX for %s: %s", (char *) ifname, strerror(errno));
        return;
  }

  ifs.sll_family = AF_PACKET;
  ifs.sll_protocol = htons(ETH_P_ARP);
  ifs.sll_ifindex = ifr.ifr_ifindex;
  ifs.sll_hatype = ARPHRD_ETHER;
  ifs.sll_pkttype = PACKET_BROADCAST;
  ifs.sll_halen = ETH_ALEN;

  memset(&frame.ether_hdr.ether_dhost, 0xFF, ETH_ALEN);
  memcpy(&frame.ether_hdr.ether_shost, ifs.sll_addr, ETH_ALEN);
  frame.ether_hdr.ether_type = htons(ETHERTYPE_ARP);

  arp->arp_hrd = htons(ARPHRD_ETHER);
  arp->arp_pro = htons(ETH_P_IP);
  arp->arp_hln = ETH_ALEN;
  arp->arp_pln = 4;
  memset(&arp->arp_tha, 0, ETH_ALEN);
  memcpy(&arp->arp_sha, ifs.sll_addr, ETH_ALEN);

  memcpy(&arp->arp_tpa, &remaddr.s_addr, 4);
  if (gratuitous)
      memcpy(&arp->arp_spa, &remaddr.s_addr, 4);
  else {
      if (ioctl(sock, SIOCGIFADDR, &ifr) == 0) {
	const struct sockaddr_in * sin = (struct sockaddr_in *) &ifr.ifr_addr;
        memcpy(&arp->arp_spa, &sin->sin_addr.s_addr, 4);
      }
  }

  arp->arp_op = htons(ARPOP_REQUEST);

  sendto(sock, &frame, sizeof(ether_arp_frame), 0, 
	 (struct sockaddr *) &ifs, sizeof(struct sockaddr_ll));
  close(sock);

  if (debug) log_arp_packet(ifname, &frame, 1);

}

int rq_add(ether_arp_frame *req_frame, struct sockaddr_ll *req_if)
{
    RQ_ENTRY *new_entry;
    
    if ((new_entry = (RQ_ENTRY *) malloc(sizeof(RQ_ENTRY))) == NULL) {
	    syslog(LOG_ERR, "No memory: %s", strerror(errno));
	    return 0;
    }

    pthread_mutex_lock(&req_queue_mutex);

    req_queue_len++;

    /* Check if the list has more entries than MAX_RQ_SIZE, 
     * and delete the oldest entry */    
    if (req_queue_len > MAX_RQ_SIZE) {
	RQ_ENTRY *temp;
	
	if (debug)
	    printf("Request queue has grown too large, deleting last element\n");
	temp = req_queue;
	req_queue = req_queue->next;
	req_queue_len--;
	
	free(temp);
    }

    /* Add entry to the list */
    
    if (req_queue != NULL)
	req_queue_tail->next = new_entry;
    else
	req_queue = new_entry;

    req_queue_tail = new_entry;

    new_entry->next = NULL;

    memcpy(&new_entry->req_frame, req_frame, sizeof(ether_arp_frame));
    memcpy(&new_entry->req_if, req_if, sizeof(struct sockaddr_ll));

    pthread_mutex_unlock(&req_queue_mutex);
    
    return 1;
}

void rq_process(struct in_addr ipaddr, int ifindex)
{
    RQ_ENTRY *cur_entry;
    RQ_ENTRY *prev_entry = NULL;

    pthread_mutex_lock(&req_queue_mutex);

    cur_entry = req_queue;
    
    /* Walk through the list */
    
    while (cur_entry != NULL) {
	if ( memcmp(&ipaddr.s_addr, cur_entry->req_frame.arp.arp_tpa, 4) == 0 && ifindex != cur_entry->req_if.sll_ifindex ) {

	    if (debug)
	        printf("Found %s in request queue\n", inet_ntoa(ipaddr));
	    arp_reply(&cur_entry->req_frame, &cur_entry->req_if);

	    /* Delete entry from the linked list */
	    	    
	    if (cur_entry == req_queue_tail)
		req_queue_tail = prev_entry;
	    
	    if (prev_entry != NULL)
		prev_entry->next = cur_entry->next;
	    else
		req_queue = cur_entry->next;
		
	    free(cur_entry);
	    cur_entry = prev_entry;
	
	    req_queue_len--;

	}

	if (cur_entry != NULL) {
    	    prev_entry = cur_entry;
	    cur_entry = cur_entry->next;
	}
    }
    
    pthread_mutex_unlock(&req_queue_mutex);
}

void *arp(void * arg) {
    const int idx = *((int *)arg);
    const char * ifname = g_ifaces[idx];

    int sock, i;
    struct sockaddr_ll ifs;
    struct ifreq ifr;

    sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));

    if (sock == -1) {
	fprintf(stderr, "Socket error %d.\n", errno);
	exit(1);
    }

    /* Get the hwaddr and ifindex of the interface */
    memset(ifr.ifr_name, 0, IFNAMSIZ);
    strncpy(ifr.ifr_name, (char *) ifname, IFNAMSIZ);
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
	syslog(LOG_ERR, "error: ioctl SIOCGIFHWADDR for %s: %s\n",
	        (char *) ifname, strerror(errno));
	abort();
    }

    memset(ifs.sll_addr, 0, ETH_ALEN);
    memcpy(ifs.sll_addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
	syslog(LOG_ERR, "error: ioctl SIOCGIFINDEX for %s: %s", (char *) ifname,
	        strerror(errno));
	abort();
    }

    ifs.sll_family = AF_PACKET;
    ifs.sll_protocol = htons(ETH_P_ARP);
    ifs.sll_ifindex = ifr.ifr_ifindex;
    ifs.sll_hatype = ARPHRD_ETHER;
    ifs.sll_pkttype = PACKET_BROADCAST;
    ifs.sll_halen = ETH_ALEN;

    if (bind(sock, (struct sockaddr *) &ifs, sizeof(struct sockaddr_ll)) < 0) {
	fprintf(stderr, "Bind %s: %d\n", (char *) ifname, errno);
	abort();
    }

    while (1) {
	ether_arp_frame frame;
	struct in_addr my_ip;
	struct in_addr spa;
	struct in_addr tpa;
	int manage_routes;

	if (g_perform_shutdown)
	    return 0;

	i = arp_recv(sock, &frame);

	if (g_perform_shutdown)
	    return 0;

	if (i < 0 && errno == ENETDOWN) {
	    remove_routes(idx);
	}

	if (i <= 0)
	    continue;

	if (frame.arp.arp_hln != ETH_ALEN || frame.arp.arp_pln != sizeof(spa.s_addr)) continue;

	if (debug) log_arp_packet(ifname, &frame, 0);

	/* Refresh local address every time around in case it changes */
	if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
	    my_ip.s_addr = 0; // work without IP address assigned to interface
	} else {
	    my_ip.s_addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
	}
	memcpy(&spa.s_addr, frame.arp.arp_spa, frame.arp.arp_pln);
	memcpy(&tpa.s_addr, frame.arp.arp_tpa, frame.arp.arp_pln);

	if (frame.arp.arp_op == ntohs(ARPOP_REPLY)) {
	    /* Received frame is an ARP reply */

	    /* Check if reply is for one of the requests in request queue */
	    if (g_proxy_arp) rq_process(spa, ifs.sll_ifindex);

	    manage_route(spa, idx);

	    /* send gratuitous ARP request to all other interfaces to let them
	     * update their ARP tables quickly */
	    if (g_proxy_arp && spa.s_addr != my_ip.s_addr) { // ignore reports for own IP address
		for (i = 0; i <= g_last_iface_idx; i++) {
		    if (i != idx) {
			arp_req(g_ifaces[i], spa, 1);
		    }
		}
	    }
	}

	else if (frame.arp.arp_op == ntohs(ARPOP_REQUEST)) {
	    /* Received frame is an ARP request */

	    if (tpa.s_addr == my_ip.s_addr) continue; // ignore requests for own IP address

	    /* Distinguish between different types:
	     *    Probe:    spa == 0, tpa != 0
	     *    Announce: spa == tpa
	     *    request:  spa != tpa
	     */

	    if (tpa.s_addr != 0) {
		const int announce = spa.s_addr == tpa.s_addr;
		const int probe    = spa.s_addr == 0;

		if (g_proxy_arp) {
		    /* Relay the ARP request to all other interfaces */
		    for (i = 0; i <= g_last_iface_idx; i++) {
			if (i != idx) {
			    arp_req(g_ifaces[i], tpa, announce); // gratutious if announce
			}
		    }

		    if (!announce) {
			/* Add the request to the request queue unless Announce */
			if (debug) printf("Adding %s to request queue\n", inet_ntoa(spa));
			rq_add(&frame, &ifs);
		    }
		}

		if (!probe) {
		    manage_route(spa, idx);
		}
	    }
	}
    }
}
