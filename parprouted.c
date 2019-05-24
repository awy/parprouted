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
 *
 */
 
#include "parprouted.h"

char *progname;
int debug=0;
int verbose=0;
int g_perform_shutdown=0;
int g_manage_routes = 1;
int g_proxy_arp = 1;


char *errstr;

pthread_t my_threads[MAX_IFACES+1];
int last_thread_idx=-1;

char * g_ifaces[MAX_IFACES];
int g_last_iface_idx=-1;

typedef struct route_entry {
    struct in_addr ipaddr_ia;
    int idx;
    time_t tstamp;
    int route_added;
    int want_route;
    struct route_entry *next;
} ROUTE_ENTRY;

ROUTE_ENTRY **route_table;
pthread_mutex_t route_table_mutex;

ROUTE_ENTRY * get_route_entry_LOCKED(ROUTE_ENTRY ** route_table_p, struct in_addr ipaddr, int idx)
{
    ROUTE_ENTRY * cur_entry=*route_table_p;
    ROUTE_ENTRY * prev_entry=NULL;

    while (cur_entry != NULL && ( ipaddr.s_addr != cur_entry->ipaddr_ia.s_addr || cur_entry->idx != idx ) ) {
	prev_entry = cur_entry;
	cur_entry = cur_entry->next;
    };

    if (cur_entry == NULL) {
	if (debug) printf("Creating new route_table entry %s(%s)\n", inet_ntoa(ipaddr), g_ifaces[idx]);

	if ((cur_entry = (ROUTE_ENTRY *) malloc(sizeof(ROUTE_ENTRY))) == NULL) {
	    errstr = strerror(errno);
	    syslog(LOG_ERR, "No memory: %s", errstr);
	} else {
	    if (prev_entry == NULL) { *route_table_p=cur_entry; }
	    else { prev_entry->next = cur_entry; }
	    cur_entry->next = NULL;
	    cur_entry->idx = idx;
	    cur_entry->ipaddr_ia.s_addr = ipaddr.s_addr;
	    cur_entry->route_added = 0;
	}
    }
    
    return cur_entry;
}

/* Remove all entires in route_table where ipaddr is NOT on interface dev */
int remove_other_routes_LOCKED(ROUTE_ENTRY * cur_entry, struct in_addr ipaddr, int idx)
{
    int removed = 0;

    for (; cur_entry != NULL; cur_entry = cur_entry->next) {
        if (ipaddr.s_addr == cur_entry->ipaddr_ia.s_addr && idx != cur_entry->idx)  {
            if (debug && cur_entry->want_route) printf("Marking entry %s(%s) for removal\n", inet_ntoa(ipaddr), g_ifaces[cur_entry->idx]);
            cur_entry->want_route = 0;
            ++removed;
        }
    }
    if (debug && removed)
	printf("Found entry %s(%s), removed entries via other interfaces\n",
		inet_ntoa(ipaddr), g_ifaces[idx]);

    return removed;
}

/* Remove route from kernel */
int route_remove_LOCKED(ROUTE_ENTRY* entry)
{
    char routecmd_str[ROUTE_CMD_LEN];
    int success = 1;
    
    if (snprintf(routecmd_str, ROUTE_CMD_LEN-1, 
	    "/sbin/ip route del %s/32 metric 50 dev %s scope link",
	    inet_ntoa(entry->ipaddr_ia), g_ifaces[entry->idx]) > ROUTE_CMD_LEN-1)
    {
	syslog(LOG_ERR, "ip route command too large to fit in buffer!");
    } else {
	if (system(routecmd_str) != 0)
	{
	    syslog(LOG_ERR, "'%s' unsuccessful!", routecmd_str);
	    if (debug) printf("%s failed\n", routecmd_str);
	    success = 0;
	}
	else 
	{
	    syslog(LOG_INFO, "route added for %s via %s", inet_ntoa(entry->ipaddr_ia), g_ifaces[entry->idx]);
	    if (debug) printf("%s success\n", routecmd_str);
	    success = 1;
	}
    }
    if (success)
	entry->route_added = 0;
    
    return success;
}

/* Add route into kernel */
int route_add_LOCKED(ROUTE_ENTRY* entry)
{
    char routecmd_str[ROUTE_CMD_LEN];
    int success = 1;

    if (snprintf(routecmd_str, ROUTE_CMD_LEN-1, 
	    "/sbin/ip route add %s/32 metric 50 dev %s scope link",
	    inet_ntoa(entry->ipaddr_ia), g_ifaces[entry->idx]) > ROUTE_CMD_LEN-1)
    {
	syslog(LOG_ERR, "ip route command too large to fit in buffer!");
    } else {
	if (system(routecmd_str) != 0)
	{ 
	    syslog(LOG_ERR, "'%s' unsuccessful, will try to remove!", routecmd_str);
	    if (debug) printf("%s failed\n", routecmd_str);
	    route_remove_LOCKED(entry);
	    success = 0;
	}
	else
	{
	    syslog(LOG_INFO, "route removed for %s via %s", inet_ntoa(entry->ipaddr_ia), g_ifaces[entry->idx]);
	    if (debug) printf("%s success\n", routecmd_str);
	    success = 1;
	}
    }
    if (success)
	entry->route_added = 1;

    return success;
}


void manage_route_entries_LOCKED(ROUTE_ENTRY **route_table_p, int in_cleanup)
{
    ROUTE_ENTRY *cur_entry=*route_table_p, *prev_entry=NULL;

    /* First loop to remove unwanted routes */
    while (cur_entry != NULL) {
	if (debug && verbose) printf("Working on route %s(%s) tstamp %u want_route %d\n", inet_ntoa(cur_entry->ipaddr_ia), g_ifaces[cur_entry->idx], (int) cur_entry->tstamp, cur_entry->want_route);

	if ( !cur_entry->want_route
	    || time(NULL) - cur_entry->tstamp > ARP_TABLE_ENTRY_TIMEOUT 
	    || in_cleanup)  {
	    
	    if (cur_entry->route_added)
		route_remove_LOCKED(cur_entry);

	    /* remove from arp list */
	    if (debug) printf("Delete arp %s(%s)\n", inet_ntoa(cur_entry->ipaddr_ia), g_ifaces[cur_entry->idx]);
		
	    if (prev_entry != NULL) {
	        prev_entry->next = cur_entry->next;
	        free(cur_entry);
	        cur_entry=prev_entry->next;
	    } else {
	        *route_table_p = cur_entry->next;
	        free(cur_entry);
        	cur_entry=*route_table_p;
            }
	} else {
    	    prev_entry = cur_entry;
	    cur_entry = cur_entry->next;
	}	
    } /* while loop */

    /* Now loop to add new routes */
    cur_entry=*route_table_p;
    while (cur_entry != NULL) {
	if (time(NULL) - cur_entry->tstamp <= ARP_TABLE_ENTRY_TIMEOUT 
		&& cur_entry->want_route
		&& !cur_entry->route_added 
		&& !in_cleanup) 
	{
	    /* add route to the kernel */
	    route_add_LOCKED(cur_entry);
	}
	cur_entry = cur_entry->next;
    } /* while loop */

}	

int add_route_LOCKED(ROUTE_ENTRY **route_table_p, const struct in_addr in, const int idx)
{
    ROUTE_ENTRY *entry;
    int added;

    entry = get_route_entry_LOCKED(route_table_p, in, idx);

    added = !entry->want_route;

    entry->want_route = 1;

    time(&entry->tstamp);

    manage_route_entries_LOCKED(route_table_p, 0);

    if (debug && (!entry->route_added || added)) {
	printf("route_table entry: '%s' Dev: '%s' route_added:%d aded:%d\n",
	        inet_ntoa(entry->ipaddr_ia),
	        g_ifaces[entry->idx], entry->route_added,
	        added);
    }

    return added;
}

void manage_route(const struct in_addr address, const int idx)
{
    int manage_routes;

    assert(idx <= g_last_iface_idx);

    if (!g_manage_routes) return;

    pthread_mutex_lock(&route_table_mutex);
    manage_routes = remove_other_routes_LOCKED(*route_table, address, idx);
    if (idx == 0) {
	manage_routes += add_route_LOCKED(route_table, address, idx);
    }
    if (manage_routes) manage_route_entries_LOCKED(route_table, 0);
    pthread_mutex_unlock(&route_table_mutex);
}

void remove_routes(int idx)
{
    int removed = 0;
    ROUTE_ENTRY *cur_entry;

    assert(idx <= g_last_iface_idx);

    pthread_mutex_lock(&route_table_mutex);

    for (cur_entry = *route_table; cur_entry != NULL; cur_entry = cur_entry->next) {
	if (cur_entry->idx == idx && cur_entry->want_route) {
	    cur_entry->want_route = 1;
	    removed++;
	}
    }
    if (removed) manage_route_entries_LOCKED(route_table, 0);

    pthread_mutex_unlock(&route_table_mutex);

    if (debug && removed)
	printf("%s, removed route entries for interface\n", g_ifaces[idx]);

}


/* ARP ping all entries in the table */

void refresharp_LOCKED(ROUTE_ENTRY *list)
{
  if (debug)
      printf("Refreshing ARP entries.\n");

  while(list != NULL) {
    arp_req(g_ifaces[list->idx], list->ipaddr_ia, 0);
    list = list->next;
  }
}

void cleanup() 
{
    int i;
    
    syslog(LOG_INFO, "Received signal; cleaning up.");

    for (i=0; i <= last_thread_idx; i++) {
	void * ret;
	pthread_kill(my_threads[i], SIGTERM);
	pthread_join(my_threads[i], &ret);
    }

    pthread_mutex_trylock(&route_table_mutex);
    manage_route_entries_LOCKED(route_table, 1);
    pthread_mutex_unlock(&route_table_mutex);

    syslog(LOG_INFO, "Terminating.");
}

void sighandler()
{
    g_perform_shutdown=1;
}

void *main_thread()
{
    time_t last_refresh;

    while (!g_perform_shutdown) {
        pthread_mutex_lock(&route_table_mutex);
        manage_route_entries_LOCKED(route_table, 0);
	pthread_mutex_unlock(&route_table_mutex);
	if (g_perform_shutdown) break;
	usleep(SLEEPTIME);
	if (g_perform_shutdown) break;
	if (time(NULL)-last_refresh > REFRESHTIME) {
	    pthread_mutex_lock(&route_table_mutex);
	    refresharp_LOCKED(*route_table);
	    pthread_mutex_unlock(&route_table_mutex);
	    time(&last_refresh);
	}
    }
    return 0;
}
    
int main (int argc, char **argv)
{
    pid_t child_pid;
    int i, help=1;
    struct sigaction handle;

    
    progname = (char *) basename(argv[0]);
    
    for (i = 1; i < argc; i++) {
	if (!strcmp(argv[i],"-d")) { 
	    debug=1;
	    help=0;
	}
	else if (!strcmp(argv[i],"-P") || !strcmp(argv[i],"--no-proxy")) {
	    g_proxy_arp = 0;
	}
	else if (!strcmp(argv[i],"-R") || !strcmp(argv[i],"--no-routes")) {
	    g_manage_routes = 0;
	}
	else if (!strcmp(argv[i],"-h") || !strcmp(argv[i],"--help")) {
	    help = 1;
	    break;
	}
	else {
	    g_last_iface_idx++;
	    g_ifaces[g_last_iface_idx]=argv[i];
	    help=0;
	}
    }

    if (help || g_last_iface_idx <= -1) {
	    printf("parprouted: proxy ARP routing daemon, version %s.\n", VERSION);
    	    printf("(C) 2007 Vladimir Ivaschenko <vi@maks.net>, GPL2 license.\n");
    	    printf("(C) 2019 Lenbrook Industries Limited.\n");
	    printf("Usage: parprouted [-d] [-P | --no-proxy] [-R | --no-routes] interface [interface]\n");
	    exit(1);
    }

    if (!debug) {
        /* fork to go into the background */
        if ((child_pid = fork()) < 0) {
            fprintf(stderr, "could not fork(): %s", strerror(errno));
            exit(1);
        } else if (child_pid > 0) {
            /* fork was ok, wait for child to exit */
            if (waitpid(child_pid, NULL, 0) != child_pid) {
                perror(progname);
                exit(1);
            }
            /* and exit myself */
            exit(0);
        }
        /* and fork again to make sure we inherit all rights from init */
        if ((child_pid = fork()) < 0) {
            perror(progname);
            exit(1);
        } else if (child_pid > 0)
            exit(0);

        /* create our own session */
        setsid();

        /* close stdin/stdout/stderr */
        close(0);
        close(1);
        close(2);

    }

    openlog(progname, LOG_PID | LOG_CONS | LOG_PERROR, LOG_DAEMON);
    syslog(LOG_INFO, "Starting");

    memset(&handle, 0, sizeof(handle));
    handle.sa_handler   = sighandler;
    handle.sa_flags     = 0; // !SA_RESTART

    sigaction(SIGINT, &handle, 0);
    sigaction(SIGTERM, &handle, 0);
    sigaction(SIGHUP, &handle, 0);

    if ((route_table = (ROUTE_ENTRY **) malloc(sizeof(ROUTE_ENTRY **))) == NULL) {
	    errstr = strerror(errno);
	    syslog(LOG_CRIT, "No memory: %s", errstr);
	    abort();
    }
    
    *route_table = NULL;

    pthread_mutex_init(&route_table_mutex, NULL);
    
    for (i=0; i <= g_last_iface_idx; i++) {
	int * idx = malloc(sizeof(idx));
	*idx = i;
	if (pthread_create(&my_threads[++last_thread_idx], NULL, arp, idx)) {
	    syslog(LOG_CRIT, "Error creating ARP thread for %s",g_ifaces[i]);
	    abort();
	}
	if (debug) printf("Created ARP thread for %s.\n",g_ifaces[i]);
    }

    main_thread();

    cleanup();

    return 0;
}
