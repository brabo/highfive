#ifndef BT_H
#define BT_H

#include "bencode.h"

#define MAXDATASIZE 1512 // max number of bytes we can get at once

#define HTTP_WAIT   0
#define HTTP_START  1
#define HTTP_RECV   2

#define MAX_TRIES   5


#define SUCCESS		0
#define DEFAULT_FAIL	-1
#define OPTS_FAIL	-2
#define PQCON_FAIL	-3


struct tracker {
	int socket;
	char *host;
	char *port;
};

struct info {
	uint8_t hinfo[20];
	int complete;
	int downloaded;
	int incomplete;
	int files;
	int cunt;
};

struct scrape_ctx {
	//uint8_t hinfo[20];
	int state;
	long long len;
	int cunt;
};


#define hf_log(level, msg, ...) _hf_log(level, msg"\n", ##__VA_ARGS__)

// tracker scrape functions
int read_scrape(struct scrape_ctx *scrape_ctx, char *buf, int len);
int process_scrape(int scrape_len);
int send_scrape_get(struct tracker *tracker);
int recv_scrape_get(struct tracker *tracker);
int scrape_tracker(struct tracker *tracker);


#endif
