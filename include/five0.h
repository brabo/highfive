#ifndef FIVE0_H
#define FIVE0_H








#define MAXEVENTS 256

#define SUCCESS		0
#define DEFAULT_FAIL	-1
#define OPTS_FAIL	-2
#define TIMEOUT_FAIL	-5

#define MAX_TCP_SIZE 		1500

struct server {
	int socket;
	int epoll;
	char *ip;
	char *port;
};

typedef struct cdata {
	char receiving;		/* currently receiving results */
	uint8_t active[3];	/* active subnet */
	uint8_t version;	/* client version number */
	uint8_t *data;		/* result buffer */
	int datalen;		/* size of data buffer */
	char ip[46];		/* client IP string */
} cdata;

struct bt_shake         // bt basic handshake
{
	uint8_t pstrlen;    // length of the BitTorrent protocol string
	char pstr[19];      // BitTorrent protocol string
	uint8_t reserved[8];    // reserved bytes
	char info_hash[20]; // info hash
	char peer_id[20];   // peer ID
};

extern int _hf_log(char level, const char *msg, ...);
#define hf_log(level, msg, ...) _hf_log(level, msg"\n", ##__VA_ARGS__)
extern void log_close(void);



#endif
