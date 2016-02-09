/*
 * High Five - BitTorrent Utils - Tracker Scrape Implementation
 *
 * Author: brabo
 *
 * TODO:	further minimize globals?
 *		examine to optimize code
 *		unhardcode pg infos
 *		examine tracker response. are we allowed full scrape? handle better!!!
 *
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <brabo@cryptolab.net> wrote this file. As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.               brabo
 * ----------------------------------------------------------------------------
 */


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <getopt.h>
#include <stdarg.h>
#include <fcntl.h>
#include <signal.h>
#include <netdb.h>
#include <time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <libpq-fe.h>
#include "scrape.h"
#include "bencode.h"


/* verbosity to (en/dis)able debug outputs */
char verbose = 0;

/* scrape receive bugger */
char *bugger = NULL;

/* log file */
FILE *logs = NULL;

/* Database connection */
PGconn *conn = NULL;


/* Function: _hf_log
 * -----------------
 *  Log to a file or stdout
 *
 *  level:		'E' for error, 'I' for info, 'D' for debug (verbose)
 *  msg:		Message to log
 *
 *  Returns:		Value of fprintf, or 1 if message was ignored
 */
int _hf_log(char level, const char *msg, ...)
{
	va_list arg;
	char fmt[1024];
	time_t t = time(NULL);
	char *ts = ctime(&t);
	ts[strlen(ts)-1] = 0;

	if (level != 'D' || verbose) {
		va_start(arg, msg);
		vsnprintf(fmt, 1023, msg, arg);
		va_end(arg);

		return fprintf(logs, "%c:[%s] %s", level, ts, fmt);
	} else {
        	return 1;
	}
}


/* Function: log_close
 * -------------------
 *  Close the log file for shutdown
 */
void log_close(void)
{
	fclose(logs);
}


/* Function: hf_quit
 * -----------------
 *  Safely stop the scrape, closing database first.
 *
 *  sig:		Signal number, if called as a signal handler.
 */
void hf_quit(int sig)
{
	hf_log('I', "SCRAPE :  Shutting down due to signal %d.", sig);

	PQfinish(conn);
	log_close();

	exit(sig);
}


/* Function: print_banner
 * ----------------------
 *  Print banner to stdout.
 */
void print_banner(void)
{
	printf("\n/-----------------------------------/");
	printf("\n/                                   /");
	printf("\n/            High Five!             /");
	printf("\n/     ...scraper starting up...     /");
	printf("\n/                                   /");
	printf("\n/-----------------------------------/\n\n");
}

/* Function: print_help
 * --------------------
 *  Print help to stdout.
 *
 *  *name:		Pointer to our own name.
 */
void print_help(char *name)
{
	printf("Usage: %s -[hv] -t tracker -d dbname [-l logfile]\n"
			"  -h\tThis help\n"
			"  -v\tIncrease verbosity\n"
			"  -t\tTracker URL (http://my.tracker.com:80/)\n"
			"  -d\tPostgresql DB name\n"
			"  -l\tSpecify a log file (default stdout)\n\n",
			name);
}


/* Function: get_in_addr
 * ---------------------
 *  Gets the socket address
 *
 *  *sa:		Sockaddr struct
 *
 *  Returns:		IPv4 or IPv6 address
 */
void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}


/* Function: init_con
 * ------------------
 *  Initiate a TCP connection
 *
 *  *host:		Host to connect to
 *  *port:		Port to connect to
 *
 *  Returns:		Connection socket on success
 *			0 on fail
 */
int init_con(char *host, char *port)
{
	struct addrinfo hints, *servinfo, *p;
	int rv;
	char s[INET6_ADDRSTRLEN];
	int sockfd;

	hf_log('I', "SCRAPE :  %-15s port %s - Connecting", host, port);

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((rv = getaddrinfo(host, port, &hints, &servinfo)) != 0) {
		hf_log('E', "SCRAPE : Getaddrinfo: %s", gai_strerror(rv));
		return 0;
	}

	int status = 0;
	struct timeval tv = {0,0};
	tv.tv_sec = 5;
	tv.tv_usec = 0;
	fd_set fdset;
	FD_ZERO(&fdset);
	FD_SET(sockfd, &fdset);

	// loop through all the results and connect to the first we can
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
			hf_log('E', "SCRAPE :  Error on socket!");
 			continue;
 		}

 		if ((fcntl(sockfd, F_SETFL, O_NONBLOCK) < 0)) {
 			hf_log('E', "SCRAPE :  Error on setting socket flags.");
 		}

 		if ( (status = connect(sockfd, p->ai_addr, p->ai_addrlen)) == -1) {
 			if ( errno != EINPROGRESS ) {
 				return 0;
 			}

 		}

 		status = select(sockfd+1, NULL, &fdset, NULL, &tv);

 		if (status > 0) {
 			break;
 		}
 	}

 	if (p == NULL) {
 		hf_log('E', "SCRAPE :  %-15s port %s - Connection failure", host);
 		return 0;
 	}

 	inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),
 		s, sizeof s);

 	hf_log('I', "SCRAPE :  %-15s port %s - Connected", s, port);
 	fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL, 0) & ~O_NONBLOCK);

 	if (setsockopt (sockfd, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *)&tv, sizeof(struct timeval)) < 0) {
 		hf_log('E', "HOST %-15s :  setsockopt failed!", host);
 	}

 	if (setsockopt (sockfd, SOL_SOCKET, SO_SNDTIMEO, (struct timeval *)&tv, sizeof(struct timeval)) < 0) {
 		hf_log('E', "HOST %-15s :  setsockopt failed!", host);
 	}

	freeaddrinfo(servinfo); // all done with this structure

	return sockfd;;
}


/* Function: upsert_hash
 * ---------------------
 *  UPSERT an info hash into our pg db
 *
 *  *info:		Info object
 *
 *  Returns:		SUCCESS on success
 *			DEFAULT_FAIL on error
 */
int upsert_hash(struct info *info)
{

	int ret = DEFAULT_FAIL;
	PGresult   *res;

	int complete = htonl(info->complete);
	int downloaded = htonl(info->downloaded);
	int incomplete = htonl(info->incomplete);
	int done = htonl(0);


	char info_hash[41];

	for (int i = 0; i < 20; i++) {
		char buf[4];
		snprintf(buf, sizeof(buf), "%.2x", info->hinfo[i]);
		info_hash[i * 2] = buf[0];
		info_hash[(i * 2) + 1] = buf[1];
	}

	info_hash[40] = '\0';

	hf_log('I', "SCRAPE :  UPSERTING #%06d | %s [%03d/%03d/%03d]", info->cunt, info_hash, info->complete, info->downloaded, info->incomplete);

	const char *values[5] = {info_hash, (char *)&complete, (char *)&downloaded, (char *)&incomplete, (char *)&done};
	int lengths[5] = {strlen(info_hash), sizeof(complete), sizeof(downloaded), sizeof(incomplete), sizeof(done)};
	int binary[5] = {0, 1, 1, 1, 1};

	res = PQexecParams(conn,
			"INSERT INTO hashes (hash, complete, downloaded, incomplete, done)"
			" VALUES ($1::varchar, $2::int4, $3::int4, $4::int4, $5::int4) ON CONFLICT (hash) DO UPDATE"
			" SET complete=EXCLUDED.complete, downloaded=EXCLUDED.downloaded, incomplete=EXCLUDED.incomplete, done=EXCLUDED.done",
			5,		//number of parameters
			NULL,		//ignore the Oid field
			values,		//values to substitute $1 and $2
			lengths,	//the lengths, in bytes, of each of the parameter values
			binary,		//whether the values are binary or not
			0);		//we want the result in text format


	if (PQresultStatus(res) != PGRES_COMMAND_OK) {
		hf_log('D', "INSERT failed: %s", PQerrorMessage(conn));
		//ret = 1;
	} else {
		ret = SUCCESS;
	}

	PQclear(res);

	return ret;
}


/* Function: parse_scrape
 * ----------------------
 *  Parse the hashes out of the decoded bencode node
 *
 *  *node:		Bencode node
 *  *info:		Info object
 *
 *  Returns:		Number of info hashes on success
 *			0 on fail
 */
int parse_scrape(be_node *node, struct info *info)
{
	int ret = 0;
	size_t i;

	switch (node->type) {
		case BE_STR: {
			long long len = be_str_len(node);
			if (info->files) {

				info->cunt = 0;
				hf_log('D', "SCRAPE :  we haz length %lli!", len);
			}
			break;
		}
		case BE_DICT:
			for (i = 0; node->val.d[i].val; ++i) {
				if (info->files) {
					if (!strncmp(node->val.d[i].key, "complete", 8)) {
						be_node *node2;
						node2 = (be_node *)node->val.d[i].val;
						info->complete = node2->val.i;
						//hf_log('D', "INFO :  Complete %i", info->complete);
					} else if (!strncmp(node->val.d[i].key, "downloaded", 10)) {
						be_node *node2;
						node2 = (be_node *)node->val.d[i].val;
						info->downloaded = node2->val.i;
						//hf_log('D', "INFO :  Downloaded %i", info->downloaded);
					} else if (!strncmp(node->val.d[i].key, "incomplete", 10)) {
						be_node *node2;
						node2 = (be_node *)node->val.d[i].val;
						info->incomplete = node2->val.i;
						//hf_log('D', "INFO :  HASH %d/%d/%d", info->complete, info->downloaded, info->incomplete);

						upsert_hash(info);
						info->cunt++;
						ret++;
						//hf_log('D', "INFO :  Have full hash, next one!");// %i", node2->val.i);
					} else {
						memcpy(info->hinfo, node->val.d[i].key, 20);
						//hf_log('D', "INFO :  GOT info hash.."); //, info->incomplete);
					}
				} else if (!strncmp(node->val.d[i].key, "files", 5)) {
					hf_log('D', "SCRAPE :  We found files dict!");
					info->files = 1;
				}
				ret += parse_scrape(node->val.d[i].val, info);
			}
			break;
		default:
			break;
	}
	return ret;
}


/* Function: read_scrape
 * ---------------------
 *  Read a scrape reply from the tracker into our bugger (maybe use the cirbuf here as well?)
 *
 *  *scrape_ctx:	Scrape context object
 *  *buf:		Scrape receive buffer
 *  len:		Number of received bytes
 *
 *  Returns:		SUCCESS on success
 *			1 on send fail
 */
int read_scrape(struct scrape_ctx *scrape_ctx, char *buf, int len)
{
	while ( len > 0) {
		if ((scrape_ctx->state == HTTP_WAIT)) {
			if (!strncmp(buf, "HTTP/1.0 200 OK\r\n", 17)) {
				hf_log('D', "SCRAPE :  HTTP OK!");
			}

			scrape_ctx->state = HTTP_START;
			buf += 17;
			len -= 17;

			hf_log('D', "SCRAPE :  %d remaining bytes.", len);

			for (int i = 0; i < len; i++) {
				if (scrape_ctx->state == HTTP_RECV) {
					break;
				}

				if (!strncmp(buf, "Content-Length: ", 16)) {
					char con_len[32];
					buf += 16;
					i += 16;
					len -= 16;
					int j = 0;
					while (strncmp(buf, "\r\n", 2)) {
						con_len[j++] = (uint8_t)*buf++;
					}
					buf;
					len -= j;
					i += j;
					scrape_ctx->len = strtol(con_len, NULL, 0);
					hf_log('D', "SCRAPE :  Content-Length :  %d.", scrape_ctx->len);
					bugger = malloc(sizeof(char) * scrape_ctx->len);
				} else if (!strncmp(buf, "\r\n\r\n", 4)) {
					buf += 4;
					len -= 4;
					i += 4;
					scrape_ctx->state = HTTP_RECV;
				} else {
					//fallback, we up the pointer
					buf++;
					len--;
				}
			}
			continue;
		}

		if (scrape_ctx->state == HTTP_RECV) {
			memcpy(bugger, buf, len);
			bugger += len;
			scrape_ctx->cunt += len;
			printf("\rgot %d bytes out of %ld bytes so far..", scrape_ctx->cunt, scrape_ctx->len);
			len = 0;

			if (scrape_ctx->cunt == scrape_ctx->len) {
				bugger -= scrape_ctx->len;
				printf("\n\n----LOGFILE----\n\n");
				hf_log('D', "SCRAPE :  Wrote data to file test01");
				return SUCCESS;
			}
			continue;
		}
	}

	return 254; // should never be reached!
}


/* Function: process_scrape
 * ------------------------
 *  Process the scrape bugger
 *
 *  scrape_len:		Bugger length
 *
 *  Returns:		SUCCESS on success
 *			DEFAULT_FAIL on send fail
 */
int process_scrape(int scrape_len)
{
	int ret = DEFAULT_FAIL;

	struct info *info = malloc(sizeof(struct info));

	hf_log('D', "SCRAPE :  We have data msg len %d", scrape_len);

	be_node *node;
	long long *max = malloc(sizeof(long long));
	*max = scrape_len + 10;

	node = _be_decode((const char **)&bugger, max);

	//if (verbose) {
	//	be_dump(node);
	//}
	info->files = 0;

	ret = parse_scrape(node, info);

	free(info);

	return ret;

}


/* Function: send_scrape_get
 * -------------------------
 *  Send a scrape GET to the tracker
 *
 *  *tracker:		Tracker object
 *
 *  Returns:		SUCCESS on success
 *			DEFAULT_FAIL on send fail
 */
int send_scrape_get(struct tracker *tracker)
{
	char *buf = "GET /scrape HTTP/1.0\r\n\r\n";

	hf_log('I', "SCRAPE :  Initiating scrape..");

	if (send(tracker->socket, buf, strlen(buf), 0) == -1) {
		hf_log('E', "SCRAPE :  Sending scrape GET failed!");
		return DEFAULT_FAIL;
	}

	return SUCCESS;
}


/* Function: recv_scrape_get
 * -------------------------
 *  Receive a scrape GET from the tracker
 *
 *  *tracker:		Tracker object
 *
 *  Returns:		Number of info hashes on success
 *			0 on receive fail
 *			DEFAULT_FAIL in some very weird situation
 *
 *  TODO:		More sturdy recv logic pls, maybe also a timeout, and proper number of retries?
 */
int recv_scrape_get(struct tracker *tracker)
{
	char *buf = malloc(MAXDATASIZE);
	int ret = DEFAULT_FAIL;
	int numbytes = 0;

	struct scrape_ctx *scrape_ctx = malloc(sizeof(struct scrape_ctx));
	scrape_ctx->state = HTTP_WAIT;
	scrape_ctx->len = 0;
	scrape_ctx->cunt = 0;

	while (1) {
		if ((numbytes = recv(tracker->socket, buf, MAXDATASIZE-1, 0)) == DEFAULT_FAIL) {
			hf_log('E', "SCRAPE :  Receiving scrape GET failed!");
			return SUCCESS;
		}

		buf[numbytes] = '\0';

		if (numbytes > 0) {
			if (!read_scrape(scrape_ctx, buf, numbytes)) {
				ret = process_scrape(scrape_ctx->len);
				break;
			}
		}
	}

	free(buf);

	return ret;
}


/* Function: parse_opts
 * --------------------
 *  Parse the CLI arguments into our tracker object
 *
 *  argc:		Number of arguments
 *  *argv[]		Arguments
 *  *tracker:		Tracker object
 *
 *  Returns:		SUCCESS on success
 *
 */
int parse_opts(int argc, char *argv[], struct tracker *tracker, char *dbname)
{
	char c;
	char *url = NULL;
	char *db = NULL;

	while ((c = getopt (argc, argv, "hvt:l:d:")) != -1) {
		switch (c) {
			case 'h':
				print_help(argv[0]);
				return OPTS_FAIL;
			case 'v':
				verbose = 1;

				break;
			case 't':
				url = malloc(sizeof(char)*(strlen(optarg) + 1));
				memcpy(url, optarg, strlen(optarg));

				break;
			case 'd':
				db = malloc(sizeof(char)*(strlen(optarg) + 1));
				memcpy(db, optarg, strlen(optarg));

				break;
			case 'l':
				logs = fopen(optarg, "a");

				if (!logs) {
					perror(optarg);
					return OPTS_FAIL;
				}
				setbuf(logs, NULL);

				break;
			case '?':
				fprintf(stderr,
					"Unknown option: %c\n",
					optopt);

				return OPTS_FAIL;
			default:
				abort();
		}
	}

	if (!url) {
		printf("Error : No Tracker given!\n");
		return OPTS_FAIL;
	}

	if (!db) {
		printf("Error : No DB name given!\n");
		return OPTS_FAIL;
	}

	memcpy(dbname, db, strlen(db));
	free(db);

	char *ptr = url;
	tracker->host = malloc(sizeof(char)*(strlen(url)));

	if (!strncmp(url, "http://", 7)) {
		url += 7;

		int i = 0;

		while (*url != ':') {
			tracker->host[i] = (char)*url++;
			i++;
		}

		url++;
		tracker->host[i] = 0x00;
		tracker->port = malloc(sizeof(char)*(strlen(url)));
		i = 0;

		while (*url != '/') {
			tracker->port[i] = (char)*url++;
			i++;
		}

		tracker->port[i] = 0x00;
	}

	if (!strncmp(url, "https://", 8)) {
		printf("HAZ HTTPS URL!\n");
	}

	free(ptr);

	return 0;
}


/* Function: scrape_tracker
 * ------------------------
 *  Scrape a tracker
 *
 *  *tracker:		Tracker object
 *
 *  Returns:		Number of info hashes on success
 *			DEFAULT_FAIL on fail
 */
int scrape_tracker(struct tracker *tracker)
{
	tracker->socket = init_con(tracker->host, tracker->port);

	send_scrape_get(tracker);
	int ret = DEFAULT_FAIL;

	while (1) {
		hf_log('D', "SCRAPE :  Trying to receive scrape GET reply");

		if ((ret = recv_scrape_get(tracker)) != DEFAULT_FAIL) {
			break;
		}
	}

	close(tracker->socket);

	return ret;
}


/* Function: main
 * --------------
 *  Mysery function
 *
 *  argc:		Number of arguments
 *  *argv[]		Arguments
 *
 *  Exits:		0 on success
 *
 */
int main(int argc, char *argv[])
{
	print_banner();
	// setup proper exit shit
	signal(SIGINT, hf_quit);
	signal(SIGTERM, hf_quit);

	struct tracker *tracker = malloc(sizeof(struct tracker));
	char *dbname = malloc(sizeof(char) * 64);
	int info_cunt =0;

	logs = stdout;
	verbose = 0;

	if(parse_opts(argc, argv, tracker, dbname)) {
		exit(OPTS_FAIL);
	}

	char *conninfo = malloc((sizeof(char) * strlen(dbname)) + 24);
	sprintf(conninfo, "dbname=%s sslmode=disable", dbname);
	conn = PQconnectdb(conninfo);

	if (PQstatus(conn) != CONNECTION_OK) {
		hf_log('E', "Connection to database failed: %s", PQerrorMessage(conn));
		PQfinish(conn);
		log_close();
		exit(PQCON_FAIL);
	}

	while (1) {
		info_cunt = scrape_tracker(tracker);

		if (info_cunt) {
			hf_log('I', "SCRAPE :  Upserted %d info hashes into our db!", info_cunt);
			break;
		}
	}

	PQfinish(conn);
	log_close();
	free(dbname);

	// if you're happy and you know it,
	exit(SUCCESS);
}


