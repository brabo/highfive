/*
 * Simple server, listen, process commands
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/types.h>
#include <netdb.h>
#include <signal.h>
#include <stdarg.h>
#include <time.h>
#include "five0.h"

/* Array of client data where fd-3 is the index */
cdata clients[MAXEVENTS];

/* verbosity to (en/dis)able debug outputs */
char verbose = 0;

/* log file */
FILE *logs = NULL;


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


/* Function: server_quit
 * ---------------------
 *  Safely stop the server, closing database first.
 *
 *  sig:		Signal number, if called as a signal handler.
 */
void five0_quit(int sig)
{
	hf_log('I', "FIVE0 :  Shutting down due to signal %d.", sig);

	//PQfinish(conn);
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
	printf("\n/              Five0!               /");
	printf("\n/   ...epoll server starting up...  /");
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
			"  -i\tListen IP\n"
			"  -p\tListen port\n",
			name);
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
int parse_opts(int argc, char *argv[], struct server *server)
{
	char c;

	while ((c = getopt (argc, argv, "hvi:p:")) != -1) {
		switch (c) {
			case 'h':
				print_help(argv[0]);
				return OPTS_FAIL;
			case 'v':
				verbose = 1;

				break;
			case 'i':
				server->ip = malloc(sizeof(char) * (strlen(optarg) + 1));
				memcpy(server->ip, optarg, strlen(optarg));
				break;

			case 'p':
				server->port = malloc(sizeof(char) * (strlen(optarg) + 1));
				memcpy(server->port, optarg, strlen(optarg));
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

	if (!server->ip) {
		printf("Error : No Listen IP given!\n");
		return OPTS_FAIL;
	}


	if (!server->port) {
		printf("Error : No Port given!\n");
		return OPTS_FAIL;
	}

	return 0;
}


/* Function: socket_non_blocking
 * -----------------------------
 *  Make our listen socket non-blocking.
 *
 *  sfd:		Listen socket FD.
 *
 *  Returns:		0 on success.
 *			-1 on fail.
 */
int socket_non_blocking(int sfd)
{
	int flags, s;

	flags = fcntl (sfd, F_GETFL, 0);
	if (flags == -1) {
		hf_log('E', "FIVE0 :  Error on fcntl!");
		return -1;
	}

	flags |= O_NONBLOCK;
	s = fcntl (sfd, F_SETFL, flags);
	if (s == -1) {
		hf_log('E', "FIVE0 :  Error on fcntl!");
		return -1;
	}

	return 0;
}


/* Function: socket_setup
 * ----------------------
 *  Setup the socket. Bind and listen.
 *
 *  addr:		Listen address.
 *
 *  Returns:		sfd on success.
 *
 *  Exits:		EXIT_FAILURE on fail.
 */
int socket_setup(char *ip, char *port)
{
	struct addrinfo hints, *res;

	int sfd;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;		// IPv4
	hints.ai_socktype = SOCK_STREAM;	// TCP
	hints.ai_flags = AI_PASSIVE;

	getaddrinfo(ip, port, &hints, &res);

	sfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (sfd == -1) {
		hf_log('E', "FIVE0 :  Unable to create socket: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (bind(sfd, res->ai_addr, res->ai_addrlen) < 0) {
		hf_log('E', "FIVE0 :  Bind failed: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}

	hf_log('I', "FIVE0 :  Listening on %s:%s", ip, port);

	if (socket_non_blocking(sfd)) {
		exit(EXIT_FAILURE);
	}

	if (listen(sfd, SOMAXCONN) == -1) {
		hf_log('E', "FIVE0 :  Error on listen: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}

	return sfd;
}


/* Function: net_init
 * ------------------
 *  Initializes network
 *
 *  sfd:		Socket FD.
 *  addr:		Listen address.
 *
 *  Returns:		sfd on success.
 *
 *  Exits:		2 on socket_non_blocking fail.
 */
int net_init(struct server *server)
{
	int ret;

	server->socket = socket_setup(server->ip, server->port);

	ret = socket_non_blocking(server->socket);
	if (ret == -1) {
		exit(2);
	}

	return 0;
}


/* Function: epoll_init
 * --------------------
 *  Initializes epoll.
 *
 *  *server:		Server object.
 *  *event:		Epoll event object.
 *
 *  Returns:		Epoll FD on success.
 *
 *  Exits:		3 on epoll_create error.
 *			4 on epoll_ctl error.
 */
int epoll_init(struct server *server, struct epoll_event *event)
{
	int ret;

	server->epoll = epoll_create1(0);
	if (server->epoll == -1) {
		hf_log('E', "FIVE0 :  Error on epoll_create!");
		exit(3);
	}

	event->data.fd = server->socket;
	event->events = EPOLLIN | EPOLLET;

	ret = epoll_ctl(server->epoll, EPOLL_CTL_ADD, server->socket, event);
	if (ret == -1) {
		hf_log('E', "FIVE0 :  Error on epoll_ctl!");
		exit(4);
	}

	return 0;
}


/* Function: epoll_read
 * --------------------
 *  Reads from epoll.
 *
 *  *server:		Server object.
 *  *event:		Epoll event object.
 *
 *  Returns:		0 on success.
 *
 */
int epoll_read(struct server *server, struct epoll_event *event)
{
	int client_sock;

	int c = sizeof(struct sockaddr_in);
	struct sockaddr_in client;
	char client_addr[46];


	while (1) {

		client_sock = accept(server->socket, (struct sockaddr *)&client, (socklen_t *)&c);

		if (client_sock == -1) {
			if (errno != EAGAIN && errno != EWOULDBLOCK) {
				hf_log('E', "FIVE0 :  Accept error: %s", strerror(errno));
			}
			break;
		}

		inet_ntop(AF_INET, &(client.sin_addr), client_addr, 45);
		hf_log('I', "FIVE0 :  Connection accepted from %s -> fd:%d", client_addr, client_sock);

		socket_non_blocking(client_sock);

		event->data.fd = client_sock;
		event->events = EPOLLIN | EPOLLET;
		epoll_ctl(server->epoll, EPOLL_CTL_ADD, client_sock, event);

		strncat(clients[client_sock-3].ip, client_addr, 45);
		clients[client_sock-3].version = 0;
	}

	return 0;
}


/* Function: net_read
 * ------------------
 *  Reads from network ring buffer.
 *
 *  *bugger:		Receive bugger.
 *  *events:		Epoll events object.
 *
 *  Returns:		Receive count on success.
 *
 */
int net_read(struct epoll_event *events, uint8_t *bugger, int i)
{
	/* We have some data to read */
	int done = 0;
	char bug[1500];

	int count = read(events[i].data.fd, bugger, MAX_TCP_SIZE);

	if (count == -1) {
		if (errno != EAGAIN) {
			done = 1;
		}
		return 2;
	} else if (count == 0) {
		/* Connection closed */
		done = 1;
		hf_log('I', "FIVE0 :  Client %s|%d disconnected", clients[events[i].data.fd-3].ip, events[i].data.fd);
		return 1;;
	}


	int j;
	for (j = 0; j < count; j++) {
		char bugs[3];
		sprintf(bugs, "%02X", *bugger++);
		bug[j * 2] = bugs[0];
		bug[(j * 2) + 1] = bugs[1];
	}
	bug[j * 2] = '\0';

	char *ptr = bug;

	hf_log('I', "FIVE0 :  READ %d bytes | [%s]", count, ptr);

	if (done) {
		hf_log('I', "FIVE0 :  Closing fd %d", events[i].data.fd);
		memset(&(clients[events[i].data.fd-3]), 0, sizeof(cdata));
		close(events[i].data.fd);
	}

	return 0;
}


/* Function: check_listen
 * ----------------------
 *  Check epoll for our listening port.
 *
 *  *server:		Server object.
 *  *event:		Epoll event object.
 *  *events:		Epoll events object.
 *
 *  Returns:		0 on success.
 *
 */
int check_listen(struct server *server, struct epoll_event *event, struct epoll_event *events)
{
	//uint8_t buf[MAX_TCP_SIZE] = {0};
	uint8_t *bugger = malloc(sizeof(uint8_t) * (MAX_TCP_SIZE) + 1);

	int n, i;

	n = epoll_wait(server->epoll, events, MAXEVENTS, -1);
	for (i = 0; i < n; i++) {
		if ((events[i].events & EPOLLERR) ||
				(events[i].events & EPOLLHUP) ||
				(!(events[i].events & EPOLLIN))) {

			/* An error has occured on this fd, or the socket is not
			 ready for reading (why were we notified then?) */
			hf_log('E', "FIVE0 :  Epoll error");
			close(events[i].data.fd);

			continue;
		} else if (server->socket == events[i].data.fd) {
			/* We have a notification on the listening socket, which
				 means one or more incoming connections. */

			epoll_read(server, event);
			continue;
		} else {
			net_read(events, bugger, i);
			// handle read bugger!
		}
	}

	free(bugger);

	return 0;
}


/* Function: main
 * --------------
 *  Main function. Parses arguments. Initializes server. Event loop.
 *
 *  argc:		Argument count.
 *  **argv:		Arguments.
 *
 *  Returns:		0 on success.
 */
int main(int argc, char **argv)
{
	signal(SIGINT, five0_quit);
	signal(SIGTERM, five0_quit);
	struct server *server = malloc(sizeof(struct server));

	logs = stdout;

	verbose = 0;

	if(parse_opts(argc, argv, server)) {
		exit(OPTS_FAIL);
	}

	struct epoll_event event;
	struct epoll_event *events;
	events = calloc(MAXEVENTS, sizeof(struct epoll_event));

	net_init(server);
	epoll_init(server, &event);

	/* The event loop */
	while (1) {
		check_listen(server, &event, events);
	}

	close(server->socket);

	free(events);
	free(server->port);
	free(server->ip);
	free(server);

	// if you're happy and you know it,
	exit(0);
}




/*   PSEUDE CODE for later use!
int waiting(int socket)
{
	//int ret = 0;
	uint32_t len = 0;
	recv(socket, &len, 4, msg_peek);
	return len;
}


int read_blob(int socket, char *bugger, uint32_t amount)
{
	int off = 0;
	int ret = 0;
	while (off < amount) {
		if ((ret = recv(socket, bugger, amount, NULL)) != -1) {
			off += ret;
			bugger += ret;
		}
	}
	return amount;
}
*/
