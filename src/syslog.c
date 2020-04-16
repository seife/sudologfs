#include "config.h"

#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include <stdlib.h>	/* malloc */
#include <limits.h>
#include <time.h>	/* strftime */
#include <inttypes.h>	/* PRIx64 */
#include "cencode.h"
#include "params.h"

/* configurable stuff here */
/*
 * syslog RFC says, that 1024 is the maximum size of a log message.
 * UDP transport probably prohibits anything beyond MTU (1500) anyway
 */
#define LOG_PACKET_LENGTH 1024
/*
 *the minimum "payload size" we want in the syslog packet, after the
 * header, filename, ...
 */
#define MIN_BUF_SPACE 128

static uint16_t strtouint16(const char* nptr, char** endptr, int base)
{
	errno = 0;
	long val = strtol(nptr, endptr, 10);
	if (endptr && **endptr != '\0') {
		/* garbage in the string */
		errno = EINVAL;
		return 0;
	}
	if (errno || (endptr && *endptr == nptr)) {
		return 0;
	}
	if (val < 0 || val > UINT16_MAX) {
		errno = ERANGE;
		return 0;
	}
	return (uint16_t)val;
}

int log_open(struct bb_state *bb_data)
{
	int sock;
	int gai;
	uint16_t port = 514;
	char *portstr;
	char *endptr;
	char *logspec = strdup(bb_data->logspec);
	struct sockaddr *addr = (struct sockaddr *) &bb_data->log_addr;
	struct addrinfo *result;
	struct addrinfo hints;

	hints.ai_flags = 0;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	hints.ai_addrlen = 0;
	hints.ai_canonname = NULL;
	hints.ai_addr = NULL;
	hints.ai_next = NULL;

	portstr = strrchr(logspec, ':');
	if (portstr) {
		*portstr = '\0';
		portstr = portstr+1;
		port = strtouint16(portstr, &endptr, 10);
		if (errno) {
			fprintf(stderr, "invalid port number: ");
			perror(NULL);
			syslog(LOG_ERR, "invalid port number: %m");
			return -1;
		}
	} else {
	    portstr = strdup("514");
	}

	gai = getaddrinfo(logspec, portstr, &hints, &result);
	if (gai != 0) {
		syslog(LOG_ERR, "getaddrinfo(%s): %s", logspec, gai_strerror(gai));
		return -1;
	}

	openlog(NULL, LOG_PERROR|LOG_PID, LOG_DAEMON);
	// XXX assume only one result from getaddrinfo
	sock = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
	if (sock < 0) {
		syslog(LOG_ERR, "socket: %m");
		free(logspec);
		return sock;
	}

	memcpy(addr, result->ai_addr, result->ai_addrlen);
	bb_data->la_sa_len = result->ai_addrlen;
	freeaddrinfo(result);

	if (!bb_data->hostname) {
		static char hn[512] = "\0";

		int ret = gethostname(hn, 512);
		if (ret < 0) {
			syslog(LOG_ERR, "gethostname() failed, set hostname manually with hostname= mount option\n");
			free(logspec);
			return -1;
		}
		bb_data->hostname = hn;
	}

	free(logspec);
	return sock;
}

int log_send(struct bb_state *bb_data, struct file_state *file_state,
	     const char *filename, const char *msg, int len, off_t offset)
{
	char buf[LOG_PACKET_LENGTH];
	char off[64];
	int i, l, m, n, chunk, ret;
	int prio = 13 * 8 + 5; /* log_audit.log_notice, 109 */
	/* timestamp stuff */
	struct tm tm;
	time_t now;

	/* base64 encoder stuff*/
	base64_encodestate s;
	int b64len;
	char *b64 = (char *)malloc(len*4/3+8);
	char *c = b64;
	if (!b64) {
		syslog(LOG_ERR, "%s: malloc failed!", __func__);
		return -1;
	}

	now = time(NULL);
	gmtime_r(&now, &tm);

	base64_init_encodestate(&s);
	n = base64_encode_block(msg, len, c, &s);
	c += n;
	b64len = n;
	n = base64_encode_blockend(c, &s);
	c += n;
	*c = '\0';
	b64len += n;
	// fprintf(stderr, "b64: '%s'\n", b64);

	n = sprintf(buf, "<%d>", prio);
	n += strftime(buf + n, LOG_PACKET_LENGTH - n, "%b %e %T ", &tm);
	strncat(buf + n, bb_data->hostname, LOG_PACKET_LENGTH - n);
	n += strlen(bb_data->hostname);
	m = snprintf(buf + n, LOG_PACKET_LENGTH - n, " %s:%08x ", filename, 0);
	if (m >= LOG_PACKET_LENGTH - n) {
		syslog(LOG_ERR, "filename too long, not sending log message");
		syslog(LOG_ERR, "%s", filename);
		free(b64);
		return -1;
	}
	n += m;

	/* "size@offset " */
	l = sprintf(off, "%x@%" PRIx64 " ", len, offset);

	chunk = LOG_PACKET_LENGTH - 1 - n;
	if (chunk < MIN_BUF_SPACE) {
		/* we assume that MIN_BUF_SPACE is much bigger than l (strlen "size@offset")
		 * here, so no extra check for l is made */
		syslog(LOG_ERR, "not enough space in packet (%d), not sending log message", chunk);
		syslog(LOG_ERR, "%s", filename);
		free(b64);
		return -1;
	}

	for (i = 0; i < b64len; /*i+= chunk*/) {
		sprintf(buf + n -9 , "%08x ", ++file_state->seq);
		/* first packet of this log message: add "size@offset " prefix */
		if (l)
			strcpy(buf + n, off);
		/* strncpy stops at end of b64 string, so it does not matter that chunk may point beyound b64 array */
		strncpy(buf + n + l, b64 + i, chunk - l);
#if 0
		/* debugging, send length of base64 string instead of string */
		char tmp[128];
		int x = strlen(buf+n);
		sprintf(tmp, "strlen %d, n: %d, tot: %d", x, n, x+n);
		strcpy(buf + n, tmp);
#else
		m = b64len - i + n + l;
		if (m > LOG_PACKET_LENGTH)
			m = LOG_PACKET_LENGTH;
		ret = sendto(bb_data->log_fd, buf, m, 0, (struct sockaddr *)&(bb_data->log_addr), bb_data->la_sa_len);
		if (ret < 0) {
			syslog(LOG_ERR, "Error, send() failed: %m");
			//return 1;
		}
#endif
		i += chunk - l;
		l = 0; /* reset after first packet is sent */
		fprintf(stderr, "sendto: %s\n", buf);
	}
	free(b64);

	return 0;
}
