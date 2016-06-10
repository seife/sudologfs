#include "config.h"

#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>	/* inet_ntoa */
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>	/* malloc */
#include <time.h>	/* strftime */
#include "cencode.h"
#include "params.h"

int log_open(char *hostname, struct sockaddr_in *addr)
{
	struct hostent *srv;
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		fprintf(stderr, "socket: %m\n");
		return sock;
	}
	srv = gethostbyname(hostname);
	if (!srv) {
		fprintf(stderr, "gethostbyname(%s): %m\n", hostname);
		return -1;
	}
	memset(addr, 0, sizeof(struct sockaddr_in));
	addr->sin_family = AF_INET;
	addr->sin_port = htons(514);
	memcpy(&addr->sin_addr.s_addr, srv->h_addr_list[0], srv->h_length);

	return sock;
}

int log_send(struct bb_state *bb_data, struct file_state *file_state,
	     const char *filename, const char *msg, int len)
{
	static char hn[512] = "\0";
	char buf[1024];
	int i, n, chunk;
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
		fprintf(stderr, "%s: malloc failed!\n", __func__);
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

	if (!hn[0])
		strcpy(hn, inet_ntoa(bb_data->log_addr.sin_addr));
	n = sprintf(buf, "<%d>", prio);
	n += strftime(buf + n, 1024-n, "%b %e %T ", &tm);
	strncat(buf + n, hn, 1024-n);
	n += strlen(hn);
	n += sprintf(buf + n, " %s:%08x ", filename, 0);

	chunk = 1023 - n;

	for (i = 0; i < b64len; i+= chunk) {
		sprintf(buf + n -9 , "%08x ", ++file_state->seq);
		strncpy(buf + n, b64 + i, chunk);
#if 1
		/* debugging, send length of base64 string instead of string */
		char tmp[128];
		int x = strlen(buf+n);
		sprintf(tmp, "strlen %d, n: %d, tot: %d", x, n, x+n);
		strcpy(buf + n, tmp);
#endif
#if 0
		sendto(BB_DATA->log_fd, msg, len, 0, (struct sockaddr *)addr, sizeof(struct sockaddr_in));
		if (n < 0) {
			fprintf(stderr, "Error, send() failed: %m\n");
			return 1;
		}
#endif
		fprintf(stderr, "sendto: %s\n", buf);
	}
	free(b64);

	return 0;
}
