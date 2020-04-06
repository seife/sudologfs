#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include "params.h"

int log_open(struct bb_state *bb_data);
int log_send(struct bb_state *bb_data, struct file_state *file_state,
	     const char *filename, const char *msg, int len, off_t offset);
