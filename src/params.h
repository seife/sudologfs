/*
   Copyright (C) 2012 Joseph J. Pfeiffer, Jr., Ph.D. <pfeiffer@cs.nmsu.edu>

   This program can be distributed under the terms of the GNU GPLv3.
   See the file COPYING.

   There are a couple of symbols that need to be #defined before
#including all the headers.
*/

#ifndef _PARAMS_H_
#define _PARAMS_H_

// The FUSE API has been changed a number of times.  So, our code
// needs to define the version of the API that we assume.  As of this
// writing, the most current API version is 26
#define FUSE_USE_VERSION 26

// maintain bbfs state in here
#include <limits.h>
#include <stdio.h>
struct bb_state {
	char *rootdir;
	struct sockaddr_in log_addr;
	int log_fd;
};
#define BB_DATA ((struct bb_state *) fuse_get_context()->private_data)

struct file_state {
	int fd;
	unsigned int seq;
};
#define FILE_STATE ((struct file_state *) fi->fh)


#endif
