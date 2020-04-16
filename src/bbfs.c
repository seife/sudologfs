/*
   sudolog File System
   Copyright (C) 2016 Stefan Seyfried, <seife@tuxbox-git.slipkontur.de>
   Updated to libfuse 3.x by Erik Inge Bolsø, <erik.inge.bolso@modirum.com>

   This file system is intended to immediately ship the contents of the
   created files to a remote syslog server via UDP syslog protocol, to
   avoid tampering of the files locally.
   It is specifically tailored to the "log_output" feature of sudo, so
   some deficiencies of this implementation (e.g. that long filenames
   do not work well...) are accepted.

   Based upon:
   Big Brother File System
   Copyright (C) 2012 Joseph J. Pfeiffer, Jr., Ph.D. <pfeiffer@cs.nmsu.edu>
   http://www.cs.nmsu.edu/~pfeiffer/fuse-tutorial/

   This program can be distributed under the terms of the GNU GPLv3.
   See the file COPYING.

   This code is derived from function prototypes found /usr/include/fuse/fuse.h
   Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>
   His code is licensed under the LGPLv2.
   A copy of that code is included in the file fuse.h

 */

#include "config.h"

#include "my_syslog.h"
#include "params.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fuse.h>
#include <libgen.h>
#include <limits.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <syslog.h>
#include <utime.h>

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_SYS_XATTR_H
#include <sys/xattr.h>
#endif

/* replace the old log_syscall() behaviour of modifying return code if it was < 0 */
#define RETURN(x) do { int __y = x;if (__y < 0) return -errno; else return __y; } while(0)

/* primitive access control option, as we need to mount with "allow other" */
#define CHECKPERM do { if (fuse_get_context()->uid) return -EACCES; } while(0)

/* helper macro to avoid "unused parameter" warnings from gcc */
#  define UNUSED(x) UNUSED_ ## x __attribute__((__unused__))

//  All the paths I see are relative to the root of the mounted
//  filesystem.  In order to get to the underlying filesystem, I need to
//  have the mountpoint.  I'll save it away early on in main(), and then
//  whenever I need a path for something I'll call this to construct
//  it.
static void bb_fullpath(char fpath[PATH_MAX], const char *path)
{
	strcpy(fpath, BB_DATA->rootdir);
	strncat(fpath, path, PATH_MAX - strlen(fpath) -1 ); // ridiculously long paths will
	// break here
}

// helper to kill suid/sgid bits where needed
static int bb_resetmodebits(const char *fpath)
{
	struct stat *statbuf;
	statbuf = (struct stat *)calloc(1, sizeof(struct stat));
	int retstat = stat(fpath, statbuf);
	if (retstat == 0 && statbuf->st_mode & (S_ISUID|S_ISGID)) {
		mode_t mode = statbuf->st_mode;
		mode &= ~S_ISUID;
		mode &= ~S_ISGID;
		free(statbuf);
		RETURN(chmod(fpath, mode));
	}
	free(statbuf);
	RETURN(0);
}

///////////////////////////////////////////////////////////
//
// Prototypes for all these functions, and the C-style comments,
// come from /usr/include/fuse.h
//
/** Get file attributes.
 *
 * Similar to stat().  The 'st_dev' and 'st_blksize' fields are
 * ignored. The 'st_ino' field is ignored except if the 'use_ino'
 * mount option is given. In that case it is passed to userspace,
 * but libfuse and the kernel will still assign a different
 * inode for internal use (called the "nodeid").
 *
 * `fi` will always be NULL if the file is not currently open, but
 * may also be NULL if the file is open.
 */
int bb_getattr(const char *path, struct stat *statbuf, struct fuse_file_info *UNUSED(fi))
{
	int retstat;
	char fpath[PATH_MAX];
	CHECKPERM;
	bb_fullpath(fpath, path);

	retstat = lstat(fpath, statbuf);

	RETURN(retstat);
}

/** Read the target of a symbolic link
 *
 * The buffer should be filled with a null terminated string.  The
 * buffer size argument includes the space for the terminating
 * null character.  If the linkname is too long to fit in the
 * buffer, it should be truncated.  The return value should be 0
 * for success.
 */
// Note the system readlink() will truncate and lose the terminating
// null.  So, the size passed to to the system readlink() must be one
// less than the size passed to bb_readlink()
// bb_readlink() code by Bernardo F Costa (thanks!)
int bb_readlink(const char *UNUSED(path), char *link, size_t size)
{
	int retstat;
	char fpath[PATH_MAX];
	CHECKPERM;

	retstat = readlink(fpath, link, size - 1);
	if (retstat >= 0) {
		link[retstat] = '\0';
		retstat = 0;
	}

	RETURN(retstat);
}

/** Create a file node
 *
 * This is called for creation of all non-directory, non-symlink
 * nodes.  If the filesystem defines a create() method, then for
 * regular files that will be called instead.
 */
int bb_mknod(const char *path, mode_t mode, dev_t dev)
{
	int retstat;
	char fpath[PATH_MAX];
	CHECKPERM;
	bb_fullpath(fpath, path);

	// On Linux this could just be 'mknod(path, mode, dev)' but this
	// tries to be be more portable by honoring the quote in the Linux
	// mknod man page stating the only portable use of mknod() is to
	// make a fifo, but saying it should never actually be used for
	// that.
	if (S_ISREG(mode)) {
		retstat = open(fpath, O_CREAT | O_EXCL | O_WRONLY, mode);
		if (retstat >= 0)
			retstat = close(retstat);
	} else
		if (S_ISFIFO(mode))
			retstat = mkfifo(fpath, mode);
		else
			retstat = mknod(fpath, mode, dev);

	RETURN(retstat);
}

/** Create a directory
 *
 * Note that the mode argument may not have the type specification
 * bits set, i.e. S_ISDIR(mode) can be false.  To obtain the
 * correct directory type bits use  mode|S_IFDIR
 * */
int bb_mkdir(const char *path, mode_t mode)
{
	char fpath[PATH_MAX];
	CHECKPERM;
	bb_fullpath(fpath, path);
	RETURN(mkdir(fpath, mode|S_IFDIR));
}

/** Remove a file */
int bb_unlink(const char *path)
{
	char fpath[PATH_MAX];
	CHECKPERM;
	bb_fullpath(fpath, path);
	RETURN(unlink(fpath));
}

/** Remove a directory */
int bb_rmdir(const char *path)
{
	char fpath[PATH_MAX];
	CHECKPERM;
	bb_fullpath(fpath, path);
	RETURN(rmdir(fpath));
}

/** Create a symbolic link */
// The parameters here are a little bit confusing, but do correspond
// to the symlink() system call.  The 'path' is where the link points,
// while the 'link' is the link itself.  So we need to leave the path
// unaltered, but insert the link into the mounted directory.
int bb_symlink(const char *path, const char *link)
{
	char flink[PATH_MAX];
	CHECKPERM;
	bb_fullpath(flink, link);
	RETURN(symlink(path, flink));
}

/** Rename a file
 *
 * *flags* may be `RENAME_EXCHANGE` or `RENAME_NOREPLACE`. If
 * RENAME_NOREPLACE is specified, the filesystem must not
 * overwrite *newname* if it exists and return an error
 * instead. If `RENAME_EXCHANGE` is specified, the filesystem
 * must atomically exchange the two files, i.e. both must
 * exist and neither may be deleted.
 */
// both path and newpath are fs-relative
int bb_rename(const char *path, const char *newpath, unsigned int flags)
{
	char fpath[PATH_MAX];
	char fnewpath[PATH_MAX];
	CHECKPERM;
	bb_fullpath(fpath, path);
	bb_fullpath(fnewpath, newpath);
	if (flags) {
#ifdef HAVE_RENAMEAT2
		return(renameat2(0, fpath, 0, fnewpath, flags));
#else
		return -EINVAL;
#endif
	}
	RETURN(rename(fpath, fnewpath));
}

/** Create a hard link to a file */
int bb_link(const char *path, const char *newpath)
{
	char fpath[PATH_MAX], fnewpath[PATH_MAX];
	CHECKPERM;
	bb_fullpath(fpath, path);
	bb_fullpath(fnewpath, newpath);
	RETURN(link(fpath, fnewpath));
}


/** Change the permission bits of a file
 *
 * `fi` will always be NULL if the file is not currenlty open, but
 * may also be NULL if the file is open.
 */
int bb_chmod(const char *path, mode_t mode, struct fuse_file_info *UNUSED(fi))
{
	char fpath[PATH_MAX];
	CHECKPERM;
	bb_fullpath(fpath, path);
	RETURN(chmod(fpath, mode));
}

/** Change the owner and group of a file
 *
 * `fi` will always be NULL if the file is not currenlty open, but
 * may also be NULL if the file is open.
 *
 * Unless FUSE_CAP_HANDLE_KILLPRIV is disabled, this method is
 * expected to reset the setuid and setgid bits.
 */
int bb_chown(const char *path, uid_t uid, gid_t gid, struct fuse_file_info *UNUSED(fi))
{
	char fpath[PATH_MAX];
	CHECKPERM;
	bb_fullpath(fpath, path);
	int reset = bb_resetmodebits(fpath);
	if (reset != 0) return(reset);
	RETURN(chown(fpath, uid, gid));
}

/** Change the size of a file
 *
 * `fi` will always be NULL if the file is not currenlty open, but
 * may also be NULL if the file is open.
 *
 * Unless FUSE_CAP_HANDLE_KILLPRIV is disabled, this method is
 * expected to reset the setuid and setgid bits.
 */
int bb_truncate(const char *path, off_t newsize, struct fuse_file_info *UNUSED(fi))
{
	char fpath[PATH_MAX];
	CHECKPERM;
	bb_fullpath(fpath, path);
	int reset = bb_resetmodebits(fpath);
	if (reset != 0) return(reset);
	RETURN(truncate(fpath, newsize));
}

/**
 * Change the access and modification times of a file with
 * nanosecond resolution
 *
 * This supersedes the old utime() interface.  New applications
 * should use this.
 *
 * `fi` will always be NULL if the file is not currenlty open, but
 * may also be NULL if the file is open.
 *
 * See the utimensat(2) man page for details.
 */
int bb_utimens(const char *path, const struct timespec tv[2], struct fuse_file_info *UNUSED(fi))
{
	char fpath[PATH_MAX];
	CHECKPERM;
	bb_fullpath(fpath, path);

	RETURN(utimensat(0, fpath, tv, 0));
}

/** Open a file
 *
 * Open flags are available in fi->flags. The following rules
 * apply.
 *
 *  - Creation (O_CREAT, O_EXCL, O_NOCTTY) flags will be
 *    filtered out / handled by the kernel.
 *
 *  - Access modes (O_RDONLY, O_WRONLY, O_RDWR, O_EXEC, O_SEARCH)
 *    should be used by the filesystem to check if the operation is
 *    permitted.  If the ``-o default_permissions`` mount option is
 *    given, this check is already done by the kernel before calling
 *    open() and may thus be omitted by the filesystem.
 *
 *  - When writeback caching is enabled, the kernel may send
 *    read requests even for files opened with O_WRONLY. The
 *    filesystem should be prepared to handle this.
 *
 *  - When writeback caching is disabled, the filesystem is
 *    expected to properly handle the O_APPEND flag and ensure
 *    that each write is appending to the end of the file.
 *
 *  - When writeback caching is enabled, the kernel will
 *    handle O_APPEND. However, unless all changes to the file
 *    come through the kernel this will not work reliably. The
 *    filesystem should thus either ignore the O_APPEND flag
 *    (and let the kernel handle it), or return an error
 *    (indicating that reliably O_APPEND is not available).
 *
 * Filesystem may store an arbitrary file handle (pointer,
 * index, etc) in fi->fh, and use this in other all other file
 * operations (read, write, flush, release, fsync).
 *
 * Filesystem may also implement stateless file I/O and not store
 * anything in fi->fh.
 *
 * There are also some flags (direct_io, keep_cache) which the
 * filesystem may set in fi, to change the way the file is opened.
 * See fuse_file_info structure in <fuse_common.h> for more details.
 *
 * If this request is answered with an error code of ENOSYS
 * and FUSE_CAP_NO_OPEN_SUPPORT is set in
 * `fuse_conn_info.capable`, this is treated as success and
 * future calls to open will also succeed without being send
 * to the filesystem process.
 *
 */
int bb_open(const char *path, struct fuse_file_info *fi)
{
	int retstat = 0;
	int fd;
	struct file_state *file_state;
	char fpath[PATH_MAX];
	CHECKPERM;
	file_state = calloc(sizeof(struct file_state), 1);
	if (!file_state)
		return -ENOMEM;

	bb_fullpath(fpath, path);

	// if the open call succeeds, my retstat is the file descriptor,
	// else it's -errno.  I'm making sure that in that case the saved
	// file descriptor is exactly -1.
	fd = open(fpath, fi->flags);
	if (fd < 0)
		retstat = -errno;

	file_state->fd = fd;
	fi->fh = (uint64_t)file_state;

	return retstat;
}

/** Read data from an open file
 *
 * Read should return exactly the number of bytes requested except
 * on EOF or error, otherwise the rest of the data will be
 * substituted with zeroes.  An exception to this is when the
 * 'direct_io' mount option is specified, in which case the return
 * value of the read system call will reflect the return value of
 * this operation.
 */
// I don't fully understand the documentation above -- it doesn't
// match the documentation for the read() system call which says it
// can return with anything up to the amount of data requested. nor
// with the fusexmp code which returns the amount of data also
// returned by read.
int bb_read(const char *UNUSED(path), char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
	int retstat = 0;
	CHECKPERM;

	retstat = pread(FILE_STATE->fd, buf, size, offset);
	RETURN(retstat);
}

/** Write data to an open file
 *
 * Write should return exactly the number of bytes requested
 * except on error.      An exception to this is when the 'direct_io'
 * mount option is specified (see read operation).
 *
 * Unless FUSE_CAP_HANDLE_KILLPRIV is disabled, this method is
 * expected to reset the setuid and setgid bits.
 */
// As  with read(), the documentation above is inconsistent with the
// documentation for the write() system call.
int bb_write(const char *path, const char *buf, size_t size, off_t offset,
		struct fuse_file_info *fi)
{
	char fpath[PATH_MAX];
	int retstat = 0;
	CHECKPERM;
	bb_fullpath(fpath, path);

	int reset = bb_resetmodebits(fpath);
	if (reset != 0) return(reset);

	retstat = pwrite(FILE_STATE->fd, buf, size, offset);
	log_send(BB_DATA, FILE_STATE, path, buf, size, offset);
	RETURN(retstat);
}

/** Get file system statistics
 *
 * The 'f_favail', 'f_fsid' and 'f_flag' fields are ignored
 */
int bb_statfs(const char *path, struct statvfs *statv)
{
	int retstat = 0;
	char fpath[PATH_MAX];
	CHECKPERM;
	bb_fullpath(fpath, path);

	// get stats for underlying filesystem
	retstat = statvfs(fpath, statv);
	RETURN(retstat);
}

/** Possibly flush cached data
 *
 * BIG NOTE: This is not equivalent to fsync().  It's not a
 * request to sync dirty data.
 *
 * Flush is called on each close() of a file descriptor, as opposed to
 * release which is called on the close of the last file descriptor for
 * a file.  Under Linux, errors returned by flush() will be passed to 
 * userspace as errors from close(), so flush() is a good place to write
 * back any cached dirty data. However, many applications ignore errors 
 * on close(), and on non-Linux systems, close() may succeed even if flush()
 * returns an error. For these reasons, filesystems should not assume
 * that errors returned by flush will ever be noticed or even
 * delivered.
 *
 * NOTE: The flush() method may be called more than once for each
 * open().  This happens if more than one file descriptor refers to an
 * open file handle, e.g. due to dup(), dup2() or fork() calls.  It is
 * not possible to determine if a flush is final, so each flush should
 * be treated equally.  Multiple write-flush sequences are relatively
 * rare, so this shouldn't be a problem.
 *
 * Filesystems shouldn't assume that flush will be called at any
 * particular point.  It may be called more times than expected, or not
 * at all.
 *
 * [close]: http://pubs.opengroup.org/onlinepubs/9699919799/functions/close.html
 */
// this is a no-op in BBFS.  It just logs the call and returns success
int bb_flush(const char *UNUSED(path), struct fuse_file_info *UNUSED(fi))
{
	// no need to get fpath on this one, since I work from fi->fh not the path
	return 0;
}

/** Release an open file
 *
 * Release is called when there are no more references to an open
 * file: all file descriptors are closed and all memory mappings
 * are unmapped.
 *
 * For every open() call there will be exactly one release() call
 * with the same flags and file handle.  It is possible to
 * have a file opened more than once, in which case only the last
 * release will mean, that no more reads/writes will happen on the
 * file.  The return value of release is ignored.
 */
int bb_release(const char *UNUSED(path), struct fuse_file_info *fi)
{
	// We need to close the file.  Had we allocated any resources
	// (buffers etc) we'd need to free them here as well.
	int ret = close(FILE_STATE->fd);
	free(FILE_STATE);
	RETURN(ret);
}

/** Synchronize file contents
 *
 * If the datasync parameter is non-zero, then only the user data
 * should be flushed, not the meta data.
 */
int bb_fsync(const char *UNUSED(path), int datasync, struct fuse_file_info *fi)
{
	// some unix-like systems (notably freebsd) don't have a datasync call
	CHECKPERM;
#ifdef HAVE_FDATASYNC
	if (datasync)
		RETURN(fdatasync(FILE_STATE->fd));
	else
#endif	
		RETURN(fsync(FILE_STATE->fd));
}

#ifdef HAVE_SYS_XATTR_H
/** Set extended attributes */
int bb_setxattr(const char *path, const char *name, const char *value, size_t size, int flags)
{
	char fpath[PATH_MAX];
	CHECKPERM;
	bb_fullpath(fpath, path);

	RETURN(lsetxattr(fpath, name, value, size, flags));
}

/** Get extended attributes */
int bb_getxattr(const char *path, const char *name, char *value, size_t size)
{
	int retstat = 0;
	char fpath[PATH_MAX];
	CHECKPERM;
	bb_fullpath(fpath, path);

	retstat = lgetxattr(fpath, name, value, size);
	RETURN(retstat);
}

/** List extended attributes */
int bb_listxattr(const char *path, char *list, size_t size)
{
	int retstat = 0;
	char fpath[PATH_MAX];
	CHECKPERM;
	bb_fullpath(fpath, path);

	retstat = llistxattr(fpath, list, size);
	RETURN(retstat);
}

/** Remove extended attributes */
int bb_removexattr(const char *path, const char *name)
{
	char fpath[PATH_MAX];
	CHECKPERM;
	bb_fullpath(fpath, path);

	RETURN(lremovexattr(fpath, name));
}
#endif

/** Open directory
 *
 * Unless the 'default_permissions' mount option is given,
 * this method should check if opendir is permitted for this
 * directory. Optionally opendir may also return an arbitrary
 * filehandle in the fuse_file_info structure, which will be
 * passed to readdir, releasedir and fsyncdir.
 */
int bb_opendir(const char *path, struct fuse_file_info *fi)
{
	DIR *dp;
	int retstat = 0;
	char fpath[PATH_MAX];
	CHECKPERM;
	bb_fullpath(fpath, path);

	// since opendir returns a pointer, takes some custom handling of
	// return status.
	dp = opendir(fpath);
	if (dp == NULL)
		retstat = -errno;

	fi->fh = (intptr_t) dp;

	return retstat;
}

/** Read directory
 *
 * The filesystem may choose between two modes of operation:
 *
 * 1) The readdir implementation ignores the offset parameter, and
 * passes zero to the filler function's offset.  The filler
 * function will not return '1' (unless an error happens), so the
 * whole directory is read in a single readdir operation.
 *
 * 2) The readdir implementation keeps track of the offsets of the
 * directory entries.  It uses the offset parameter and always
 * passes non-zero offset to the filler function.  When the buffer
 * is full (or an error happens) the filler function will return
 * '1'.
 */

int bb_readdir(const char *UNUSED(path), void *buf, fuse_fill_dir_t filler, off_t UNUSED(offset),
		struct fuse_file_info *fi, enum fuse_readdir_flags UNUSED(flags))
{
	int retstat = 0;
	DIR *dp;
	struct dirent *de;
	CHECKPERM;

	// once again, no need for fullpath -- but note that I need to cast fi->fh
	dp = (DIR *) (uintptr_t) fi->fh;

	// Every directory contains at least two entries: . and ..  If my
	// first call to the system readdir() returns NULL I've got an
	// error; near as I can tell, that's the only condition under
	// which I can get an error from readdir()
	de = readdir(dp);
	if (de == 0) {
		return -errno;
	}

	// This will copy the entire directory into the buffer.  The loop exits
	// when either the system readdir() returns NULL, or filler()
	// returns something non-zero.  The first case just means I've
	// read the whole directory; the second means the buffer is full.
	do {
		if (filler(buf, de->d_name, NULL, 0, 0) != 0) {
			return -ENOMEM;
		}
	} while ((de = readdir(dp)) != NULL);

	return retstat;
}

/** Release directory
 */
int bb_releasedir(const char *UNUSED(path), struct fuse_file_info *fi)
{
	int retstat = 0;
	closedir((DIR *) (uintptr_t) fi->fh);
	return retstat;
}

/** Synchronize directory contents
 *
 * If the datasync parameter is non-zero, then only the user data
 * should be flushed, not the meta data
 */
// when exactly is this called?  when a user calls fsync and it
// happens to be a directory? ??? >>> I need to implement this...
int bb_fsyncdir(const char *UNUSED(path), int UNUSED(datasync), struct fuse_file_info *UNUSED(fi))
{
	int retstat = 0;
	return retstat;
}


/**
 * Initialize filesystem
 *
 * The return value will passed in the `private_data` field of
 * `struct fuse_context` to all file operations, and as a
 * parameter to the destroy() method. It overrides the initial
 * value provided to fuse_main() / fuse_new().
 */
// Undocumented but extraordinarily useful fact:  the fuse_context is
// set up before this function is called, and
// fuse_get_context()->private_data returns the user_data passed to
// fuse_main().  Really seems like either it should be a third
// parameter coming in here, or else the fact should be documented
// (and this might as well return void, as it did in older versions of
// FUSE).
void *bb_init(struct fuse_conn_info *UNUSED(conn), struct fuse_config *UNUSED(cfg))
{
	return BB_DATA;
}

/**
 * Clean up filesystem
 *
 * Called on filesystem exit.
 */
void bb_destroy(void *userdata)
{
	/* clean up, free allocated stuff */
	struct bb_state *bb_data = (struct bb_state *)userdata;
	free(bb_data->rootdir);
	free(bb_data);
}

/**
 * Check file access permissions
 *
 * This will be called for the access() system call.  If the
 * 'default_permissions' mount option is given, this method is not
 * called.
 *
 * This method is not called under Linux kernel versions 2.4.x
 */
int bb_access(const char *path, int mask)
{
	int retstat = 0;
	char fpath[PATH_MAX];
	CHECKPERM;
	bb_fullpath(fpath, path);

	retstat = access(fpath, mask);
	RETURN(retstat);
}

/**
 * Create and open a file
 *
 * If the file does not exist, first create it with the specified
 * mode, and then open it.
 *
 * If this method is not implemented or under Linux kernel
 * versions earlier than 2.6.15, the mknod() and open() methods
 * will be called instead.
 */
// Not implemented.  I had a version that used creat() to create and
// open the file, which it turned out opened the file write-only.


struct fuse_operations bb_oper = {
	.getattr = bb_getattr,
	.readlink = bb_readlink,
	.mknod = bb_mknod,
	.mkdir = bb_mkdir,
	.unlink = bb_unlink,
	.rmdir = bb_rmdir,
	.symlink = bb_symlink,
	.rename = bb_rename,
	.link = bb_link,
	.chmod = bb_chmod,
	.chown = bb_chown,
	.truncate = bb_truncate,
	.open = bb_open,
	.read = bb_read,
	.write = bb_write,
	.statfs = bb_statfs,
	.flush = bb_flush,
	.release = bb_release,
	.fsync = bb_fsync,

#ifdef HAVE_SYS_XATTR_H
	.setxattr = bb_setxattr,
	.getxattr = bb_getxattr,
	.listxattr = bb_listxattr,
	.removexattr = bb_removexattr,
#endif

	.opendir = bb_opendir,
	.readdir = bb_readdir,
	.releasedir = bb_releasedir,
	.fsyncdir = bb_fsyncdir,
	.init = bb_init,
	.destroy = bb_destroy,
	.access = bb_access,
	.lock = NULL,
	.utimens = bb_utimens,
	.bmap = NULL,
	.ioctl = NULL,
	.poll = NULL,
	.write_buf = NULL,
	.read_buf = NULL,
	.flock = NULL,
	.fallocate = NULL,
	.copy_file_range = NULL,
	.lseek = NULL
};

void bb_usage()
{
	fprintf(stderr,
		"usage:  sudologfs rootDir mountPoint [options]\n"
		" (or sudologfs rootDir mountPoint loghost[:port] for backwards compat)\n"
		"\n"
		"    -o syslog=loghost[:port]	set syslog destination\n"
		"    -o hostname=hostname	set source hostname in the syslog message\n"
		);
}

static int sudologfs_opt_proc(void *bb_state, const char *arg, int key,
                          struct fuse_args *outargs)
{
	(void) outargs;
	struct bb_state *state = (struct bb_state *) bb_state;

	switch (key) {
	case FUSE_OPT_KEY_OPT:
		/* Pass through */
		return 1;

	case FUSE_OPT_KEY_NONOPT:
		// first non-option: rootdir, we'll keep that
		if (!state->rootdir) {
			state->rootdir = realpath(arg, NULL);
			if (state->rootdir) {
				return 0;
			} else {
				fprintf(stderr, "rootdir did not resolve to path");
				return -1;
			}
		}
		// second non-option: mountpoint, pass on to libfuse
		else if (!state->mountpoint) {
			state->mountpoint = strdup(arg);
			return 1;
		}
		// third non-option, only with manual non-fstab mounts: logspec, we'll keep that
		else if (!state->logspec) {
			state->logspec = strdup(arg);
			return 0;
		}

		fprintf(stderr, "sudologfs: invalid argument `%s'\n", arg);
		return -1;

	default:
		fprintf(stderr, "internal option parsing error\n");
		abort();
	}
}

#define SUDOLOGFS_OPT(t, p, v) { t, offsetof(struct bb_state, p), v }

static struct fuse_opt sudologfs_opts[] = {
	SUDOLOGFS_OPT("syslog=%s", logspec, 0),
	SUDOLOGFS_OPT("hostname=%s", hostname, 0),

	FUSE_OPT_END
};

int main(int argc, char *argv[])
{
	int fuse_stat;
	struct bb_state *bb_data;
	char *logspec;
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

	// See which version of fuse we're running
	fprintf(stderr, "Fuse library version %d.%d\n", FUSE_MAJOR_VERSION, FUSE_MINOR_VERSION);

	bb_data = calloc(1, sizeof(struct bb_state));
	if (bb_data == NULL) {
		perror("main calloc");
		abort();
	}

	if (fuse_opt_parse(&args, bb_data, sudologfs_opts, sudologfs_opt_proc) == -1)
	{
		bb_usage();
		exit(1);
	}
	fuse_opt_add_arg(&args, "-oallow_other");

	if (!(bb_data->rootdir && bb_data->mountpoint && bb_data->logspec)) {
		fprintf(stderr, "too few arguments\n");
		bb_usage();
		exit(1);
	}

	bb_data->log_fd = log_open(bb_data);
	if (bb_data->log_fd < 0) {
		fprintf(stderr, "Parsing logspec '%s' failed, this is a fatal error.\n", bb_data->logspec);
		free(bb_data->rootdir);
		free(bb_data);
		return 1;
	}

	syslog(LOG_NOTICE, "mounting %s to %s, logging to %s for hostname %s", bb_data->rootdir, bb_data->mountpoint, bb_data->logspec, bb_data->hostname);

	// turn over control to fuse
	fuse_stat = fuse_main(args.argc, args.argv, &bb_oper, bb_data);
	syslog(LOG_NOTICE, "exiting with %d", fuse_stat);
	closelog();

	return fuse_stat;
}
