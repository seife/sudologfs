#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([sudologfs], [0.42], [seife@tuxbox-git.slipkontur.de])
AM_INIT_AUTOMAKE([foreign dist-bzip2 no-dist-gzip])
AC_CONFIG_SRCDIR([src/bbfs.c])
AC_CONFIG_HEADERS([src/config.h])

# Checks for programs.
AC_PROG_CC

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h limits.h stdlib.h string.h sys/stat.h sys/statvfs.h unistd.h sys/xattr.h netinet/in.h])

# Check for FUSE development environment
PKG_CHECK_MODULES(FUSE, fuse3)

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UID_T
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_CHECK_MEMBERS([struct stat.st_blksize])
AC_STRUCT_ST_BLOCKS
AC_CHECK_MEMBERS([struct stat.st_rdev])
AC_TYPE_UINT16_T
AC_TYPE_UINT64_T

# Checks for library functions.
AC_FUNC_CHOWN
AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
AC_FUNC_MALLOC
AC_CHECK_FUNCS([ftruncate mkdir mkfifo realpath renameat2 rmdir strerror])
AC_CHECK_FUNCS([utimensat],, AC_MSG_FAILURE(['utimensat(2) missing on your system']))
AC_DEFINE([_XOPEN_SOURCE], [700], [needed for pwrite/pread/lstat/utimensat])

# Not all systems that support FUSE also support fdatasync (notably freebsd)
AC_CHECK_FUNCS([fdatasync])

AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT
