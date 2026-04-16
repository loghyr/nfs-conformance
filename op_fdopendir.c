/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_fdopendir.c -- exercise fdopendir(3) on NFS directory fds
 * (POSIX.1-2008).
 *
 * fdopendir pairs with openat to provide safe, race-free directory
 * traversal: openat(dirfd, name, O_DIRECTORY) obtains a handle to
 * the child directory, then fdopendir converts it to a DIR* for
 * readdir iteration.  On NFS, this exercises the READDIR compound
 * relative to a specific filehandle rather than a path.
 *
 * Cases:
 *
 *   1. Basic fdopendir + readdir.  Create a directory with 3 known
 *      files, openat it, fdopendir, iterate with readdir, verify
 *      all 3 names appear (plus "." and "..").
 *
 *   2. fdopendir on nested directory.  Create a/b/c, open "a" as
 *      dirfd, openat(dirfd, "b/c"), fdopendir the result.  Verify
 *      readdir returns "." and ".." for the empty leaf.
 *
 *   3. fdopendir after rename.  Open a directory fd, rename the
 *      directory, fdopendir the old fd, readdir.  The fd should
 *      still work (it references the inode, not the name).
 *
 *   4. closedir closes the fd.  After closedir(dp), the underlying
 *      fd must be invalid.  Verify fstat returns EBADF.
 *
 *   5. fdopendir on non-directory fd.  Open a regular file,
 *      fdopendir must return NULL with ENOTDIR.
 *
 * Portable: POSIX.1-2008 across Linux / FreeBSD / macOS / Solaris.
 */

#define _GNU_SOURCE
#define _DARWIN_C_SOURCE

#include "tests.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

int Hflag = 0;
int Sflag = 0;
int Tflag = 0;
int Fflag = 0;
int Nflag = 0;

static const char *myname = "op_fdopendir";

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  exercise fdopendir(3) on NFS directory fds "
		"(POSIX.1-2008)\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

static void touch(int dirfd, const char *name)
{
	int fd = openat(dirfd, name, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd >= 0) close(fd);
}

static void case_basic(void)
{
	char sub[64];
	snprintf(sub, sizeof(sub), "t_fdo.b.%ld", (long)getpid());
	rmdir(sub);
	mkdir(sub, 0755);

	int dirfd = open(sub, O_RDONLY | O_DIRECTORY);
	if (dirfd < 0) {
		complain("case1: open dir: %s", strerror(errno));
		rmdir(sub);
		return;
	}

	touch(dirfd, "alpha");
	touch(dirfd, "beta");
	touch(dirfd, "gamma");

	/* Re-open because fdopendir consumes the fd. */
	int dirfd2 = open(sub, O_RDONLY | O_DIRECTORY);
	if (dirfd2 < 0) {
		complain("case1: reopen dir: %s", strerror(errno));
		unlinkat(dirfd, "alpha", 0);
		unlinkat(dirfd, "beta", 0);
		unlinkat(dirfd, "gamma", 0);
		close(dirfd);
		rmdir(sub);
		return;
	}

	DIR *dp = fdopendir(dirfd2);
	if (!dp) {
		complain("case1: fdopendir: %s", strerror(errno));
		close(dirfd2);
		goto out;
	}

	int found_alpha = 0, found_beta = 0, found_gamma = 0;
	struct dirent *de;
	while ((de = readdir(dp)) != NULL) {
		if (strcmp(de->d_name, "alpha") == 0) found_alpha = 1;
		else if (strcmp(de->d_name, "beta") == 0) found_beta = 1;
		else if (strcmp(de->d_name, "gamma") == 0) found_gamma = 1;
	}
	closedir(dp);

	if (!found_alpha) complain("case1: 'alpha' not found in readdir");
	if (!found_beta)  complain("case1: 'beta' not found in readdir");
	if (!found_gamma) complain("case1: 'gamma' not found in readdir");

out:
	unlinkat(dirfd, "alpha", 0);
	unlinkat(dirfd, "beta", 0);
	unlinkat(dirfd, "gamma", 0);
	close(dirfd);
	rmdir(sub);
}

static void case_nested(void)
{
	char a[64], ab[128], abc[192];
	snprintf(a, sizeof(a), "t_fdo.n.%ld", (long)getpid());
	snprintf(ab, sizeof(ab), "%s/b", a);
	snprintf(abc, sizeof(abc), "%s/c", ab);

	rmdir(abc); rmdir(ab); rmdir(a);
	mkdir(a, 0755); mkdir(ab, 0755); mkdir(abc, 0755);

	int dirfd_a = open(a, O_RDONLY | O_DIRECTORY);
	if (dirfd_a < 0) {
		complain("case2: open a: %s", strerror(errno));
		rmdir(abc); rmdir(ab); rmdir(a);
		return;
	}

	int dirfd_c = openat(dirfd_a, "b/c", O_RDONLY | O_DIRECTORY);
	if (dirfd_c < 0) {
		complain("case2: openat(a, b/c): %s", strerror(errno));
		close(dirfd_a);
		rmdir(abc); rmdir(ab); rmdir(a);
		return;
	}

	DIR *dp = fdopendir(dirfd_c);
	if (!dp) {
		complain("case2: fdopendir: %s", strerror(errno));
		close(dirfd_c);
		close(dirfd_a);
		rmdir(abc); rmdir(ab); rmdir(a);
		return;
	}

	int found_dot = 0, found_dotdot = 0, count = 0;
	struct dirent *de;
	while ((de = readdir(dp)) != NULL) {
		if (strcmp(de->d_name, ".") == 0) found_dot = 1;
		else if (strcmp(de->d_name, "..") == 0) found_dotdot = 1;
		count++;
	}
	closedir(dp);

	if (!found_dot) complain("case2: '.' not found in empty leaf dir");
	if (!found_dotdot) complain("case2: '..' not found in empty leaf dir");
	if (count != 2)
		complain("case2: expected 2 entries (./..); got %d", count);

	close(dirfd_a);
	rmdir(abc); rmdir(ab); rmdir(a);
}

static void case_after_rename(void)
{
	char old[64], new_name[64];
	snprintf(old, sizeof(old), "t_fdo.ro.%ld", (long)getpid());
	snprintf(new_name, sizeof(new_name), "t_fdo.rn.%ld", (long)getpid());
	rmdir(old); rmdir(new_name);
	mkdir(old, 0755);

	int dirfd = open(old, O_RDONLY | O_DIRECTORY);
	if (dirfd < 0) {
		complain("case3: open: %s", strerror(errno));
		rmdir(old);
		return;
	}

	touch(dirfd, "sentinel");

	if (rename(old, new_name) != 0) {
		complain("case3: rename: %s", strerror(errno));
		unlinkat(dirfd, "sentinel", 0);
		close(dirfd);
		rmdir(old);
		return;
	}

	/* dirfd still points to the inode, even though the name moved. */
	int dirfd2 = dup(dirfd);
	DIR *dp = fdopendir(dirfd2);
	if (!dp) {
		complain("case3: fdopendir after rename: %s",
			 strerror(errno));
		close(dirfd2);
		goto out;
	}

	int found = 0;
	struct dirent *de;
	while ((de = readdir(dp)) != NULL) {
		if (strcmp(de->d_name, "sentinel") == 0) found = 1;
	}
	closedir(dp);

	if (!found)
		complain("case3: 'sentinel' not found via fdopendir after "
			 "rename (fd should still reference the inode)");

out:
	unlinkat(dirfd, "sentinel", 0);
	close(dirfd);
	rmdir(new_name);
	rmdir(old);
}

static void case_closedir_closes_fd(void)
{
	char sub[64];
	snprintf(sub, sizeof(sub), "t_fdo.cl.%ld", (long)getpid());
	rmdir(sub);
	mkdir(sub, 0755);

	int dirfd = open(sub, O_RDONLY | O_DIRECTORY);
	if (dirfd < 0) {
		complain("case4: open: %s", strerror(errno));
		rmdir(sub);
		return;
	}

	DIR *dp = fdopendir(dirfd);
	if (!dp) {
		complain("case4: fdopendir: %s", strerror(errno));
		close(dirfd);
		rmdir(sub);
		return;
	}

	int underlying_fd = dirfd;
	closedir(dp);

	struct stat st;
	errno = 0;
	if (fstat(underlying_fd, &st) == 0)
		complain("case4: fstat on fd after closedir succeeded "
			 "(fd should be closed)");
	else if (errno != EBADF)
		complain("case4: expected EBADF after closedir, got %s",
			 strerror(errno));

	rmdir(sub);
}

static void case_not_directory(void)
{
	char a[64];
	snprintf(a, sizeof(a), "t_fdo.nd.%ld", (long)getpid());
	unlink(a);

	int fd = open(a, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) { complain("case5: create: %s", strerror(errno)); return; }

	errno = 0;
	DIR *dp = fdopendir(fd);
	if (dp) {
		complain("case5: fdopendir on regular file succeeded "
			 "(expected ENOTDIR)");
		closedir(dp);
	} else if (errno != ENOTDIR) {
		complain("case5: expected ENOTDIR, got %s", strerror(errno));
		close(fd);
	}

	unlink(a);
}

int main(int argc, char **argv)
{
	const char *dir = ".";
	struct timespec t0, t1;

	while (--argc > 0 && argv[1][0] == '-') {
		argv++;
		for (const char *p = &argv[0][1]; *p; p++) {
			switch (*p) {
			case 'h': Hflag = 1; break;
			case 's': Sflag = 1; break;
			case 't': Tflag = 1; break;
			case 'f': Fflag = 1; break;
			case 'n': Nflag = 1; break;
			case 'd':
				if (argc < 2) { usage(); return TEST_FAIL; }
				dir = argv[1];
				argv++;
				argc--;
				goto next;
			default: usage(); return TEST_FAIL;
			}
		}
next:
		;
	}
	if (Hflag) { usage(); return TEST_PASS; }

	prelude(myname,
		"fdopendir(3) on NFS directory fds (POSIX.1-2008)");
	cd_or_skip(myname, dir, Nflag);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_basic", case_basic());
	RUN_CASE("case_nested", case_nested());
	RUN_CASE("case_after_rename", case_after_rename());
	RUN_CASE("case_closedir_closes_fd", case_closedir_closes_fd());
	RUN_CASE("case_not_directory", case_not_directory());

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}
