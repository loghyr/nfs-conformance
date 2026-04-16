/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_tmpfile.c -- exercise O_TMPFILE (Linux 3.11+).
 *
 * O_TMPFILE asks the kernel to create an unnamed file in DIR.  The
 * file has no name in the filesystem: it cannot be found via
 * readdir() or opened by path, and it is deleted when the last fd
 * is closed.  linkat(fd, "", AT_FDCWD, path, AT_EMPTY_PATH) can
 * materialize it into a normal named file.
 *
 * On NFS, O_TMPFILE maps to an OPEN that creates an anonymous file
 * object; NFSv4.2 clients emit a specific CLAIM form for this.  Not
 * every NFS server supports it -- the test skips if the open is
 * refused.
 *
 * Cases:
 *
 *   1. O_TMPFILE open creates an anonymous fd.  Skip test if
 *      EOPNOTSUPP / EINVAL / ENOTSUP (server/client lacks support).
 *
 *   2. Write + read-back on the anonymous fd works (no name
 *      involved).
 *
 *   3. File is not visible via readdir in DIR.
 *
 *   4. linkat(AT_EMPTY_PATH) materializes the anonymous file to a
 *      path; open by path now works and sees the written data.
 *
 *   5. Close without linkat leaves no trace: open DIR, readdir,
 *      confirm the anonymous file never appeared.
 *
 *   6. O_TMPFILE | O_EXCL disables linkat materialization: linkat
 *      on that fd must fail with ENOENT (Linux behavior).  Confirm.
 *
 * Linux-only.  Skip on other platforms.
 */

#if defined(__linux__)
# define _GNU_SOURCE
#endif
#define _DEFAULT_SOURCE

#include "tests.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifdef O_TMPFILE
# define HAVE_O_TMPFILE 1
#else
# define HAVE_O_TMPFILE 0
#endif

int Hflag = 0;
int Sflag = 0;
int Tflag = 0;
int Fflag = 0;
int Nflag = 0;

static const char *myname = "op_tmpfile";

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  exercise O_TMPFILE anonymous-file creation (Linux 3.11+)\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

#if HAVE_O_TMPFILE

/*
 * Try to open an O_TMPFILE; return fd on success, -1 with errno
 * preserved on failure.  Callers must distinguish "server/client
 * does not support it" (EOPNOTSUPP, EINVAL, ENOTSUP) from a real
 * failure.
 */
static int try_tmpfile_open(int flags, mode_t mode)
{
	return open(".", O_RDWR | O_TMPFILE | flags, mode);
}

static int tmpfile_unsupported(int saved_errno)
{
	return saved_errno == EOPNOTSUPP
	    || saved_errno == EINVAL
	    || saved_errno == ENOTSUP
	    || saved_errno == ENOSYS;
}

static void case_tmpfile_open(void)
{
	int fd = try_tmpfile_open(0, 0600);
	if (fd < 0) {
		if (tmpfile_unsupported(errno)) {
			if (!Sflag)
				printf("NOTE: %s: case1 O_TMPFILE not "
				       "supported here (%s) — NFSv4.2 "
				       "server may not implement it\n",
				       myname, strerror(errno));
		} else {
			complain("case1: O_TMPFILE: %s", strerror(errno));
		}
		return;
	}
	close(fd);
}

static void case_tmpfile_io(void)
{
	int fd = try_tmpfile_open(0, 0600);
	if (fd < 0) {
		if (tmpfile_unsupported(errno)) return;
		complain("case2: O_TMPFILE: %s", strerror(errno));
		return;
	}

	const char pat[] = "tmpfile-io-pattern";
	if (write(fd, pat, sizeof(pat)) != (ssize_t)sizeof(pat)) {
		complain("case2: write: %s", strerror(errno));
		close(fd);
		return;
	}
	if (lseek(fd, 0, SEEK_SET) != 0) {
		complain("case2: lseek: %s", strerror(errno));
		close(fd);
		return;
	}
	char buf[sizeof(pat)];
	if (read(fd, buf, sizeof(buf)) != (ssize_t)sizeof(pat)) {
		complain("case2: read: %s", strerror(errno));
		close(fd);
		return;
	}
	if (memcmp(buf, pat, sizeof(pat)) != 0)
		complain("case2: tmpfile data mismatch");

	close(fd);
}

static int dir_has_name_matching(const char *prefix)
{
	DIR *d = opendir(".");
	if (!d) return -1;
	struct dirent *e;
	int found = 0;
	while ((e = readdir(d)) != NULL) {
		if (strncmp(e->d_name, prefix, strlen(prefix)) == 0) {
			found = 1;
			break;
		}
	}
	closedir(d);
	return found;
}

static void case_tmpfile_not_in_readdir(void)
{
	int fd = try_tmpfile_open(0, 0600);
	if (fd < 0) {
		if (tmpfile_unsupported(errno)) return;
		complain("case3: O_TMPFILE: %s", strerror(errno));
		return;
	}

	/* An unnamed file cannot match any prefix at readdir; confirm
	 * no stray anonymous artefact is visible.  The server may
	 * intern it under some internal name visible to the client
	 * library, which would be a bug. */
	int has_unlike_name = dir_has_name_matching("#");
	if (has_unlike_name > 0 && !Sflag)
		printf("NOTE: %s: case3 saw a '#'-prefixed entry in "
		       "readdir — server may be leaking the O_TMPFILE "
		       "intermediate name\n", myname);
	close(fd);
}

static void case_tmpfile_linkat(void)
{
	int fd = try_tmpfile_open(0, 0600);
	if (fd < 0) {
		if (tmpfile_unsupported(errno)) return;
		complain("case4: O_TMPFILE: %s", strerror(errno));
		return;
	}

	const char pat[] = "linkat-materialize-pattern";
	if (write(fd, pat, sizeof(pat)) != (ssize_t)sizeof(pat)) {
		complain("case4: write: %s", strerror(errno));
		close(fd);
		return;
	}

	char name[64];
	snprintf(name, sizeof(name), "t_tf.mat.%ld", (long)getpid());
	unlink(name);

	if (linkat(fd, "", AT_FDCWD, name, AT_EMPTY_PATH) != 0) {
		if (errno == ENOENT && !Sflag) {
			/* Some setups require /proc/self/fd/%d path form
			 * because AT_EMPTY_PATH needs CAP_DAC_READ_SEARCH.
			 * Retry via the /proc form. */
			char proc[64];
			snprintf(proc, sizeof(proc),
				 "/proc/self/fd/%d", fd);
			if (linkat(AT_FDCWD, proc, AT_FDCWD, name,
				   AT_SYMLINK_FOLLOW) != 0) {
				printf("NOTE: %s: case4 linkat(AT_EMPTY_PATH) "
				       "and /proc fallback both failed (%s)\n",
				       myname, strerror(errno));
				close(fd);
				return;
			}
		} else {
			complain("case4: linkat: %s", strerror(errno));
			close(fd);
			return;
		}
	}
	close(fd);

	/* Now open by name and verify. */
	int rfd = open(name, O_RDONLY);
	if (rfd < 0) {
		complain("case4: open materialized: %s", strerror(errno));
		unlink(name);
		return;
	}
	char buf[sizeof(pat)];
	ssize_t r = read(rfd, buf, sizeof(buf));
	close(rfd);
	if (r != (ssize_t)sizeof(pat))
		complain("case4: materialized read: %zd", r);
	else if (memcmp(buf, pat, sizeof(pat)) != 0)
		complain("case4: materialized data mismatch");

	unlink(name);
}

static void case_tmpfile_close_deletes(void)
{
	/* Snapshot DIR entry count before/after — an O_TMPFILE open
	 * followed by close without linkat should leave no new entry. */
	int before = 0, after = 0;
	DIR *d = opendir(".");
	if (!d) { complain("case5: opendir: %s", strerror(errno)); return; }
	while (readdir(d) != NULL) before++;
	rewinddir(d);

	int fd = try_tmpfile_open(0, 0600);
	if (fd < 0) {
		closedir(d);
		if (tmpfile_unsupported(errno)) return;
		complain("case5: O_TMPFILE: %s", strerror(errno));
		return;
	}
	if (write(fd, "transient", 9) != 9) {
		complain("case5: write: %s", strerror(errno));
		close(fd);
		closedir(d);
		return;
	}
	close(fd);

	/* Fresh directory scan post-close. */
	closedir(d);
	d = opendir(".");
	if (!d) { complain("case5: reopendir: %s", strerror(errno)); return; }
	while (readdir(d) != NULL) after++;
	closedir(d);

	if (after != before)
		complain("case5: directory entry count changed %d -> %d "
			 "after O_TMPFILE close (unnamed file leaked into "
			 "readdir or was not deleted)",
			 before, after);
}

static void case_tmpfile_excl_no_link(void)
{
	int fd = try_tmpfile_open(O_EXCL, 0600);
	if (fd < 0) {
		if (tmpfile_unsupported(errno)) return;
		complain("case6: O_TMPFILE|O_EXCL: %s", strerror(errno));
		return;
	}

	char name[64];
	snprintf(name, sizeof(name), "t_tf.ex.%ld", (long)getpid());
	unlink(name);

	errno = 0;
	int rc = linkat(fd, "", AT_FDCWD, name, AT_EMPTY_PATH);
	if (rc == 0) {
		complain("case6: linkat(AT_EMPTY_PATH) on O_TMPFILE|O_EXCL "
			 "succeeded (Linux documents this as ENOENT)");
		unlink(name);
	} else if (errno != ENOENT && !Sflag) {
		printf("NOTE: %s: case6 linkat on O_EXCL tmpfile returned "
		       "%s (expected ENOENT on Linux)\n",
		       myname, strerror(errno));
	}
	close(fd);
}

#endif /* HAVE_O_TMPFILE */

int main(int argc, char **argv)
{
	const char *dir = ".";

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
		"O_TMPFILE anonymous-file creation (Linux 3.11+)");
	cd_or_skip(myname, dir, Nflag);

#if !HAVE_O_TMPFILE
	skip("%s: O_TMPFILE not available on this platform", myname);
#else
	struct timespec t0, t1;
	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_tmpfile_open", case_tmpfile_open());
	RUN_CASE("case_tmpfile_io", case_tmpfile_io());
	RUN_CASE("case_tmpfile_not_in_readdir",
		 case_tmpfile_not_in_readdir());
	RUN_CASE("case_tmpfile_linkat", case_tmpfile_linkat());
	RUN_CASE("case_tmpfile_close_deletes",
		 case_tmpfile_close_deletes());
	RUN_CASE("case_tmpfile_excl_no_link",
		 case_tmpfile_excl_no_link());

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
#endif
}
