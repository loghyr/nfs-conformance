/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_open_excl.c -- exercise NFSv4 OPEN with createmode=EXCLUSIVE4_1
 * (RFC 7530 S18.16.3 / RFC 8881 S18.16.3) via O_CREAT|O_EXCL.
 *
 * EXCLUSIVE4_1 (or EXCLUSIVE4 on NFSv4.0) lets the client atomically
 * create a file and detect replays: the server stores a client-supplied
 * verifier in the file's attributes (typically ctime on Linux knfsd),
 * and returns NFS4ERR_EXIST on a retry with a different verifier,
 * preventing a retried CREATE from silently replacing a file created by
 * another client between the original request and its retry.
 *
 * Cases:
 *
 *   1. O_CREAT|O_EXCL on a nonexistent file: open() succeeds (fd >= 0).
 *
 *   2. O_CREAT|O_EXCL on an existing file: returns -1/EEXIST.
 *
 *   3. File is zero-length after exclusive create: st_size == 0.
 *      The server must not leave garbage bytes in an exclusively-created
 *      file (regression check for servers that initialise from stale
 *      on-disk blocks).
 *
 *   4. Write then read back: pwrite()/pread() through the exclusively
 *      opened fd round-trip correctly.  Exercises that the OPEN-created
 *      stateid is valid for immediate I/O.
 *
 *   5. openat(AT_FDCWD) variant: identical semantics to plain open(),
 *      exercising the *at form of the syscall.
 *
 * Portable: POSIX across Linux / FreeBSD / macOS / Solaris.
 */

#define _POSIX_C_SOURCE 200809L

#include "tests.h"

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

static const char *myname = "op_open_excl";

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  exercise O_CREAT|O_EXCL -> NFSv4 OPEN EXCLUSIVE "
		"(RFC 7530 S18.16)\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

static void case_create_new(void)
{
	char f[64];
	snprintf(f, sizeof(f), "t_oe.n.%ld", (long)getpid());
	unlink(f);

	int fd = open(f, O_CREAT | O_EXCL | O_RDWR, 0644);
	if (fd < 0) {
		complain("case1: open(O_CREAT|O_EXCL) on new file: %s",
			 strerror(errno));
		return;
	}
	close(fd);
	unlink(f);
}

static void case_eexist(void)
{
	char f[64];
	snprintf(f, sizeof(f), "t_oe.ex.%ld", (long)getpid());
	unlink(f);

	int fd = open(f, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("case2: setup open: %s", strerror(errno));
		return;
	}
	close(fd);

	errno = 0;
	fd = open(f, O_CREAT | O_EXCL | O_RDWR, 0644);
	if (fd >= 0) {
		complain("case2: O_CREAT|O_EXCL on existing file "
			 "unexpectedly succeeded");
		close(fd);
	} else if (errno != EEXIST) {
		complain("case2: expected EEXIST, got %s", strerror(errno));
	}
	unlink(f);
}

static void case_zero_size(void)
{
	char f[64];
	snprintf(f, sizeof(f), "t_oe.z.%ld", (long)getpid());
	unlink(f);

	int fd = open(f, O_CREAT | O_EXCL | O_RDWR, 0644);
	if (fd < 0) {
		complain("case3: open(O_CREAT|O_EXCL): %s", strerror(errno));
		return;
	}

	struct stat st;
	if (fstat(fd, &st) != 0) {
		complain("case3: fstat: %s", strerror(errno));
	} else if (st.st_size != 0) {
		complain("case3: exclusive-created file has st_size=%lld "
			 "(expected 0)",
			 (long long)st.st_size);
	}
	close(fd);
	unlink(f);
}

static void case_write_read(void)
{
	char f[64];
	snprintf(f, sizeof(f), "t_oe.wr.%ld", (long)getpid());
	unlink(f);

	int fd = open(f, O_CREAT | O_EXCL | O_RDWR, 0644);
	if (fd < 0) {
		complain("case4: open(O_CREAT|O_EXCL): %s", strerror(errno));
		return;
	}

	unsigned char wbuf[512], rbuf[512];
	fill_pattern(wbuf, sizeof(wbuf), 42);

	if (pwrite_all(fd, wbuf, sizeof(wbuf), 0, "case4: write") != 0) {
		close(fd); unlink(f); return;
	}
	if (pread_all(fd, rbuf, sizeof(rbuf), 0, "case4: read") != 0) {
		close(fd); unlink(f); return;
	}

	size_t off = check_pattern(rbuf, sizeof(rbuf), 42);
	if (off != 0)
		complain("case4: data mismatch at byte %zu (after excl create)",
			 off - 1);

	close(fd);
	unlink(f);
}

static void case_openat(void)
{
	char f[64];
	snprintf(f, sizeof(f), "t_oe.at.%ld", (long)getpid());
	unlink(f);

	int fd = openat(AT_FDCWD, f, O_CREAT | O_EXCL | O_RDWR, 0644);
	if (fd < 0) {
		complain("case5: openat(AT_FDCWD, O_CREAT|O_EXCL): %s",
			 strerror(errno));
		return;
	}
	close(fd);
	unlink(f);
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
		"O_CREAT|O_EXCL -> NFSv4 OPEN EXCLUSIVE (RFC 7530 S18.16)");
	cd_or_skip(myname, dir, Nflag);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_create_new", case_create_new());
	RUN_CASE("case_eexist", case_eexist());
	RUN_CASE("case_zero_size", case_zero_size());
	RUN_CASE("case_write_read", case_write_read());
	RUN_CASE("case_openat", case_openat());

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}
