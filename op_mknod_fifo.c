/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_mknod_fifo.c -- exercise NFSv4 CREATE(NF4FIFO) (RFC 7530 S18.4)
 * via mkfifo(3).
 *
 * FIFOs are created on the NFS server as NF4FIFO objects via the same
 * CREATE compound used for NF4DIR.  While FIFO data path I/O is
 * client-local (no NFS READ/WRITE generated), the CREATE, GETATTR, and
 * REMOVE ops are all exercised, and the server must preserve the FIFO
 * type bit through GETATTR.
 *
 * Diagnostic value: creating a non-regular, non-directory object via
 * NFSv4 CREATE exercises a code path distinct from both OPEN (regular
 * files) and MKDIR.  A server that maps NF4FIFO incorrectly (e.g.
 * returns NF4REG on GETATTR) will fail case 1's lstat() type check
 * without any TLS involvement, isolating the issue to object-type
 * handling rather than auth.
 *
 * Cases:
 *
 *   1. mkfifo() basic: creates a FIFO; lstat() returns S_ISFIFO.
 *
 *   2. Mode round-trip: mkfifo(path, 0640) then explicit chmod(0640);
 *      lstat() confirms the mode bits are preserved.
 *
 *   3. EEXIST: mkfifo() on an existing path returns -1/EEXIST.
 *
 *   4. Open for read (O_RDONLY|O_NONBLOCK): succeeds on POSIX without
 *      a writer present when O_NONBLOCK is set.
 *
 *   5. Open for write (O_WRONLY|O_NONBLOCK): POSIX mandates ENXIO
 *      when no reader is present and O_NONBLOCK is set.
 *
 *   6. unlink removes the FIFO: access() returns ENOENT after unlink.
 *
 * Portable: POSIX across Linux / FreeBSD / macOS / Solaris.
 *
 * Note: cases 4 and 5 open the FIFO on the NFS-mounted path; the
 * actual FIFO data path is client-local.  These cases test OPEN /
 * ACCESS / GETATTR on an NF4FIFO object, not NFS I/O transfer.
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

static const char *myname = "op_mknod_fifo";

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  exercise mkfifo -> NFSv4 CREATE(NF4FIFO) (RFC 7530 S18.4)\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

static void case_basic(void)
{
	char f[64];
	snprintf(f, sizeof(f), "t_mf.b.%ld", (long)getpid());
	unlink(f);

	if (mkfifo(f, 0644) != 0) {
		complain("case1: mkfifo: %s", strerror(errno));
		return;
	}

	struct stat st;
	if (lstat(f, &st) != 0) {
		complain("case1: lstat: %s", strerror(errno));
	} else if (!S_ISFIFO(st.st_mode)) {
		complain("case1: lstat mode 0%o is not S_IFIFO "
			 "(server may not support NF4FIFO)",
			 st.st_mode & S_IFMT);
	}
	unlink(f);
}

static void case_mode(void)
{
	char f[64];
	snprintf(f, sizeof(f), "t_mf.m.%ld", (long)getpid());
	unlink(f);

	if (mkfifo(f, 0640) != 0) {
		complain("case2: mkfifo(0640): %s", strerror(errno));
		return;
	}
	/* Force mode independent of the process umask. */
	if (chmod(f, 0640) != 0) {
		complain("case2: chmod(0640): %s", strerror(errno));
		unlink(f);
		return;
	}

	struct stat st;
	if (lstat(f, &st) != 0) {
		complain("case2: lstat: %s", strerror(errno));
		unlink(f);
		return;
	}
	mode_t got = st.st_mode & 0777;
	if (got != 0640)
		complain("case2: mode expected 0640, got 0%o", got);
	unlink(f);
}

static void case_eexist(void)
{
	char f[64];
	snprintf(f, sizeof(f), "t_mf.ee.%ld", (long)getpid());
	unlink(f);

	if (mkfifo(f, 0644) != 0) {
		complain("case3: setup mkfifo: %s", strerror(errno));
		return;
	}
	errno = 0;
	if (mkfifo(f, 0644) == 0) {
		complain("case3: mkfifo on existing FIFO unexpectedly "
			 "succeeded");
	} else if (errno != EEXIST) {
		complain("case3: expected EEXIST, got %s", strerror(errno));
	}
	unlink(f);
}

static void case_open_rdonly(void)
{
	char f[64];
	snprintf(f, sizeof(f), "t_mf.rd.%ld", (long)getpid());
	unlink(f);

	if (mkfifo(f, 0644) != 0) {
		complain("case4: mkfifo: %s", strerror(errno));
		return;
	}
	/*
	 * O_RDONLY|O_NONBLOCK on a FIFO with no writer succeeds on all
	 * POSIX-conformant systems (POSIX.1-2008 §2.9.1).
	 */
	int fd = open(f, O_RDONLY | O_NONBLOCK);
	if (fd < 0)
		complain("case4: open(O_RDONLY|O_NONBLOCK) on FIFO: %s",
			 strerror(errno));
	else
		close(fd);
	unlink(f);
}

static void case_open_wronly(void)
{
	char f[64];
	snprintf(f, sizeof(f), "t_mf.wr.%ld", (long)getpid());
	unlink(f);

	if (mkfifo(f, 0644) != 0) {
		complain("case5: mkfifo: %s", strerror(errno));
		return;
	}
	/*
	 * O_WRONLY|O_NONBLOCK with no reader: POSIX mandates ENXIO
	 * (POSIX.1-2008 §2.9.1).
	 */
	errno = 0;
	int fd = open(f, O_WRONLY | O_NONBLOCK);
	if (fd >= 0) {
		complain("case5: open(O_WRONLY|O_NONBLOCK) with no reader "
			 "unexpectedly succeeded");
		close(fd);
	} else if (errno != ENXIO) {
		complain("case5: expected ENXIO, got %s", strerror(errno));
	}
	unlink(f);
}

static void case_unlink(void)
{
	char f[64];
	snprintf(f, sizeof(f), "t_mf.ul.%ld", (long)getpid());
	unlink(f);

	if (mkfifo(f, 0644) != 0) {
		complain("case6: mkfifo: %s", strerror(errno));
		return;
	}
	if (unlink(f) != 0) {
		complain("case6: unlink: %s", strerror(errno));
		return;
	}
	if (access(f, F_OK) == 0)
		complain("case6: FIFO still accessible after unlink");
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
		"mkfifo -> NFSv4 CREATE(NF4FIFO) (RFC 7530 S18.4)");
	cd_or_skip(myname, dir, Nflag);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_basic", case_basic());
	RUN_CASE("case_mode", case_mode());
	RUN_CASE("case_eexist", case_eexist());
	RUN_CASE("case_open_rdonly", case_open_rdonly());
	RUN_CASE("case_open_wronly", case_open_wronly());
	RUN_CASE("case_unlink", case_unlink());

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}
