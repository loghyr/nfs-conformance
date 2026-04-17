/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_sync_dsync.c -- exercise O_SYNC / O_DSYNC durability contract.
 *
 * POSIX: O_SYNC requires every write() to commit data AND metadata
 * to stable storage before returning.  O_DSYNC commits data (plus
 * any metadata needed to read the data back); other metadata
 * updates may be deferred.  Paired with write(), O_DSYNC is
 * equivalent to fdatasync(); O_SYNC is equivalent to fsync().
 *
 * On NFSv4, O_SYNC/O_DSYNC writes are sent with stable=FILE_SYNC
 * (instead of UNSTABLE+COMMIT).  The server must not reply until
 * the data is durable.  Pairs naturally with op_commit.
 *
 * The client-visible durability test is: fork a child that opens
 * O_SYNC/O_DSYNC, writes, and _exit()s WITHOUT close().  The parent
 * then stats via a fresh path lookup.  If the server honored
 * FILE_SYNC, the write is visible; if not, the write may be lost.
 *
 * Cases:
 *
 *   1. O_SYNC open + write + read-back works.  Baseline sanity.
 *
 *   2. O_DSYNC open + write + read-back works.
 *
 *   3. O_SYNC child-exit durability.  Fork child; child opens
 *      O_SYNC, writes, _exit()s.  Parent waits, opens by path,
 *      reads, verifies data.  Tests that the write is on the
 *      server after the child exits without closing.
 *
 *   4. O_DSYNC child-exit durability.  Same as case 3 with O_DSYNC.
 *
 *   5. O_SYNC large write crosses wsize boundary.  256 KiB write
 *      via O_SYNC; verify.
 *
 *   6. fsync after O_SYNC close is a no-op.  Open O_SYNC, write,
 *      close, reopen, fsync -- fsync should succeed (even if it
 *      is effectively a no-op on a cleanly-closed file).
 *
 * Portable: POSIX.1-2008 (O_SYNC); O_DSYNC widely available but
 * Linux aliased O_DSYNC to O_SYNC until 2.6.33.  macOS exposes
 * O_DSYNC but the kernel treats it the same as O_SYNC.  Record
 * rather than assert the distinction.
 */

#define _POSIX_C_SOURCE 200809L

#include "tests.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef O_DSYNC
# define O_DSYNC O_SYNC
#endif

int Hflag = 0;
int Sflag = 0;
int Tflag = 0;
int Fflag = 0;
int Nflag = 0;

static const char *myname = "op_sync_dsync";

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  exercise O_SYNC / O_DSYNC durability (RFC 7530 S16.36)\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

static void sync_round_trip(int flags, const char *label, int casenum)
{
	char a[64];
	snprintf(a, sizeof(a), "t_sd.rt%d.%ld", casenum, (long)getpid());
	unlink(a);

	int fd = open(a, O_RDWR | O_CREAT | flags, 0644);
	if (fd < 0) {
		complain("case%d: open %s: %s",
			 casenum, label, strerror(errno));
		unlink(a);
		return;
	}

	const char pat[] = "sync-durability-pattern";
	ssize_t w = write(fd, pat, sizeof(pat));
	close(fd);
	if (w != (ssize_t)sizeof(pat)) {
		complain("case%d: %s write: %zd: %s",
			 casenum, label, w, strerror(errno));
		unlink(a);
		return;
	}

	int rfd = open(a, O_RDONLY);
	if (rfd < 0) {
		complain("case%d: reopen: %s", casenum, strerror(errno));
		unlink(a);
		return;
	}
	char buf[sizeof(pat)];
	ssize_t r = read(rfd, buf, sizeof(buf));
	close(rfd);
	if (r != (ssize_t)sizeof(pat))
		complain("case%d: %s read: %zd", casenum, label, r);
	else if (memcmp(buf, pat, sizeof(pat)) != 0)
		complain("case%d: %s data mismatch", casenum, label);

	unlink(a);
}

static void case_sync_round_trip(void)
{
	sync_round_trip(O_SYNC, "O_SYNC", 1);
}

static void case_dsync_round_trip(void)
{
	sync_round_trip(O_DSYNC, "O_DSYNC", 2);
}

/*
 * Child opens with sync flag, writes, _exit()s without closing.
 * Parent verifies the data landed on the server.  If the server
 * honored stable=FILE_SYNC the write is persisted; otherwise it
 * may have been lost when the child died (client page cache gone).
 */
static void sync_child_exit_durability(int flags, const char *label,
				       int casenum)
{
	char a[64];
	snprintf(a, sizeof(a), "t_sd.ce%d.%ld", casenum, (long)getpid());
	unlink(a);

	const char pat[] = "child-exit-durability-pattern";

	pid_t pid = fork();
	if (pid < 0) {
		complain("case%d: fork: %s", casenum, strerror(errno));
		return;
	}
	if (pid == 0) {
		int fd = open(a, O_RDWR | O_CREAT | flags, 0644);
		if (fd < 0)
			_exit(71);
		ssize_t w = write(fd, pat, sizeof(pat));
		if (w != (ssize_t)sizeof(pat))
			_exit(72);
		/* Intentionally do NOT close(fd): exercise the server-
		 * side stable-storage guarantee, not the client-side
		 * close-to-open flush. */
		_exit(0);
	}

	int status = 0;
	if (waitpid(pid, &status, 0) < 0) {
		complain("case%d: waitpid: %s", casenum, strerror(errno));
		unlink(a);
		return;
	}
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		complain("case%d: child exited abnormally (status 0x%x)",
			 casenum, status);
		unlink(a);
		return;
	}

	int rfd = open(a, O_RDONLY);
	if (rfd < 0) {
		complain("case%d: parent reopen: %s",
			 casenum, strerror(errno));
		unlink(a);
		return;
	}
	char buf[sizeof(pat)];
	ssize_t r = read(rfd, buf, sizeof(buf));
	close(rfd);
	if (r != (ssize_t)sizeof(pat))
		complain("case%d: %s child write not durable: read %zd "
			 "(server did not honor FILE_SYNC)",
			 casenum, label, r);
	else if (memcmp(buf, pat, sizeof(pat)) != 0)
		complain("case%d: %s durable read mismatch", casenum, label);

	unlink(a);
}

static void case_sync_child_exit(void)
{
	sync_child_exit_durability(O_SYNC, "O_SYNC", 3);
}

static void case_dsync_child_exit(void)
{
	sync_child_exit_durability(O_DSYNC, "O_DSYNC", 4);
}

static void case_sync_large(void)
{
	char a[64];
	snprintf(a, sizeof(a), "t_sd.lg.%ld", (long)getpid());
	unlink(a);

	const size_t sz = 256 * 1024;
	unsigned char *buf = malloc(sz);
	if (!buf) {
		complain("case5: malloc: %s", strerror(errno));
		return;
	}
	for (size_t i = 0; i < sz; i++)
		buf[i] = (unsigned char)(i & 0xFF);

	int fd = open(a, O_RDWR | O_CREAT | O_SYNC, 0644);
	if (fd < 0) {
		complain("case5: open: %s", strerror(errno));
		free(buf);
		unlink(a);
		return;
	}
	ssize_t w = write(fd, buf, sz);
	close(fd);
	if (w != (ssize_t)sz) {
		complain("case5: large O_SYNC write: %zd / %zu: %s",
			 w, sz, strerror(errno));
		free(buf);
		unlink(a);
		return;
	}

	int rfd = open(a, O_RDONLY);
	if (rfd < 0) {
		complain("case5: reopen: %s", strerror(errno));
		free(buf);
		unlink(a);
		return;
	}
	unsigned char *vbuf = malloc(sz);
	if (!vbuf) {
		complain("case5: malloc verify: %s", strerror(errno));
		close(rfd);
		free(buf);
		unlink(a);
		return;
	}
	ssize_t r = read(rfd, vbuf, sz);
	close(rfd);
	if (r != (ssize_t)sz)
		complain("case5: large read: %zd / %zu", r, sz);
	else if (memcmp(vbuf, buf, sz) != 0)
		complain("case5: large O_SYNC round-trip mismatch");

	free(buf);
	free(vbuf);
	unlink(a);
}

static void case_fsync_after_sync_close(void)
{
	char a[64];
	snprintf(a, sizeof(a), "t_sd.fs.%ld", (long)getpid());
	unlink(a);

	int fd = open(a, O_RDWR | O_CREAT | O_SYNC, 0644);
	if (fd < 0) {
		complain("case6: open O_SYNC: %s", strerror(errno));
		unlink(a);
		return;
	}
	const char pat[] = "fsync-after-close";
	if (write(fd, pat, sizeof(pat)) != (ssize_t)sizeof(pat)) {
		complain("case6: write: %s", strerror(errno));
		close(fd);
		unlink(a);
		return;
	}
	close(fd);

	int rfd = open(a, O_RDWR);
	if (rfd < 0) {
		complain("case6: reopen: %s", strerror(errno));
		unlink(a);
		return;
	}
	if (fsync(rfd) != 0)
		complain("case6: fsync after clean close: %s",
			 strerror(errno));
	close(rfd);

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
		"O_SYNC / O_DSYNC durability contract");
	cd_or_skip(myname, dir, Nflag);

	if (O_DSYNC == O_SYNC && !Sflag)
		printf("NOTE: %s: O_DSYNC == O_SYNC on this platform "
		       "(kernel aliases them)\n", myname);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_sync_round_trip", case_sync_round_trip());
	RUN_CASE("case_dsync_round_trip", case_dsync_round_trip());
	RUN_CASE("case_sync_child_exit", case_sync_child_exit());
	RUN_CASE("case_dsync_child_exit", case_dsync_child_exit());
	RUN_CASE("case_sync_large", case_sync_large());
	RUN_CASE("case_fsync_after_sync_close", case_fsync_after_sync_close());

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}
