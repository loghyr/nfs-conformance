/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_ofd_lock.c -- exercise fcntl(F_OFD_SETLK / F_OFD_GETLK), the
 * Linux open-file-description locks (3.15+).  NFSv4.1 LOCK / LOCKU
 * semantics have to get this right: OFD locks attach to the open
 * file description, not to the process, so a v4.0-style client that
 * maps fcntl locks via POSIX lock owners will leak or falsely share
 * locks across fork() in ways this test detects.
 *
 * POSIX fcntl locks (F_SETLK) are per-process: opening the same file
 * twice in the same process yields no conflict, and closing any fd
 * to the file releases ALL of that process's locks.  OFD locks fix
 * both: they attach to the open file description and release only
 * when the last fd referring to that description closes.
 *
 * Cases:
 *
 *   1. OFD write lock blocks OFD write lock on same range, different
 *      fd.  Two independent opens of the same file, each trying to
 *      take an OFD write lock on the same byte range; the second
 *      SETLK returns EAGAIN.
 *
 *   2. F_OFD_GETLK reports the holder.  After taking a lock on fd1,
 *      GETLK on fd2 reports that the range is locked.
 *
 *   3. Close releases only the closing fd's locks.  fd1 takes a
 *      lock; duplicate fd1 via dup(); close one copy; lock still
 *      held (OFD lock survives until LAST fd closes).  The POSIX
 *      version of this test would FAIL -- closing any fd drops all
 *      that process's locks.
 *
 *   4. Non-overlapping locks don't conflict.  Two OFD write locks on
 *      disjoint byte ranges via two fds succeed concurrently.
 *
 *   5. SETLK across fork() -- OFD locks are inherited by a forked
 *      child because the open file description is shared.  Parent
 *      takes an OFD write lock; forks; child's F_OFD_GETLK on the
 *      same fd reports the lock (held by "ourselves", so GETLK
 *      returns F_UNLCK per the OFD-lock rule that a process cannot
 *      see a conflict with a lock it already owns via the same
 *      description).  Child exits; parent verifies lock still held.
 *
 * Linux-only.  Stubs out on other platforms.
 */

#define _GNU_SOURCE

#include "tests.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

int Hflag = 0;
int Sflag = 0;
int Tflag = 0;
int Fflag = 0;
int Nflag = 0;

static const char *myname = "op_ofd_lock";

#if !defined(__linux__)
int main(void)
{
	skip("%s: F_OFD_SETLK is Linux-specific (3.15+)", myname);
	return TEST_SKIP;
}
#else

#if !defined(F_OFD_SETLK) || !defined(F_OFD_GETLK)
int main(void)
{
	skip("%s: F_OFD_SETLK / F_OFD_GETLK not defined in this header set",
	     myname);
	return TEST_SKIP;
}
#else

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  exercise F_OFD_SETLK -> NFSv4.1 LOCK/LOCKU\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

/*
 * Build a flock struct for [start, start+len) with the given type.
 */
static struct flock mkflock(short type, off_t start, off_t len)
{
	struct flock fl = { 0 };
	fl.l_type = type;
	fl.l_whence = SEEK_SET;
	fl.l_start = start;
	fl.l_len = len;
	fl.l_pid = 0; /* required 0 for OFD locks; kernel fills on GETLK */
	return fl;
}

static void case_conflict_same_range(const char *name)
{
	int fd1 = open(name, O_RDWR);
	int fd2 = open(name, O_RDWR);
	if (fd1 < 0 || fd2 < 0) {
		complain("case1: open: %s", strerror(errno));
		if (fd1 >= 0) close(fd1);
		if (fd2 >= 0) close(fd2);
		return;
	}

	struct flock fl = mkflock(F_WRLCK, 0, 4096);
	if (fcntl(fd1, F_OFD_SETLK, &fl) != 0) {
		complain("case1: SETLK fd1: %s", strerror(errno));
		goto out;
	}

	fl = mkflock(F_WRLCK, 0, 4096);
	errno = 0;
	int rc = fcntl(fd2, F_OFD_SETLK, &fl);
	if (rc == 0) {
		complain("case1: SETLK fd2 unexpectedly succeeded on "
			 "same range");
	} else if (errno != EAGAIN && errno != EACCES) {
		complain("case1: SETLK fd2: expected EAGAIN/EACCES, got %s",
			 strerror(errno));
	}

	/* Release fd1's lock for the next case. */
	fl = mkflock(F_UNLCK, 0, 4096);
	fcntl(fd1, F_OFD_SETLK, &fl);
out:
	close(fd1);
	close(fd2);
}

static void case_getlk_reports(const char *name)
{
	int fd1 = open(name, O_RDWR);
	int fd2 = open(name, O_RDWR);
	if (fd1 < 0 || fd2 < 0) {
		complain("case2: open: %s", strerror(errno));
		if (fd1 >= 0) close(fd1);
		if (fd2 >= 0) close(fd2);
		return;
	}

	struct flock fl = mkflock(F_WRLCK, 0, 4096);
	if (fcntl(fd1, F_OFD_SETLK, &fl) != 0) {
		complain("case2: SETLK fd1: %s", strerror(errno));
		goto out;
	}

	/* GETLK on fd2 should report the range as locked. */
	struct flock query = mkflock(F_WRLCK, 0, 4096);
	if (fcntl(fd2, F_OFD_GETLK, &query) != 0) {
		complain("case2: GETLK fd2: %s", strerror(errno));
		goto out;
	}
	if (query.l_type == F_UNLCK)
		complain("case2: GETLK reported range unlocked, expected "
			 "held by another fd");

	fl = mkflock(F_UNLCK, 0, 4096);
	fcntl(fd1, F_OFD_SETLK, &fl);
out:
	close(fd1);
	close(fd2);
}

static void case_dup_survives_close(const char *name)
{
	int fd = open(name, O_RDWR);
	if (fd < 0) {
		complain("case3: open: %s", strerror(errno));
		return;
	}
	int dup_fd = dup(fd);
	if (dup_fd < 0) {
		complain("case3: dup: %s", strerror(errno));
		close(fd);
		return;
	}

	/* Take the lock on fd. */
	struct flock fl = mkflock(F_WRLCK, 0, 4096);
	if (fcntl(fd, F_OFD_SETLK, &fl) != 0) {
		complain("case3: SETLK: %s", strerror(errno));
		close(dup_fd);
		close(fd);
		return;
	}

	/* Close the dup; the lock is on the same open file description
	 * and must survive this close. */
	close(dup_fd);

	/* Probe from a fresh fd that the lock is still held. */
	int fd_probe = open(name, O_RDWR);
	if (fd_probe >= 0) {
		struct flock query = mkflock(F_WRLCK, 0, 4096);
		if (fcntl(fd_probe, F_OFD_GETLK, &query) == 0) {
			if (query.l_type == F_UNLCK)
				complain("case3: OFD lock was released by "
					 "close of a dup'd fd");
		} else {
			complain("case3: GETLK probe: %s", strerror(errno));
		}
		close(fd_probe);
	}

	fl = mkflock(F_UNLCK, 0, 4096);
	fcntl(fd, F_OFD_SETLK, &fl);
	close(fd);
}

static void case_disjoint_ok(const char *name)
{
	int fd1 = open(name, O_RDWR);
	int fd2 = open(name, O_RDWR);
	if (fd1 < 0 || fd2 < 0) {
		complain("case4: open: %s", strerror(errno));
		if (fd1 >= 0) close(fd1);
		if (fd2 >= 0) close(fd2);
		return;
	}

	struct flock fl1 = mkflock(F_WRLCK, 0, 4096);
	struct flock fl2 = mkflock(F_WRLCK, 4096, 4096);
	if (fcntl(fd1, F_OFD_SETLK, &fl1) != 0)
		complain("case4: SETLK fd1 [0..4096): %s", strerror(errno));
	if (fcntl(fd2, F_OFD_SETLK, &fl2) != 0)
		complain("case4: SETLK fd2 [4096..8192): %s", strerror(errno));

	struct flock unlock1 = mkflock(F_UNLCK, 0, 4096);
	struct flock unlock2 = mkflock(F_UNLCK, 4096, 4096);
	fcntl(fd1, F_OFD_SETLK, &unlock1);
	fcntl(fd2, F_OFD_SETLK, &unlock2);
	close(fd1);
	close(fd2);
}

static void case_fork_shares(const char *name)
{
	int fd = open(name, O_RDWR);
	if (fd < 0) {
		complain("case5: open: %s", strerror(errno));
		return;
	}

	struct flock fl = mkflock(F_WRLCK, 0, 4096);
	if (fcntl(fd, F_OFD_SETLK, &fl) != 0) {
		complain("case5: parent SETLK: %s", strerror(errno));
		close(fd);
		return;
	}

	pid_t child = fork();
	if (child < 0) {
		complain("case5: fork: %s", strerror(errno));
		goto parent_cleanup;
	}
	if (child == 0) {
		/*
		 * In the child: the open file description is shared
		 * with the parent, so the OFD lock taken via this fd
		 * is the child's own lock too.  F_OFD_GETLK must
		 * report F_UNLCK (we don't conflict with ourselves).
		 */
		struct flock q = mkflock(F_WRLCK, 0, 4096);
		if (fcntl(fd, F_OFD_GETLK, &q) != 0)
			_exit(10);
		if (q.l_type != F_UNLCK)
			_exit(11); /* saw a conflict with our own OFD lock */
		_exit(0);
	}

	int status = 0;
	if (waitpid(child, &status, 0) < 0) {
		complain("case5: waitpid: %s", strerror(errno));
		goto parent_cleanup;
	}
	if (!WIFEXITED(status)) {
		complain("case5: child did not exit normally");
	} else if (WEXITSTATUS(status) != 0) {
		if (WEXITSTATUS(status) == 10)
			complain("case5: child F_OFD_GETLK failed");
		else if (WEXITSTATUS(status) == 11)
			complain("case5: child saw conflict with shared OFD "
				 "lock (OFD semantics broken across fork)");
		else
			complain("case5: child exited with code %d",
				 WEXITSTATUS(status));
	}

	/* Verify the lock is still held from the parent's view after
	 * the child exited. */
	int fd_probe = open(name, O_RDWR);
	if (fd_probe >= 0) {
		struct flock query = mkflock(F_WRLCK, 0, 4096);
		if (fcntl(fd_probe, F_OFD_GETLK, &query) == 0) {
			if (query.l_type == F_UNLCK)
				complain("case5: OFD lock dropped across "
					 "child exit");
		}
		close(fd_probe);
	}

parent_cleanup:
	fl = mkflock(F_UNLCK, 0, 4096);
	fcntl(fd, F_OFD_SETLK, &fl);
	close(fd);
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
		"fcntl(F_OFD_SETLK) -> NFSv4.1 LOCK/LOCKU (RFC 5661)");
	cd_or_skip(myname, dir, Nflag);

	char name[64];
	int fd = scratch_open("t_ofd", name, sizeof(name));
	if (ftruncate(fd, 16 * 1024) != 0)
		bail("ftruncate: %s", strerror(errno));
	close(fd);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_conflict_same_range", case_conflict_same_range(name));
	RUN_CASE("case_getlk_reports", case_getlk_reports(name));
	RUN_CASE("case_dup_survives_close", case_dup_survives_close(name));
	RUN_CASE("case_disjoint_ok", case_disjoint_ok(name));
	RUN_CASE("case_fork_shares", case_fork_shares(name));

	unlink(name);

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}

#endif /* F_OFD_SETLK */
#endif /* __linux__ */
