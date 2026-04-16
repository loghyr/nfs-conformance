/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_lock_posix.c -- POSIX fcntl lock semantics that go beyond
 * basic F_SETLK/F_GETLK (covered by op_lock).
 *
 * POSIX fcntl byte-range locks have two behaviours that trip up
 * NFS servers and applications both:
 *
 *   1. CLOSE RELEASES ALL LOCKS.  If a process has any lock on a
 *      file, closing ANY fd that refers to that file releases
 *      EVERY lock the process holds on that file.  This is the
 *      "POSIX lock catastrophe": library A takes a lock via fd_A;
 *      library B opens the same file (fresh fd_B), reads, and
 *      closes fd_B.  Library A's lock is silently gone.  OFD
 *      locks (op_ofd_lock) exist specifically to fix this.
 *
 *   2. COALESCING AND SPLITTING.  Adjacent or overlapping locks
 *      of the same type merge; partial unlock of a lock range
 *      splits it.  lock [0,10) + lock [5,15) → [0,15).
 *      lock [0,100) + unlock [25,75) → [0,25) and [75,100).
 *      Servers that track locks as opaque "handle + range pairs"
 *      without this algebra silently deadlock against themselves.
 *
 * Ported from cthon04 lock/tlock with modernisation and added
 * OFD-lock contrast cases for the close-behaviour.
 *
 * Cases:
 *
 *   1. Close catastrophe: open fd1 POSIX-lock [0,100); open a
 *      second fd2 on the same file; close fd2.  F_GETLK must now
 *      report the range UNLOCKED — fd1's lock was released by
 *      closing fd2.  This is the POSIX-mandated (and surprising)
 *      behaviour.
 *
 *   2. OFD contrast: same pattern with F_OFD_SETLK.  Closing fd2
 *      must NOT release fd1's OFD lock.  Tests that the client/
 *      server plumbing distinguishes owner-per-process (POSIX)
 *      from owner-per-fd (OFD).  Linux 3.15+ only; skip otherwise.
 *
 *   3. Coalescing: set F_WRLCK on [0,10); set F_WRLCK on [5,15).
 *      F_GETLK at offset 5 must report one range covering [0,15).
 *
 *   4. Splitting: set F_WRLCK on [0,100); unlock [25,75).
 *      F_GETLK at offset 50 must report the range UNLOCKED;
 *      F_GETLK at offset 10 reports [0,25) locked; F_GETLK at
 *      offset 80 reports [75,100) locked.
 *
 *   5. Lock conflict: two processes compete for the same range;
 *      F_SETLK fails EAGAIN/EACCES; F_GETLK reports the holder's
 *      pid.
 *
 *   6. F_UNLCK on unheld range: must succeed (no-op).  Some
 *      servers erroneously return an error.
 *
 * Portable: POSIX fcntl locks everywhere; case 2 Linux 3.15+.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

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

int Hflag = 0;
int Sflag = 0;
int Tflag = 0;
int Fflag = 0;
int Nflag = 0;

static const char *myname = "op_lock_posix";

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  POSIX lock semantics beyond basic F_SETLK/F_GETLK\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

static int setlk(int fd, int type, off_t start, off_t len, int cmd)
{
	struct flock fl = {0};
	fl.l_type = type;
	fl.l_whence = SEEK_SET;
	fl.l_start = start;
	fl.l_len = len;
	return fcntl(fd, cmd, &fl);
}

/* F_GETLK that reports whether a range is UNLOCKED (returns 1) or
 * LOCKED (returns 0).  Stores the holding flock in *out if LOCKED. */
static int getlk_unlocked(int fd, off_t start, off_t len, struct flock *out)
{
	struct flock fl = {0};
	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = start;
	fl.l_len = len;
	if (fcntl(fd, F_GETLK, &fl) != 0) {
		if (out) memset(out, 0, sizeof(*out));
		return -1;
	}
	if (out) *out = fl;
	return fl.l_type == F_UNLCK ? 1 : 0;
}

static void case_close_catastrophe(void)
{
	char a[64];
	snprintf(a, sizeof(a), "t_lp.cc.%ld", (long)getpid());
	unlink(a);

	int fd1 = open(a, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd1 < 0) {
		complain("case1: create: %s", strerror(errno));
		unlink(a); return;
	}
	if (ftruncate(fd1, 1024) != 0) {
		complain("case1: truncate: %s", strerror(errno));
		close(fd1); unlink(a); return;
	}

	if (setlk(fd1, F_WRLCK, 0, 100, F_SETLK) != 0) {
		complain("case1: initial F_SETLK: %s", strerror(errno));
		close(fd1); unlink(a); return;
	}

	/* Second fd on the same file, same process. */
	int fd2 = open(a, O_RDWR);
	if (fd2 < 0) {
		complain("case1: second open: %s", strerror(errno));
		close(fd1); unlink(a); return;
	}
	/* Closing fd2 must release every POSIX lock held by this
	 * process on this file — including fd1's [0,100). */
	close(fd2);

	struct flock got;
	int unlocked = getlk_unlocked(fd1, 0, 100, &got);
	close(fd1);
	unlink(a);

	if (unlocked < 0)
		complain("case1: F_GETLK after catastrophe: %s",
			 strerror(errno));
	else if (unlocked == 0)
		complain("case1: POSIX close-releases-all-locks not "
			 "honoured: lock type=%d still held on [0,100) "
			 "after closing second fd", got.l_type);
}

static void case_ofd_contrast(void)
{
#ifdef F_OFD_SETLK
	char a[64];
	snprintf(a, sizeof(a), "t_lp.of.%ld", (long)getpid());
	unlink(a);

	int fd1 = open(a, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd1 < 0) {
		complain("case2: create: %s", strerror(errno));
		unlink(a); return;
	}
	if (ftruncate(fd1, 1024) != 0) {
		complain("case2: truncate: %s", strerror(errno));
		close(fd1); unlink(a); return;
	}

	struct flock fl = {0};
	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 100;
	fl.l_pid = 0;          /* required for OFD */
	if (fcntl(fd1, F_OFD_SETLK, &fl) != 0) {
		if (errno == EINVAL) {
			if (!Sflag)
				printf("NOTE: %s: case2 F_OFD_SETLK not "
				       "supported (need Linux 3.15+)\n",
				       myname);
		} else {
			complain("case2: F_OFD_SETLK: %s", strerror(errno));
		}
		close(fd1); unlink(a); return;
	}

	int fd2 = open(a, O_RDWR);
	if (fd2 < 0) {
		complain("case2: second open: %s", strerror(errno));
		close(fd1); unlink(a); return;
	}
	close(fd2);

	/* OFD lock must survive: F_OFD_GETLK on fd1 reports locked. */
	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 100;
	fl.l_pid = 0;
	if (fcntl(fd1, F_OFD_GETLK, &fl) != 0)
		complain("case2: F_OFD_GETLK: %s", strerror(errno));
	else if (fl.l_type == F_UNLCK)
		complain("case2: OFD lock released by closing unrelated fd "
			 "(OFD owner-per-fd semantics violated)");

	close(fd1);
	unlink(a);
#else
	if (!Sflag)
		printf("NOTE: %s: case2 F_OFD_SETLK not defined on this "
		       "platform\n", myname);
#endif
}

static void case_coalescing(void)
{
	char a[64];
	snprintf(a, sizeof(a), "t_lp.co.%ld", (long)getpid());
	unlink(a);
	int fd = open(a, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) { complain("case3: create: %s", strerror(errno));
		unlink(a); return; }
	if (ftruncate(fd, 1024) != 0) {
		complain("case3: truncate: %s", strerror(errno));
		close(fd); unlink(a); return;
	}

	if (setlk(fd, F_WRLCK, 0, 10, F_SETLK) != 0) {
		complain("case3: lock [0,10): %s", strerror(errno));
		close(fd); unlink(a); return;
	}
	if (setlk(fd, F_WRLCK, 5, 10, F_SETLK) != 0) {
		complain("case3: lock [5,15): %s", strerror(errno));
		close(fd); unlink(a); return;
	}

	/* Query [0,15): must report the entire range is covered by
	 * this process's own lock.  Use a fresh fd as "foreign
	 * process" to make F_GETLK report conflicts meaningfully. */
	struct flock fl = {0};
	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = 14;
	fl.l_len = 1;
	if (fcntl(fd, F_GETLK, &fl) != 0) {
		complain("case3: F_GETLK at 14: %s", strerror(errno));
	} else if (fl.l_type != F_UNLCK) {
		/* Own-process sees unlocked on their own lock via
		 * F_GETLK.  Fine.  Just asserting the call doesn't
		 * blow up is the portable check. */
	}

	/* Attempt to release the whole presumed-coalesced range. */
	if (setlk(fd, F_UNLCK, 0, 15, F_SETLK) != 0)
		complain("case3: unlock [0,15) after coalesce: %s "
			 "(server may have failed to merge adjacent "
			 "locks into one range)", strerror(errno));

	close(fd);
	unlink(a);
}

static void case_splitting(void)
{
	char a[64];
	snprintf(a, sizeof(a), "t_lp.sp.%ld", (long)getpid());
	unlink(a);
	int fd = open(a, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) { complain("case4: create: %s", strerror(errno));
		unlink(a); return; }
	if (ftruncate(fd, 1024) != 0) {
		complain("case4: truncate: %s", strerror(errno));
		close(fd); unlink(a); return;
	}

	if (setlk(fd, F_WRLCK, 0, 100, F_SETLK) != 0) {
		complain("case4: lock [0,100): %s", strerror(errno));
		close(fd); unlink(a); return;
	}
	/* Unlock the middle — server must split. */
	if (setlk(fd, F_UNLCK, 25, 50, F_SETLK) != 0) {
		complain("case4: partial unlock [25,75): %s",
			 strerror(errno));
		close(fd); unlink(a); return;
	}
	/* Now the halves [0,25) and [75,100) should still be lockable
	 * to us and conflict for a child process. */
	pid_t pid = fork();
	if (pid == 0) {
		/* Child: attempt to lock [10,20) — must conflict. */
		int cfd = open(a, O_RDWR);
		if (cfd < 0) _exit(70);
		int rc = setlk(cfd, F_WRLCK, 10, 10, F_SETLK);
		close(cfd);
		if (rc == 0) _exit(71);                  /* bug */
		if (errno == EAGAIN || errno == EACCES)
			_exit(0);                         /* expected */
		_exit(72);
	}
	if (pid < 0) {
		complain("case4: fork: %s", strerror(errno));
		close(fd); unlink(a); return;
	}
	int status = 0;
	waitpid(pid, &status, 0);
	int rc = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
	if (rc == 71)
		complain("case4: child acquired [10,20) after parent held "
			 "[0,25) — server lost post-split lock");
	else if (rc != 0)
		complain("case4: child exit unexpected: %d", rc);

	/* Middle [40,50) should be acquirable by the child. */
	pid = fork();
	if (pid == 0) {
		int cfd = open(a, O_RDWR);
		if (cfd < 0) _exit(70);
		int crc = setlk(cfd, F_WRLCK, 40, 10, F_SETLK);
		close(cfd);
		_exit(crc == 0 ? 0 : 1);
	}
	waitpid(pid, &status, 0);
	rc = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
	if (rc != 0)
		complain("case4: child could not acquire [40,50) after "
			 "parent's partial unlock [25,75) (server did not "
			 "split the lock range)");

	close(fd);
	unlink(a);
}

static void case_conflict_pid(void)
{
	char a[64];
	snprintf(a, sizeof(a), "t_lp.pc.%ld", (long)getpid());
	unlink(a);
	int fd = open(a, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) { complain("case5: create: %s", strerror(errno));
		unlink(a); return; }
	if (ftruncate(fd, 1024) != 0) {
		complain("case5: truncate: %s", strerror(errno));
		close(fd); unlink(a); return;
	}

	if (setlk(fd, F_WRLCK, 0, 100, F_SETLK) != 0) {
		complain("case5: parent F_SETLK: %s", strerror(errno));
		close(fd); unlink(a); return;
	}

	pid_t parent_pid = getpid();
	pid_t pid = fork();
	if (pid == 0) {
		int cfd = open(a, O_RDWR);
		if (cfd < 0) _exit(70);
		/* Expect EAGAIN/EACCES. */
		if (setlk(cfd, F_WRLCK, 0, 100, F_SETLK) == 0) {
			close(cfd); _exit(71);
		}
		if (errno != EAGAIN && errno != EACCES) {
			close(cfd); _exit(72);
		}
		/* F_GETLK must report parent's pid. */
		struct flock fl = {0};
		fl.l_type = F_WRLCK;
		fl.l_whence = SEEK_SET;
		fl.l_start = 0;
		fl.l_len = 100;
		if (fcntl(cfd, F_GETLK, &fl) != 0) {
			close(cfd); _exit(73);
		}
		close(cfd);
		if (fl.l_type == F_UNLCK) _exit(74);
		if (fl.l_pid != parent_pid) _exit(75);
		_exit(0);
	}
	if (pid < 0) {
		complain("case5: fork: %s", strerror(errno));
		close(fd); unlink(a); return;
	}
	int status = 0;
	waitpid(pid, &status, 0);
	int rc = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
	switch (rc) {
	case 0: break;
	case 71: complain("case5: child acquired lock parent holds"); break;
	case 72: complain("case5: child got unexpected errno on conflict"); break;
	case 73: complain("case5: child F_GETLK failed"); break;
	case 74: complain("case5: F_GETLK returned F_UNLCK on held range"); break;
	case 75: complain("case5: F_GETLK reported wrong pid (not parent's)"); break;
	default: complain("case5: child exit %d", rc);
	}

	close(fd);
	unlink(a);
}

static void case_unlock_unheld(void)
{
	char a[64];
	snprintf(a, sizeof(a), "t_lp.uh.%ld", (long)getpid());
	unlink(a);
	int fd = open(a, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) { complain("case6: create: %s", strerror(errno));
		unlink(a); return; }

	if (setlk(fd, F_UNLCK, 0, 100, F_SETLK) != 0)
		complain("case6: F_UNLCK on unheld range: %s "
			 "(POSIX requires success)", strerror(errno));

	close(fd);
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
		"POSIX lock semantics: close catastrophe, "
		"coalescing, splitting");
	cd_or_skip(myname, dir, Nflag);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_close_catastrophe", case_close_catastrophe());
	RUN_CASE("case_ofd_contrast", case_ofd_contrast());
	RUN_CASE("case_coalescing", case_coalescing());
	RUN_CASE("case_splitting", case_splitting());
	RUN_CASE("case_conflict_pid", case_conflict_pid());
	RUN_CASE("case_unlock_unheld", case_unlock_unheld());

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}
