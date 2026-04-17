/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_flock.c -- exercise flock(2), the BSD advisory lock model.
 *
 * Three lock models intersect on an NFS client:
 *
 *   - POSIX fcntl F_SETLK locks (exercised by op_lock / op_lock_posix).
 *     Owner = process; byte-range scoped; released when ANY fd
 *     referring to the file is closed.
 *   - OFD locks (exercised by op_ofd_lock).  Owner = fd; byte-range
 *     scoped; released only when the specific fd is closed.
 *   - flock(2) BSD locks.  Owner = open file description; whole-file
 *     scoped; released when the file description is closed.  Shared
 *     by dup'd fds; independent of fcntl locks on the same file.
 *
 * flock is NFS-visible on Linux where NFSv4 servers expose it over
 * the wire (or the client converts it to a fcntl-compat lock,
 * depending on kernel config).  On FreeBSD the NFS client translates
 * flock into the same NLM/NFSv4 lock path used for fcntl locks, so
 * the third-model distinction matters less, but the tests still
 * catch lock-path regressions.
 *
 * Cases:
 *
 *   1. Exclusive lock on a regular file (LOCK_EX).  Succeeds on a
 *      freshly-opened fd.  LOCK_UN releases cleanly.
 *
 *   2. Shared locks stack (LOCK_SH).  Two fds from this process can
 *      both hold LOCK_SH concurrently without blocking.  The first
 *      fd's LOCK_UN does not release the second's lock.
 *
 *   3. Exclusive-vs-shared conflict (LOCK_EX | LOCK_NB).  A second
 *      fd trying LOCK_EX while the first holds LOCK_SH must fail
 *      with EWOULDBLOCK when LOCK_NB is set.  A second fd trying
 *      LOCK_SH must succeed.
 *
 *   4. Dup'd fds share the lock state (LOCK_EX + dup + LOCK_UN on
 *      dup).  flock owner is the open file description, not the
 *      fd, so LOCK_UN via the dup releases the original's lock.
 *      This is the property that distinguishes flock from OFD
 *      locks cleanly.
 *
 *   5. Close releases.  LOCK_EX held on fd1; close(fd1); a second
 *      fd2 opened fresh must then be able to acquire LOCK_EX.
 *      Tests the cleanup path that NFS servers sometimes lose
 *      when the client forgets to send UNLOCK on close.
 *
 *   6. flock vs fcntl interaction.  POSIX does not mandate that
 *      flock(2) and fcntl(F_SETLK) share a lock space, but many
 *      systems (and NFS client implementations) blur the line.
 *      Exercise the common-confusion path: acquire flock(LOCK_EX)
 *      on fd_a, then try fcntl(F_SETLK, F_WRLCK, whole file) on
 *      fd_b.  Record whichever outcome -- the two lock models are
 *      separate (fcntl succeeds), unified (fcntl blocks/EAGAINs),
 *      or one is unimplemented over NFS (ENOLCK/EOPNOTSUPP).  The
 *      test only asserts that the operation TERMINATES -- a hang
 *      or a spurious error outside the expected set is the real
 *      bug.  Gemini-flagged gap: "common source of client-side
 *      emulation bugs over NFS".
 *
 * Platform:
 *   Linux / FreeBSD / macOS: flock(2) available natively.
 *   Solaris: flock is a BSD-compat convenience; semantics match.
 */

/*
 * Feature-test gating for flock(2):
 *   - Linux glibc: _DEFAULT_SOURCE from the Makefile is enough.
 *   - macOS: requires _DARWIN_C_SOURCE (flock is a BSD extension
 *     that strict _POSIX_C_SOURCE hides).
 *   - FreeBSD: flock lives under __BSD_VISIBLE in <sys/file.h>,
 *     which the Makefile's _XOPEN_SOURCE=700 disables.
 */
#if defined(__APPLE__)
# define _DARWIN_C_SOURCE 1
#endif
#if defined(__FreeBSD__)
# define __BSD_VISIBLE 1
#endif

#include "tests.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/file.h>     /* flock(2), LOCK_* */
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

int Hflag = 0;
int Sflag = 0;
int Tflag = 0;
int Fflag = 0;
int Nflag = 0;

static const char *myname = "op_flock";

static char fl_name[64];

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  exercise flock(2) advisory locking (BSD model)\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

static int open_rw(const char *path, const char *ctx)
{
	int fd = open(path, O_RDWR);
	if (fd < 0)
		complain("%s: open %s: %s", ctx, path, strerror(errno));
	return fd;
}

static void case_exclusive_lock(void)
{
	int fd = open_rw(fl_name, "case1");
	if (fd < 0) return;
	if (flock(fd, LOCK_EX) != 0) {
		if (errno == ENOLCK || errno == EOPNOTSUPP) {
			close(fd);
			skip("%s: flock returned %s -- NFS lock manager "
			     "unavailable or flock not supported on this mount",
			     myname, strerror(errno));
		}
		complain("case1: LOCK_EX: %s", strerror(errno));
		close(fd);
		return;
	}
	if (flock(fd, LOCK_UN) != 0)
		complain("case1: LOCK_UN: %s", strerror(errno));
	close(fd);
}

static void case_shared_stack(void)
{
	int a = open_rw(fl_name, "case2a");
	int b = open_rw(fl_name, "case2b");
	if (a < 0 || b < 0) {
		if (a >= 0) close(a);
		if (b >= 0) close(b);
		return;
	}
	if (flock(a, LOCK_SH) != 0) {
		complain("case2: LOCK_SH fd A: %s", strerror(errno));
		close(a); close(b);
		return;
	}
	if (flock(b, LOCK_SH) != 0) {
		complain("case2: LOCK_SH fd B alongside A: %s "
			 "(shared locks must stack)", strerror(errno));
		flock(a, LOCK_UN);
		close(a); close(b);
		return;
	}
	/*
	 * Release A.  B's lock must still be held.  A fresh LOCK_EX
	 * attempt via a third fd must fail with EWOULDBLOCK.
	 */
	if (flock(a, LOCK_UN) != 0)
		complain("case2: LOCK_UN fd A: %s", strerror(errno));

	int c = open_rw(fl_name, "case2c");
	if (c >= 0) {
		errno = 0;
		int rc = flock(c, LOCK_EX | LOCK_NB);
		if (rc == 0) {
			complain("case2: LOCK_EX via C succeeded while B "
				 "still holds LOCK_SH (B's lock was "
				 "erroneously released when A unlocked)");
			flock(c, LOCK_UN);
		} else if (errno != EWOULDBLOCK && errno != EAGAIN) {
			complain("case2: LOCK_EX NB expected EWOULDBLOCK, "
				 "got %s", strerror(errno));
		}
		close(c);
	}

	if (flock(b, LOCK_UN) != 0)
		complain("case2: LOCK_UN fd B: %s", strerror(errno));
	close(a);
	close(b);
}

static void case_exclusive_shared_conflict(void)
{
	int a = open_rw(fl_name, "case3a");
	int b = open_rw(fl_name, "case3b");
	if (a < 0 || b < 0) {
		if (a >= 0) close(a);
		if (b >= 0) close(b);
		return;
	}
	if (flock(a, LOCK_EX) != 0) {
		complain("case3: LOCK_EX fd A: %s", strerror(errno));
		close(a); close(b);
		return;
	}
	/* Second fd tries LOCK_EX with NB -- must fail EWOULDBLOCK. */
	errno = 0;
	if (flock(b, LOCK_EX | LOCK_NB) == 0) {
		complain("case3: LOCK_EX via B succeeded while A holds "
			 "LOCK_EX (exclusive locks must not stack)");
		flock(b, LOCK_UN);
	} else if (errno != EWOULDBLOCK && errno != EAGAIN) {
		complain("case3: LOCK_EX NB expected EWOULDBLOCK, got %s",
			 strerror(errno));
	}
	/* Second fd tries LOCK_SH with NB -- must also fail. */
	errno = 0;
	if (flock(b, LOCK_SH | LOCK_NB) == 0) {
		complain("case3: LOCK_SH via B succeeded while A holds "
			 "LOCK_EX (SH must block on held EX)");
		flock(b, LOCK_UN);
	} else if (errno != EWOULDBLOCK && errno != EAGAIN) {
		complain("case3: LOCK_SH NB expected EWOULDBLOCK, got %s",
			 strerror(errno));
	}
	if (flock(a, LOCK_UN) != 0)
		complain("case3: LOCK_UN fd A: %s", strerror(errno));
	close(a);
	close(b);
}

static void case_dup_shares_lock_state(void)
{
	int fd = open_rw(fl_name, "case4");
	if (fd < 0) return;
	if (flock(fd, LOCK_EX) != 0) {
		complain("case4: LOCK_EX: %s", strerror(errno));
		close(fd);
		return;
	}
	int dupfd = dup(fd);
	if (dupfd < 0) {
		complain("case4: dup: %s", strerror(errno));
		flock(fd, LOCK_UN);
		close(fd);
		return;
	}
	/*
	 * flock owner is the open file description.  LOCK_UN via the
	 * dup must release the lock; a subsequent LOCK_EX via a freshly-
	 * opened fd must succeed with LOCK_NB.
	 */
	if (flock(dupfd, LOCK_UN) != 0) {
		complain("case4: LOCK_UN via dup: %s", strerror(errno));
		close(dupfd);
		close(fd);
		return;
	}
	close(dupfd);

	int other = open_rw(fl_name, "case4-other");
	if (other < 0) {
		close(fd);
		return;
	}
	errno = 0;
	if (flock(other, LOCK_EX | LOCK_NB) != 0) {
		complain("case4: LOCK_EX after dup's LOCK_UN failed with %s "
			 "(dup did not release the shared open-file "
			 "description's lock)",
			 strerror(errno));
	} else {
		flock(other, LOCK_UN);
	}
	close(other);
	close(fd);
}

static void case_close_releases(void)
{
	int fd = open_rw(fl_name, "case5");
	if (fd < 0) return;
	if (flock(fd, LOCK_EX) != 0) {
		complain("case5: LOCK_EX: %s", strerror(errno));
		close(fd);
		return;
	}
	/*
	 * Close without explicit LOCK_UN.  The server-side lock must
	 * be released as part of close; a fresh LOCK_EX must then
	 * succeed.  NFS servers that don't receive or process UNLOCK
	 * on close fail here.
	 */
	close(fd);

	int other = open_rw(fl_name, "case5-other");
	if (other < 0) return;
	errno = 0;
	if (flock(other, LOCK_EX | LOCK_NB) != 0) {
		complain("case5: LOCK_EX after close returned %s "
			 "(close did not release the flock -- NFS "
			 "client/server lost the UNLOCK on close)",
			 strerror(errno));
	} else {
		flock(other, LOCK_UN);
	}
	close(other);
}

static void case_flock_vs_fcntl(void)
{
	int fa = open_rw(fl_name, "case6a");
	int fb = open_rw(fl_name, "case6b");
	if (fa < 0 || fb < 0) {
		if (fa >= 0) close(fa);
		if (fb >= 0) close(fb);
		return;
	}

	if (flock(fa, LOCK_EX) != 0) {
		if (errno == ENOLCK || errno == EOPNOTSUPP) {
			close(fa); close(fb);
			skip("%s: flock returned %s; lock manager or flock "
			     "routing unavailable", myname, strerror(errno));
		}
		complain("case6: LOCK_EX via flock: %s", strerror(errno));
		close(fa); close(fb);
		return;
	}

	/*
	 * Try fcntl(F_SETLK, F_WRLCK, whole file) on a SECOND fd.
	 * Legal outcomes on this invocation:
	 *   - succeed (0): flock and fcntl use disjoint lock spaces
	 *     (BSD + some Linux configs).
	 *   - fail EAGAIN / EACCES: unified lock space; fcntl saw the
	 *     flock as a conflict.
	 *   - fail ENOLCK / EOPNOTSUPP: lock manager for one or the
	 *     other isn't running over this mount.
	 * Anything else is a bug (usually "hang" or "wrong errno" from
	 * a broken client-side emulation).
	 */
	struct flock fl;
	memset(&fl, 0, sizeof(fl));
	fl.l_type   = F_WRLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start  = 0;
	fl.l_len    = 0; /* whole file */

	errno = 0;
	int rc = fcntl(fb, F_SETLK, &fl);
	int saved = errno;
	if (rc == 0) {
		if (!Sflag)
			printf("NOTE: %s: case6 fcntl F_WRLCK succeeded while "
			       "fd_a holds flock(LOCK_EX) -- disjoint lock "
			       "spaces (BSD model)\n", myname);
		/* Release. */
		fl.l_type = F_UNLCK;
		fcntl(fb, F_SETLK, &fl);
	} else if (saved == EAGAIN || saved == EACCES) {
		if (!Sflag)
			printf("NOTE: %s: case6 fcntl F_WRLCK blocked by the "
			       "flock -- unified lock space (Linux-style)\n",
			       myname);
	} else if (saved == ENOLCK || saved == EOPNOTSUPP) {
		if (!Sflag)
			printf("NOTE: %s: case6 fcntl F_WRLCK returned %s -- "
			       "fcntl locks not routed over this mount\n",
			       myname, strerror(saved));
	} else {
		complain("case6: fcntl F_WRLCK after flock(LOCK_EX) returned "
			 "unexpected errno %s (expected success, EAGAIN/EACCES, "
			 "or ENOLCK/EOPNOTSUPP)", strerror(saved));
	}

	flock(fa, LOCK_UN);
	close(fa);
	close(fb);
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

	prelude(myname, "flock(2) BSD advisory locking over NFS");
	cd_or_skip(myname, dir, Nflag);

	int fd = scratch_open("t_flock", fl_name, sizeof(fl_name));
	close(fd); /* we only need the name; each case opens fresh fds. */

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_exclusive_lock",
		 case_exclusive_lock());
	RUN_CASE("case_shared_stack",
		 case_shared_stack());
	RUN_CASE("case_exclusive_shared_conflict",
		 case_exclusive_shared_conflict());
	RUN_CASE("case_dup_shares_lock_state",
		 case_dup_shares_lock_state());
	RUN_CASE("case_close_releases",
		 case_close_releases());
	RUN_CASE("case_flock_vs_fcntl",
		 case_flock_vs_fcntl());

	unlink(fl_name);

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}
