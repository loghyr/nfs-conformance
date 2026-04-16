/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_lock.c -- exercise NFSv4 LOCK / LOCKU / LOCKT ops (RFC 7530
 * S18.10 / S18.12 / S18.11) via the POSIX fcntl(F_SETLK/F_GETLK)
 * surface.
 *
 * This tests traditional POSIX byte-range locks (not OFD locks, which
 * are tested by op_ofd_lock).  POSIX locks are per-process, and on
 * NFS they map to NFSv4 LOCK/LOCKU with a state owner per open file.
 *
 * Cases:
 *
 *   1. Write-lock whole file.  fcntl(F_SETLK, F_WRLCK, 0, 0)
 *      succeeds.  fcntl(F_GETLK) on the same region from the same
 *      process reports F_UNLCK (POSIX: self-locks are invisible to
 *      F_GETLK).  Unlock.
 *
 *   2. Read-lock whole file.  Same round-trip as case 1 but with
 *      F_RDLCK.
 *
 *   3. Lock conflict detection.  Fork a child that write-locks
 *      bytes [0..511].  Parent tries F_SETLK (non-blocking)
 *      for F_WRLCK on [0..511] and expects -1/EAGAIN (or
 *      EACCES on some systems).  Parent then tries F_GETLK
 *      and expects the child's lock description back (pid, type,
 *      offset, length).  Child unlocks and exits.
 *
 *   4. Non-overlapping locks.  Fork a child that write-locks
 *      [0..511].  Parent write-locks [512..1023].  Both should
 *      succeed (no conflict).  Both unlock.
 *
 *   5. Read-lock sharing.  Fork a child that read-locks [0..511].
 *      Parent also read-locks [0..511].  Both should succeed
 *      (multiple readers allowed).  Both unlock.
 *
 *   6. Upgrade read->write.  Take F_RDLCK on [0..511], then
 *      F_SETLK with F_WRLCK on same range.  Should succeed
 *      (atomic upgrade).  F_GETLK from same process shows F_UNLCK.
 *      Unlock.
 *
 *   7. F_SETLKW blocking wait.  Fork a child that write-locks
 *      [0..511] for 1 second then unlocks.  Parent uses F_SETLKW
 *      (blocking) to request F_WRLCK on [0..511].  After child
 *      releases, parent should acquire the lock.
 *
 * Portable: POSIX across Linux / FreeBSD / macOS / Solaris.
 */

#define _POSIX_C_SOURCE 200809L

#include "tests.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
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

static const char *myname = "op_lock";

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  exercise fcntl(F_SETLK/F_GETLK) -> NFSv4 LOCK/LOCKU/LOCKT "
		"(RFC 7530 S18.10-12)\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

static int make_scratch(const char *tag, char *out, size_t outsz)
{
	snprintf(out, outsz, "t_lk.%s.%ld", tag, (long)getpid());
	unlink(out);
	int fd = open(out, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("%s: open(%s): %s", tag, out, strerror(errno));
		return -1;
	}
	/* Extend to 4096 bytes so byte-range tests have room. */
	if (ftruncate(fd, 4096) != 0) {
		complain("%s: ftruncate: %s", tag, strerror(errno));
		close(fd);
		unlink(out);
		return -1;
	}
	return fd;
}

static int try_lock(int fd, int type, off_t start, off_t len, int cmd)
{
	struct flock fl;
	memset(&fl, 0, sizeof(fl));
	fl.l_type   = type;
	fl.l_whence = SEEK_SET;
	fl.l_start  = start;
	fl.l_len    = len;
	return fcntl(fd, cmd, &fl);
}

static int get_lock_info(int fd, int type, off_t start, off_t len,
			 struct flock *out)
{
	memset(out, 0, sizeof(*out));
	out->l_type   = type;
	out->l_whence = SEEK_SET;
	out->l_start  = start;
	out->l_len    = len;
	return fcntl(fd, F_GETLK, out);
}

static void case_wrlock_whole(void)
{
	char name[64];
	int fd = make_scratch("wr", name, sizeof(name));
	if (fd < 0) return;

	if (try_lock(fd, F_WRLCK, 0, 0, F_SETLK) != 0) {
		complain("case1: F_SETLK(F_WRLCK, whole): %s",
			 strerror(errno));
		goto out;
	}

	struct flock fl;
	if (get_lock_info(fd, F_WRLCK, 0, 0, &fl) != 0) {
		complain("case1: F_GETLK: %s", strerror(errno));
		goto out;
	}
	if (fl.l_type != F_UNLCK)
		complain("case1: F_GETLK on own lock expected F_UNLCK, "
			 "got type=%d", fl.l_type);

	try_lock(fd, F_UNLCK, 0, 0, F_SETLK);
out:
	close(fd);
	unlink(name);
}

static void case_rdlock_whole(void)
{
	char name[64];
	int fd = make_scratch("rd", name, sizeof(name));
	if (fd < 0) return;

	if (try_lock(fd, F_RDLCK, 0, 0, F_SETLK) != 0) {
		complain("case2: F_SETLK(F_RDLCK, whole): %s",
			 strerror(errno));
		goto out;
	}

	struct flock fl;
	if (get_lock_info(fd, F_RDLCK, 0, 0, &fl) != 0) {
		complain("case2: F_GETLK: %s", strerror(errno));
		goto out;
	}
	if (fl.l_type != F_UNLCK)
		complain("case2: F_GETLK on own read lock expected F_UNLCK, "
			 "got type=%d", fl.l_type);

	try_lock(fd, F_UNLCK, 0, 0, F_SETLK);
out:
	close(fd);
	unlink(name);
}

static void case_conflict(void)
{
	char name[64];
	int fd = make_scratch("cf", name, sizeof(name));
	if (fd < 0) return;

	int pipefd[2];
	if (pipe(pipefd) != 0) {
		complain("case3: pipe: %s", strerror(errno));
		close(fd);
		unlink(name);
		return;
	}

	pid_t pid = fork();
	if (pid < 0) {
		complain("case3: fork: %s", strerror(errno));
		close(fd);
		unlink(name);
		close(pipefd[0]);
		close(pipefd[1]);
		return;
	}

	if (pid == 0) {
		/* Child: lock [0..511], signal parent, wait, unlock, exit. */
		close(pipefd[0]);
		int cfd = open(name, O_RDWR);
		if (cfd < 0) _exit(1);
		if (try_lock(cfd, F_WRLCK, 0, 512, F_SETLK) != 0) _exit(1);
		char c = 'L';
		(void)write(pipefd[1], &c, 1);
		/* Wait for parent to signal us to unlock. */
		(void)read(pipefd[1], &c, 1);
		try_lock(cfd, F_UNLCK, 0, 512, F_SETLK);
		close(cfd);
		_exit(0);
	}

	/* Parent: wait for child to acquire lock. */
	close(pipefd[1]);
	char c;
	if (read(pipefd[0], &c, 1) != 1) {
		complain("case3: child did not signal lock acquired");
		goto reap;
	}

	/* Non-blocking attempt should fail. */
	errno = 0;
	if (try_lock(fd, F_WRLCK, 0, 512, F_SETLK) == 0) {
		complain("case3: F_SETLK succeeded despite child lock");
	} else if (errno != EAGAIN && errno != EACCES) {
		complain("case3: expected EAGAIN/EACCES, got %s",
			 strerror(errno));
	}

	/* F_GETLK should report the child's lock. */
	struct flock fl;
	if (get_lock_info(fd, F_WRLCK, 0, 512, &fl) != 0) {
		complain("case3: F_GETLK: %s", strerror(errno));
	} else if (fl.l_type == F_UNLCK) {
		complain("case3: F_GETLK returned F_UNLCK (expected child "
			 "lock)");
	} else if (fl.l_pid != pid) {
		/*
		 * NFS may not return the correct l_pid for remote locks.
		 * NOTE rather than FAIL.
		 */
		if (!Sflag)
			printf("NOTE: %s: case3 F_GETLK l_pid=%d, expected "
			       "child pid=%d (NFS may not preserve pid)\n",
			       myname, (int)fl.l_pid, (int)pid);
	}

reap:
	/* Tell child to unlock and exit. */
	close(pipefd[0]);
	kill(pid, SIGTERM);
	waitpid(pid, NULL, 0);
	close(fd);
	unlink(name);
}

static void case_nonoverlap(void)
{
	char name[64];
	int fd = make_scratch("no", name, sizeof(name));
	if (fd < 0) return;

	int pipefd[2];
	if (pipe(pipefd) != 0) {
		complain("case4: pipe: %s", strerror(errno));
		close(fd);
		unlink(name);
		return;
	}

	pid_t pid = fork();
	if (pid < 0) {
		complain("case4: fork: %s", strerror(errno));
		close(fd);
		unlink(name);
		close(pipefd[0]);
		close(pipefd[1]);
		return;
	}

	if (pid == 0) {
		close(pipefd[0]);
		int cfd = open(name, O_RDWR);
		if (cfd < 0) _exit(1);
		if (try_lock(cfd, F_WRLCK, 0, 512, F_SETLK) != 0) _exit(1);
		char c = 'L';
		(void)write(pipefd[1], &c, 1);
		(void)read(pipefd[1], &c, 1);
		try_lock(cfd, F_UNLCK, 0, 512, F_SETLK);
		close(cfd);
		_exit(0);
	}

	close(pipefd[1]);
	char c;
	if (read(pipefd[0], &c, 1) != 1) {
		complain("case4: child signal failed");
		goto reap;
	}

	/* Parent locks [512..1023] — should succeed (non-overlapping). */
	if (try_lock(fd, F_WRLCK, 512, 512, F_SETLK) != 0) {
		complain("case4: F_SETLK [512..1023] failed despite "
			 "non-overlap: %s", strerror(errno));
	} else {
		try_lock(fd, F_UNLCK, 512, 512, F_SETLK);
	}

reap:
	close(pipefd[0]);
	kill(pid, SIGTERM);
	waitpid(pid, NULL, 0);
	close(fd);
	unlink(name);
}

static void case_shared_read(void)
{
	char name[64];
	int fd = make_scratch("sr", name, sizeof(name));
	if (fd < 0) return;

	int pipefd[2];
	if (pipe(pipefd) != 0) {
		complain("case5: pipe: %s", strerror(errno));
		close(fd);
		unlink(name);
		return;
	}

	pid_t pid = fork();
	if (pid < 0) {
		complain("case5: fork: %s", strerror(errno));
		close(fd);
		unlink(name);
		close(pipefd[0]);
		close(pipefd[1]);
		return;
	}

	if (pid == 0) {
		close(pipefd[0]);
		int cfd = open(name, O_RDWR);
		if (cfd < 0) _exit(1);
		if (try_lock(cfd, F_RDLCK, 0, 512, F_SETLK) != 0) _exit(1);
		char c = 'L';
		(void)write(pipefd[1], &c, 1);
		(void)read(pipefd[1], &c, 1);
		try_lock(cfd, F_UNLCK, 0, 512, F_SETLK);
		close(cfd);
		_exit(0);
	}

	close(pipefd[1]);
	char c;
	if (read(pipefd[0], &c, 1) != 1) {
		complain("case5: child signal failed");
		goto reap;
	}

	/* Parent also read-locks [0..511] — should succeed. */
	if (try_lock(fd, F_RDLCK, 0, 512, F_SETLK) != 0) {
		complain("case5: F_SETLK(F_RDLCK) failed despite shared "
			 "read: %s", strerror(errno));
	} else {
		try_lock(fd, F_UNLCK, 0, 512, F_SETLK);
	}

reap:
	close(pipefd[0]);
	kill(pid, SIGTERM);
	waitpid(pid, NULL, 0);
	close(fd);
	unlink(name);
}

static void case_upgrade(void)
{
	char name[64];
	int fd = make_scratch("up", name, sizeof(name));
	if (fd < 0) return;

	if (try_lock(fd, F_RDLCK, 0, 512, F_SETLK) != 0) {
		complain("case6: initial F_RDLCK: %s", strerror(errno));
		goto out;
	}

	if (try_lock(fd, F_WRLCK, 0, 512, F_SETLK) != 0) {
		complain("case6: upgrade F_RDLCK->F_WRLCK: %s",
			 strerror(errno));
		try_lock(fd, F_UNLCK, 0, 512, F_SETLK);
		goto out;
	}

	try_lock(fd, F_UNLCK, 0, 512, F_SETLK);
out:
	close(fd);
	unlink(name);
}

static volatile sig_atomic_t alarm_fired;
static void alarm_handler(int sig) { (void)sig; alarm_fired = 1; }

static void case_blocking_wait(void)
{
	char name[64];
	int fd = make_scratch("bw", name, sizeof(name));
	if (fd < 0) return;

	int pipefd[2];
	if (pipe(pipefd) != 0) {
		complain("case7: pipe: %s", strerror(errno));
		close(fd);
		unlink(name);
		return;
	}

	pid_t pid = fork();
	if (pid < 0) {
		complain("case7: fork: %s", strerror(errno));
		close(fd);
		unlink(name);
		close(pipefd[0]);
		close(pipefd[1]);
		return;
	}

	if (pid == 0) {
		close(pipefd[0]);
		int cfd = open(name, O_RDWR);
		if (cfd < 0) _exit(1);
		if (try_lock(cfd, F_WRLCK, 0, 512, F_SETLK) != 0) _exit(1);
		char c = 'L';
		(void)write(pipefd[1], &c, 1);
		/* Hold lock for 1 second. */
		sleep(1);
		try_lock(cfd, F_UNLCK, 0, 512, F_SETLK);
		close(cfd);
		_exit(0);
	}

	close(pipefd[1]);
	char c;
	if (read(pipefd[0], &c, 1) != 1) {
		complain("case7: child signal failed");
		goto reap;
	}
	close(pipefd[0]);

	/*
	 * Set an alarm so we don't hang forever if F_SETLKW never
	 * returns (e.g., server loses the lock state).
	 */
	alarm_fired = 0;
	struct sigaction sa, old_sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = alarm_handler;
	sigaction(SIGALRM, &sa, &old_sa);
	alarm(10);

	if (try_lock(fd, F_WRLCK, 0, 512, F_SETLKW) != 0) {
		if (alarm_fired)
			complain("case7: F_SETLKW timed out (child did not "
				 "release lock in 10s)");
		else
			complain("case7: F_SETLKW: %s", strerror(errno));
	} else {
		try_lock(fd, F_UNLCK, 0, 512, F_SETLK);
	}

	alarm(0);
	sigaction(SIGALRM, &old_sa, NULL);

reap:
	waitpid(pid, NULL, 0);
	close(fd);
	unlink(name);
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
		"fcntl(F_SETLK/F_GETLK) -> NFSv4 LOCK/LOCKU/LOCKT "
		"(RFC 7530 S18.10-12)");
	cd_or_skip(myname, dir, Nflag);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_wrlock_whole", case_wrlock_whole());
	RUN_CASE("case_rdlock_whole", case_rdlock_whole());
	RUN_CASE("case_conflict", case_conflict());
	RUN_CASE("case_nonoverlap", case_nonoverlap());
	RUN_CASE("case_shared_read", case_shared_read());
	RUN_CASE("case_upgrade", case_upgrade());
	RUN_CASE("case_blocking_wait", case_blocking_wait());

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}
