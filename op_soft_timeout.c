/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_soft_timeout.c -- validate soft-mount error semantics.
 *
 * A soft NFS mount (-o soft, softerr, or softreval) tells the kernel
 * to return an error to the application when the server is unreachable
 * or unresponsive, rather than retrying forever.  The contract is:
 *
 *   - Errors are RETURNED to the caller (ETIMEDOUT, EIO), not silently
 *     dropped or converted to success.
 *   - Normal I/O on an accessible server completes without spurious
 *     ETIMEDOUT.
 *   - Error paths complete promptly (no multi-minute hangs).
 *
 * IMPORTANT: Testing that ETIMEDOUT is returned when the server goes
 * offline requires taking the server down or using iptables to block
 * packets.  That needs root + network control and is out of scope for
 * this binary.  Instead, this test validates the OBSERVABLE properties
 * of a soft mount while the server is accessible:
 *
 *   1. Sanity: I/O succeeds without spurious ETIMEDOUT.
 *   2. ESTALE returns promptly (alarm-bounded, not a hang).
 *   3. fsync completes promptly (alarm-bounded).
 *   4. Error is not silenced: after a known-error op, the error is
 *      visible to the caller.
 *
 * This test auto-detects the "soft", "softerr", or "softreval" mount
 * option via /proc/self/mountinfo.  If none is present, the test
 * skips (unless -f forces it).
 *
 * Cases:
 *
 *   1. Sanity: write 4 KiB, fsync, read back, verify no ETIMEDOUT.
 *      A well-behaved soft mount must not produce spurious errors when
 *      the server is accessible.
 *
 *   2. Deleted-path stat returns promptly.  Create a file, unlink it,
 *      then stat the same name.  ENOENT must arrive within 5 seconds.
 *      Uses SIGALRM + sigsetjmp to catch hangs.
 *
 *   3. fsync completes within a bounded time.  Write 4 KiB, set a 10
 *      second alarm, fsync, cancel the alarm.  A soft mount must not
 *      let fsync block indefinitely when the server is responding.
 *
 *   4. After write error the fd is in an error state.  Force an EBADF by
 *      writing to a closed fd; verify errno is set (not silenced).  This
 *      is a local fd-error case, not an NFS-level error, but ensures
 *      the test infrastructure catches error non-propagation.
 *
 * Portable: Linux (mount option detection).  Cases 1-4 use POSIX I/O.
 * SIGALRM + sigsetjmp used for hang detection (POSIX).
 */

#define _POSIX_C_SOURCE 200809L

#include "tests.h"

#include <errno.h>
#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
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

static const char *myname = "op_soft_timeout";

/* Alarm handling for hang detection. */
static volatile sig_atomic_t alarm_fired;
static sigjmp_buf alarm_jmp;

static void alarm_handler(int sig __attribute__((unused)))
{
	alarm_fired = 1;
	siglongjmp(alarm_jmp, 1);
}

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  validate soft-mount error propagation semantics\n"
		"  -h help  -s silent  -t timing  -f force (skip mount check)\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

/*
 * Case 1: Basic I/O succeeds on a soft mount with an accessible server.
 * A soft mount that returns ETIMEDOUT for normal I/O is misconfigured
 * or the server is down -- complain and surface it.
 */
static void case_sanity_io(void)
{
	char name[64];
	int fd = scratch_open("t_soft.io", name, sizeof(name));

	unsigned char buf[4096];
	fill_pattern(buf, sizeof(buf), 1);

	if (pwrite_all(fd, buf, sizeof(buf), 0, "case1: write 4KiB") != 0) {
		close(fd); unlink(name); return;
	}

	if (fsync(fd) != 0) {
		complain("case1: fsync: %s (spurious error on soft mount "
			 "with accessible server?)", strerror(errno));
		close(fd); unlink(name); return;
	}

	unsigned char rbuf[4096];
	if (pread_all(fd, rbuf, sizeof(rbuf), 0, "case1: read 4KiB") != 0) {
		close(fd); unlink(name); return;
	}

	size_t mis = check_pattern(rbuf, sizeof(rbuf), 1);
	if (mis)
		complain("case1: mismatch at byte %zu (soft-mount I/O "
			 "corruption?)", mis - 1);

	close(fd);
	unlink(name);
}

/*
 * Case 2: stat on a deleted path returns ENOENT promptly (not a hang).
 * On a hard mount, a server unreachable scenario would block here.
 * On a soft mount, the error must come back within the retrans*timeo
 * window.  We use a generous 10-second alarm to catch runaway hangs.
 */
static void case_deleted_path_stat(void)
{
	char name[64];
	snprintf(name, sizeof(name), "t_soft.dp.%ld", (long)getpid());
	unlink(name);  /* ensure absent */

	int fd = open(name, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("case2: create: %s", strerror(errno));
		return;
	}
	close(fd);
	unlink(name);  /* now absent */

	struct sigaction sa, old_sa;
	sa.sa_handler = alarm_handler;
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGALRM, &sa, &old_sa);

	alarm_fired = 0;
	alarm(10);

	int timed_out = sigsetjmp(alarm_jmp, 1);
	if (!timed_out) {
		struct stat st;
		int r = stat(name, &st);
		alarm(0);  /* cancel alarm */
		if (r == 0)
			complain("case2: stat of deleted path returned success "
				 "(expected ENOENT)");
		else if (errno != ENOENT)
			complain("case2: stat: %s (expected ENOENT)",
				 strerror(errno));
		/* ENOENT is correct: deleted path is absent. */
	} else {
		alarm(0);
		complain("case2: stat of deleted path hung for > 10 seconds "
			 "(soft mount should return error promptly)");
	}

	sigaction(SIGALRM, &old_sa, NULL);
}

/*
 * Case 3: fsync completes within 10 seconds on a soft mount.
 * On a hard mount with a down server, fsync can block indefinitely.
 * On a soft mount, it must return (with an error if the server is
 * down, without an error if it is up).
 */
static void case_fsync_bounded(void)
{
	char name[64];
	int fd = scratch_open("t_soft.fs", name, sizeof(name));

	unsigned char buf[4096];
	fill_pattern(buf, sizeof(buf), 3);
	if (pwrite_all(fd, buf, sizeof(buf), 0, "case3: write") != 0) {
		close(fd); unlink(name); return;
	}

	struct sigaction sa, old_sa;
	sa.sa_handler = alarm_handler;
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGALRM, &sa, &old_sa);

	alarm_fired = 0;
	alarm(10);

	int timed_out = sigsetjmp(alarm_jmp, 1);
	if (!timed_out) {
		int r = fsync(fd);
		alarm(0);
		if (r != 0 && errno != ETIMEDOUT && errno != EIO)
			complain("case3: fsync: unexpected error: %s",
				 strerror(errno));
		/*
		 * ETIMEDOUT or EIO here means the server is unresponsive.
		 * That is the correct soft-mount behavior -- but it also
		 * means this machine is not connected to the server right
		 * now.  Log as NOTE rather than FAIL.
		 */
		if (r != 0 && !Sflag)
			printf("NOTE: %s: case3: fsync returned %s "
			       "(server may be inaccessible)\n",
			       myname, strerror(errno));
	} else {
		alarm(0);
		complain("case3: fsync hung for > 10 seconds "
			 "(soft mount should return error, not hang)");
	}

	sigaction(SIGALRM, &old_sa, NULL);
	close(fd);
	unlink(name);
}

/*
 * Case 4: Writing to a closed fd returns EBADF (error is not silenced).
 * This is a local kernel check, not NFS-level, but it validates that
 * the test infrastructure correctly surfaces errno.  On a correctly
 * functioning system, a write to fd -1 or a closed fd must fail.
 */
static void case_error_propagates(void)
{
	/*
	 * Write to a definitely-invalid fd -- must return -1 with
	 * EBADF.  This catches a (hypothetical) implementation that
	 * silently swallows write errors and returns 0 bytes written.
	 *
	 * Use a sentinel -1 rather than a freshly-closed fd: in a
	 * single-threaded context close+write-to-same-number is safe,
	 * but any future addition of a signal handler or pthread that
	 * opens an fd between close() and write() could reuse the
	 * slot and the write would succeed against an unrelated
	 * object -- false PASS of the errno-propagation assertion.
	 */
	int bad_fd = -1;
	unsigned char b = 0xAB;
	ssize_t r = write(bad_fd, &b, 1);
	if (r >= 0)
		complain("case4: write to invalid fd returned %zd "
			 "(expected -1 / EBADF)", r);
	else if (errno != EBADF)
		complain("case4: write to invalid fd: %s (expected EBADF)",
			 strerror(errno));
	/* EBADF: correct. */
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
		"soft-mount error propagation (no spurious ETIMEDOUT, "
		"no hangs, errors returned not silenced)");
	cd_or_skip(myname, dir, Nflag);

	if (!Fflag) {
		int has_soft = mount_has_option("soft");
		int has_softerr = mount_has_option("softerr");
		int has_softreval = mount_has_option("softreval");

		if (has_soft == -1 || has_softerr == -1 ||
		    has_softreval == -1) {
			if (!Sflag)
				printf("NOTE: %s: cannot detect mount options "
				       "on this platform; running anyway\n",
				       myname);
		} else if (has_soft == 0 && has_softerr == 0 &&
			   has_softreval == 0) {
			skip("%s: mount does not have soft/softerr/softreval; "
			     "mount with -o soft to run this test "
			     "(or -f to force)",
			     myname);
		}
	}

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_sanity_io", case_sanity_io());
	RUN_CASE("case_deleted_path_stat", case_deleted_path_stat());
	RUN_CASE("case_fsync_bounded", case_fsync_bounded());
	RUN_CASE("case_error_propagates", case_error_propagates());

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}
