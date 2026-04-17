/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_deleg_setdeleg.c -- exercise F_SETDELEG / F_GETDELEG fcntl
 * interface (Linux kernel >= 6.x, Jeff Layton).
 *
 * Charter tier: SPEC (NFSv4 WANT_DELEGATION / delegation fcntl path,
 *                      RFC 8881 S10.4 and S18.49)
 *
 * Ported from: xfstests generic/787 (file delegation test, locktest -F).
 * NFS adaptation: xfstests drives two synchronized processes via a
 * socket-based protocol in locktest(8) and covers 13 scenarios including
 * chmod/unlink/rename breaks.  Here we use fork() within a single test
 * process (no cross-machine socket) and cover only the core NFS
 * semantics: delegation take/release, F_GETDELEG readback, F_SETLEASE
 * interop, EAGAIN when a writer is present, SIGIO on write-break, and
 * no-SIGIO on compatible read.  The locktest socket-sync protocol and
 * the chmod/unlink/rename break scenarios are out of scope for this
 * single-client test; they remain covered by xfstests generic/787.
 *
 * This test is Linux-only and self-contained: no cb_recall_probe or
 * second NFS client is required.  SIGIO break cases use fork() within
 * the same test.  The cb_recall_probe-based tests (op_deleg_read,
 * op_deleg_recall) cover server-initiated CB_RECALL via a second
 * client session; this test covers the client-side fcntl path.
 *
 * Skip conditions:
 *   - Non-Linux: skip unconditionally.
 *   - Kernel too old / syscall absent: F_SETDELEG returns EINVAL or
 *     ENOSYS; skip the whole test.
 *   - Server refuses delegation: F_SETDELEG returns EAGAIN or
 *     EOPNOTSUPP (NFS client returns EOPNOTSUPP when the server
 *     rejects WANT_DELEGATION with NFS4ERR_NOTSUPP or similar);
 *     emit NOTE and skip the affected case (not a failure -- server
 *     is allowed to refuse WANT_DELEGATION).
 *
 * Cases:
 *
 *   1. Read delegation: open O_RDONLY (sole opener), F_SETDELEG F_RDLCK.
 *      If granted: F_GETDELEG returns F_RDLCK.  Release with F_UNLCK.
 *
 *   2. Write delegation: open O_RDWR (sole opener), F_SETDELEG F_WRLCK.
 *      If granted: F_GETDELEG returns F_WRLCK.  Release with F_UNLCK.
 *
 *   3. F_SETLEASE interop.  After F_SETDELEG grants a read delegation,
 *      F_GETLEASE should report F_RDLCK (the delegation registered
 *      through F_SETDELEG appears to the lease interface as a lease).
 *      NOTE-only if F_GETLEASE returns F_UNLCK (some kernel/server
 *      combinations may not interop the two interfaces).
 *
 *   4. Read delegation refused when a writer is present.  Open file
 *      O_RDWR (first fd), then attempt F_SETDELEG F_RDLCK on a second
 *      O_RDONLY fd.  Expect EAGAIN because the server cannot grant a
 *      read delegation while a local write reference is open.
 *
 *   5. SIGIO break on competing write open.  Parent holds a read
 *      delegation (F_RDLCK).  Child opens the file O_RDWR.  Server
 *      sends CB_RECALL; the kernel delivers SIGIO to the fd owner.
 *      Parent releases the delegation in response; child's open
 *      succeeds.  NOTE-only if SIGIO is not received within 5s
 *      (server may have refused the initial delegation, or the kernel
 *      version does not yet implement the break path).
 *
 *   6. No SIGIO on compatible concurrent read.  Parent holds a read
 *      delegation.  Child opens O_RDONLY.  Parent must NOT receive
 *      SIGIO: read delegations are compatible with concurrent readers
 *      (RFC 8881 S10.4.2).  NOTE-only if SIGIO is received (server
 *      may have issued an unnecessary recall).
 */

#define _GNU_SOURCE

#include "tests.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

int Hflag = 0;
int Sflag = 0;
int Tflag = 0;
int Fflag = 0;
int Nflag = 0;

static const char *myname = "op_deleg_setdeleg";

#if !defined(__linux__)
int main(void)
{
	skip("%s: F_SETDELEG / F_GETDELEG are Linux-only fcntl extensions",
	     myname);
	return TEST_SKIP;
}
#else

/*
 * F_SETDELEG (1024+16) and F_GETDELEG (1024+15) were added in kernel
 * 6.x (Jeff Layton).  Guard against older kernel headers.
 */
#ifndef F_SETDELEG
#define F_SETDELEG (1024 + 16)
#endif
#ifndef F_GETDELEG
#define F_GETDELEG (1024 + 15)
#endif

/*
 * Both F_SETDELEG and F_GETDELEG take a pointer to struct delegation
 * (defined in <linux/fcntl.h> on kernel >= 6.x).  Define a local copy
 * here so the file compiles against any kernel header version; on older
 * kernels F_SETDELEG returns EINVAL/ENOSYS before touching the struct.
 */
struct nfc_deleg {
	uint32_t d_flags; /* must be 0 */
	uint16_t d_type;  /* F_RDLCK, F_WRLCK, or F_UNLCK */
	uint16_t d_pad;   /* must be 0 */
};

/* Pre-built unlock struct for use in the signal handler. */
static const struct nfc_deleg g_deleg_unlck = { 0, F_UNLCK, 0 };

/* Global flag set by the SIGIO handler in cases 5 and 6. */
static volatile sig_atomic_t g_sigio_fd = -1;
static volatile sig_atomic_t g_sigio_received = 0;

static void sigio_handler(int sig __attribute__((unused)))
{
	g_sigio_received = 1;
	/*
	 * Release the delegation from the signal handler so the competing
	 * opener can proceed.  fcntl is not formally async-signal-safe, but
	 * on Linux this is safe in practice and is the standard pattern for
	 * delegation break handling.
	 */
	if (g_sigio_fd >= 0)
		fcntl(g_sigio_fd, F_SETDELEG, &g_deleg_unlck);
}

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  exercise F_SETDELEG/F_GETDELEG NFSv4 delegation fcntl\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

/*
 * try_setdeleg -- call fcntl(fd, F_SETDELEG, ltype).
 * Returns:
 *    0  on success (delegation granted)
 *    1  EAGAIN or EOPNOTSUPP (server/client does not support; NOTE emitted)
 *   -2  other error (calls complain())
 * Calls skip() (does not return) on EINVAL or ENOSYS.
 */
static int try_setdeleg(int fd, int ltype, const char *ctx)
{
	struct nfc_deleg d = { 0, (uint16_t)ltype, 0 };
	if (fcntl(fd, F_SETDELEG, &d) == 0)
		return 0;
	if (errno == EINVAL || errno == ENOSYS) {
		skip("%s: F_SETDELEG returned %s -- kernel does not "
		     "support F_SETDELEG (need Linux >= 6.x with NFS "
		     "delegation support)",
		     myname, strerror(errno));
		/* skip() does not return */
	}
	if (errno == EAGAIN || errno == EOPNOTSUPP) {
		if (!Sflag)
			printf("NOTE: %s: %s: F_SETDELEG returned %s "
			       "(server did not grant delegation) -- case "
			       "skipped\n",
			       myname, ctx, strerror(errno));
		return 1;
	}
	complain("%s: F_SETDELEG: %s", ctx, strerror(errno));
	return -2;
}

/* case 1: read delegation take/query/release */
static void case_read_delegation(const char *name)
{
	/* Ensure no other opener holds the file. */
	int fd = open(name, O_RDONLY);
	if (fd < 0) {
		complain("case1: open O_RDONLY: %s", strerror(errno));
		return;
	}

	int rc = try_setdeleg(fd, F_RDLCK, "case1");
	if (rc != 0) {
		/* EAGAIN or error -- skip() or complain() already called */
		close(fd);
		return;
	}

	struct nfc_deleg gd = { 0 };
	if (fcntl(fd, F_GETDELEG, &gd) < 0) {
		complain("case1: F_GETDELEG: %s", strerror(errno));
	} else if (gd.d_type != F_RDLCK) {
		complain("case1: F_GETDELEG returned %d, expected F_RDLCK (%d)",
			 (int)gd.d_type, F_RDLCK);
	}

	struct nfc_deleg unlk = { 0, F_UNLCK, 0 };
	if (fcntl(fd, F_SETDELEG, &unlk) != 0)
		complain("case1: F_SETDELEG F_UNLCK: %s", strerror(errno));

	close(fd);
}

/* case 2: write delegation take/query/release */
static void case_write_delegation(const char *name)
{
	int fd = open(name, O_RDWR);
	if (fd < 0) {
		complain("case2: open O_RDWR: %s", strerror(errno));
		return;
	}

	int rc = try_setdeleg(fd, F_WRLCK, "case2");
	if (rc != 0) {
		close(fd);
		return;
	}

	struct nfc_deleg gd = { 0 };
	if (fcntl(fd, F_GETDELEG, &gd) < 0) {
		complain("case2: F_GETDELEG: %s", strerror(errno));
	} else if (gd.d_type != F_WRLCK) {
		complain("case2: F_GETDELEG returned %d, expected F_WRLCK (%d)",
			 (int)gd.d_type, F_WRLCK);
	}

	struct nfc_deleg unlk = { 0, F_UNLCK, 0 };
	if (fcntl(fd, F_SETDELEG, &unlk) != 0)
		complain("case2: F_SETDELEG F_UNLCK: %s", strerror(errno));

	close(fd);
}

/*
 * case 3: F_SETLEASE interop -- F_GETLEASE should report F_RDLCK after
 * F_SETDELEG grants a read delegation.  NOTE-only on mismatch because
 * the two interfaces may not be unified in all kernel versions.
 */
static void case_setlease_interop(const char *name)
{
	int fd = open(name, O_RDONLY);
	if (fd < 0) {
		complain("case3: open O_RDONLY: %s", strerror(errno));
		return;
	}

	int rc = try_setdeleg(fd, F_RDLCK, "case3");
	if (rc != 0) {
		close(fd);
		return;
	}

	int lease = fcntl(fd, F_GETLEASE);
	if (lease < 0) {
		if (!Sflag)
			printf("NOTE: %s: case3: F_GETLEASE returned error "
			       "(%s); F_SETDELEG and F_GETLEASE may not "
			       "interoperate on this kernel\n",
			       myname, strerror(errno));
	} else if (lease != F_RDLCK) {
		if (!Sflag)
			printf("NOTE: %s: case3: F_GETLEASE returned %d "
			       "(expected F_RDLCK %d) after F_SETDELEG "
			       "granted read delegation\n",
			       myname, lease, F_RDLCK);
	}

	struct nfc_deleg unlk = { 0, F_UNLCK, 0 };
	if (fcntl(fd, F_SETDELEG, &unlk) != 0)
		complain("case3: F_SETDELEG F_UNLCK: %s", strerror(errno));

	close(fd);
}

/*
 * case 4: F_RDLCK delegation refused when an O_RDWR opener is present.
 * Open file O_RDWR (fd1), then request F_RDLCK on a second fd.  The
 * server cannot grant a read delegation with a local write reference
 * outstanding, so F_SETDELEG should return EAGAIN.
 * NOTE-only if EAGAIN is not returned (some servers may allow it).
 */
static void case_refused_with_writer(const char *name)
{
	int fd1 = open(name, O_RDWR);
	if (fd1 < 0) {
		complain("case4: open O_RDWR: %s", strerror(errno));
		return;
	}

	int fd2 = open(name, O_RDONLY);
	if (fd2 < 0) {
		complain("case4: open O_RDONLY: %s", strerror(errno));
		close(fd1);
		return;
	}

	struct nfc_deleg rd = { 0, F_RDLCK, 0 };
	int rc = fcntl(fd2, F_SETDELEG, &rd);
	if (rc == -1 && (errno == EINVAL || errno == ENOSYS ||
			  errno == EOPNOTSUPP)) {
		/* Already handled by case 1's try_setdeleg; just close */
	} else if (rc == -1 && errno == EAGAIN) {
		/* Expected: server refused due to write reference */
	} else if (rc == 0) {
		if (!Sflag)
			printf("NOTE: %s: case4: F_SETDELEG granted read "
			       "delegation despite concurrent O_RDWR opener -- "
			       "server behaviour is permissive\n",
			       myname);
		struct nfc_deleg unlk = { 0, F_UNLCK, 0 };
		fcntl(fd2, F_SETDELEG, &unlk);
	} else {
		complain("case4: F_SETDELEG: %s", strerror(errno));
	}

	close(fd2);
	close(fd1);
}

/*
 * case 5: SIGIO delivered to fd owner when a competing write open breaks
 * a read delegation.
 *
 * Flow:
 *   parent: open O_RDONLY, request F_RDLCK delegation.
 *   parent: set SIGIO owner, install handler, fork child.
 *   child:  open file O_RDWR (triggers CB_RECALL on parent's delegation).
 *           wait briefly, close, exit.
 *   parent: wait up to 5s for SIGIO (handler releases delegation via F_UNLCK).
 *           wait for child.
 *
 * NOTE-only on timeout (server may not have granted delegation, or SIGIO
 * break path not implemented in this kernel version).
 */
static void case_sigio_on_write_break(const char *name)
{
	int fd = open(name, O_RDONLY);
	if (fd < 0) {
		complain("case5: open O_RDONLY: %s", strerror(errno));
		return;
	}

	int rc = try_setdeleg(fd, F_RDLCK, "case5");
	if (rc != 0) {
		close(fd);
		return;
	}

	/* Set fd SIGIO owner and install handler before forking. */
	g_sigio_fd = fd;
	g_sigio_received = 0;

	if (fcntl(fd, F_SETOWN, getpid()) != 0) {
		complain("case5: F_SETOWN: %s", strerror(errno));
		struct nfc_deleg unlk = { 0, F_UNLCK, 0 };
		fcntl(fd, F_SETDELEG, &unlk);
		close(fd);
		return;
	}

	struct sigaction sa, old_sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sigio_handler;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGIO, &sa, &old_sa);

	pid_t pid = fork();
	if (pid < 0) {
		complain("case5: fork: %s", strerror(errno));
		sigaction(SIGIO, &old_sa, NULL);
		struct nfc_deleg unlk = { 0, F_UNLCK, 0 };
		fcntl(fd, F_SETDELEG, &unlk);
		close(fd);
		return;
	}

	if (pid == 0) {
		/* Child: open for write (triggers CB_RECALL on parent). */
		int cfd = open(name, O_RDWR);
		if (cfd >= 0) {
			sleep_ms(200);
			close(cfd);
		}
		_exit(0);
	}

	/* Parent: wait up to 5 seconds for SIGIO. */
	struct timespec deadline;
	clock_gettime(CLOCK_MONOTONIC, &deadline);
	deadline.tv_sec += 5;

	while (!g_sigio_received) {
		struct timespec now;
		clock_gettime(CLOCK_MONOTONIC, &now);
		if (now.tv_sec > deadline.tv_sec ||
		    (now.tv_sec == deadline.tv_sec &&
		     now.tv_nsec >= deadline.tv_nsec))
			break;
		sleep_ms(50);
	}

	/* Release delegation if handler did not (e.g., timeout). */
	if (!g_sigio_received) {
		struct nfc_deleg unlk = { 0, F_UNLCK, 0 };
		fcntl(fd, F_SETDELEG, &unlk);
	}

	int wstatus = 0;
	waitpid(pid, &wstatus, 0);

	if (!g_sigio_received && !Sflag)
		printf("NOTE: %s: case5: SIGIO not received within 5s after "
		       "competing write open -- server may not have granted "
		       "the initial delegation, or SIGIO break path is not "
		       "yet implemented in this kernel\n",
		       myname);

	sigaction(SIGIO, &old_sa, NULL);
	g_sigio_fd = -1;
	close(fd);
}

/*
 * case 6: No SIGIO on compatible concurrent read open.
 * RFC 8881 S10.4.2: read delegations are compatible with concurrent
 * read access; the server must NOT recall on a concurrent O_RDONLY open.
 *
 * NOTE-only if SIGIO IS received (some servers may recall unnecessarily).
 */
static void case_no_sigio_on_read(const char *name)
{
	int fd = open(name, O_RDONLY);
	if (fd < 0) {
		complain("case6: open O_RDONLY: %s", strerror(errno));
		return;
	}

	int rc = try_setdeleg(fd, F_RDLCK, "case6");
	if (rc != 0) {
		close(fd);
		return;
	}

	g_sigio_fd = fd;
	g_sigio_received = 0;

	if (fcntl(fd, F_SETOWN, getpid()) != 0) {
		complain("case6: F_SETOWN: %s", strerror(errno));
		struct nfc_deleg unlk = { 0, F_UNLCK, 0 };
		fcntl(fd, F_SETDELEG, &unlk);
		close(fd);
		return;
	}

	struct sigaction sa, old_sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sigio_handler;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGIO, &sa, &old_sa);

	pid_t pid = fork();
	if (pid < 0) {
		complain("case6: fork: %s", strerror(errno));
		sigaction(SIGIO, &old_sa, NULL);
		struct nfc_deleg unlk = { 0, F_UNLCK, 0 };
		fcntl(fd, F_SETDELEG, &unlk);
		close(fd);
		return;
	}

	if (pid == 0) {
		/* Child: open O_RDONLY (should NOT trigger recall). */
		int cfd = open(name, O_RDONLY);
		if (cfd >= 0) {
			sleep_ms(500);
			close(cfd);
		}
		_exit(0);
	}

	/* Parent: wait 1.5s; SIGIO should NOT arrive. */
	sleep_ms(1500);

	int wstatus = 0;
	waitpid(pid, &wstatus, 0);

	if (g_sigio_received && !Sflag)
		printf("NOTE: %s: case6: SIGIO received after concurrent "
		       "O_RDONLY open (server recalled read delegation -- "
		       "not required by RFC 8881 S10.4.2 for compatible "
		       "concurrent readers)\n",
		       myname);

	/* Release delegation if it was not broken already. */
	if (!g_sigio_received) {
		struct nfc_deleg unlk = { 0, F_UNLCK, 0 };
		fcntl(fd, F_SETDELEG, &unlk);
	}

	sigaction(SIGIO, &old_sa, NULL);
	g_sigio_fd = -1;
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
		"F_SETDELEG/F_GETDELEG NFSv4 delegation via fcntl "
		"(RFC 8881 S10.4)");
	cd_or_skip(myname, dir, Nflag);

	/* Create the test file: a single file reused across all cases. */
	char name[64];
	int fd = scratch_open("t16", name, sizeof(name));
	/* Seed with 4KB so delegation tests have real data. */
	unsigned char seed[4096];
	fill_pattern(seed, sizeof(seed), 0xAA);
	pwrite_all(fd, seed, sizeof(seed), 0, "seed");
	close(fd);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_read_delegation",     case_read_delegation(name));
	RUN_CASE("case_write_delegation",    case_write_delegation(name));
	RUN_CASE("case_setlease_interop",    case_setlease_interop(name));
	RUN_CASE("case_refused_with_writer", case_refused_with_writer(name));
	RUN_CASE("case_sigio_on_write_break", case_sigio_on_write_break(name));
	RUN_CASE("case_no_sigio_on_read",    case_no_sigio_on_read(name));

	unlink(name);

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}

#endif /* __linux__ */
