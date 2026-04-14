/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * op_rename_atomic.c -- exercise the renameat2(2) atomicity flags,
 * which map to NFSv4 RENAME with specific server-side semantics:
 *
 *   RENAME_NOREPLACE : fail with EEXIST if the target exists; do
 *                      not overwrite.  Server must check existence
 *                      and apply the rename atomically.
 *
 *   RENAME_EXCHANGE  : atomically swap two existing names.  The
 *                      NFS protocol has no direct "exchange" op;
 *                      the client issues a sequence the server must
 *                      execute under a lock.  Older servers return
 *                      EINVAL; we SKIP case 2 in that case.
 *
 * Cases:
 *
 *   1a. RENAME_NOREPLACE to nonexistent target: success.
 *   1b. RENAME_NOREPLACE to existing target: EEXIST.  Source and
 *       target contents both unchanged.
 *
 *   2a. RENAME_EXCHANGE of two existing files: atomic swap.  After
 *       the call, file-A-name holds file-B's contents and vice versa.
 *       If the server returns EINVAL / ENOTSUP, skip this case
 *       (not all NFSv4.2 servers support EXCHANGE).
 *
 *   3. Both flags on a single call: EINVAL (mutually exclusive).
 *
 *   4. RENAME_NOREPLACE with neither source present: ENOENT.
 *
 * Linux-only: renameat2 is a Linux-specific syscall; glibc wraps
 * it from 2.28 onward.
 */

#define _GNU_SOURCE

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

static const char *myname = "op_rename_atomic";

#if !defined(__linux__)
int main(void)
{
	skip("%s: renameat2(2) is Linux-specific", myname);
	return TEST_SKIP;
}
#else

#include <linux/fs.h> /* RENAME_NOREPLACE, RENAME_EXCHANGE */

#if !defined(RENAME_NOREPLACE) || !defined(RENAME_EXCHANGE)
int main(void)
{
	skip("%s: RENAME_NOREPLACE / RENAME_EXCHANGE not defined", myname);
	return TEST_SKIP;
}
#else

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  exercise renameat2 -> NFSv4 RENAME (atomic flags)\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

/*
 * write_tiny -- create path with content "body\n", verifying the
 * short write completes.  Used by every case to seed files.
 */
static int write_tiny(const char *path, const char *body)
{
	int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("open(%s) for write: %s", path, strerror(errno));
		return -1;
	}
	size_t n = strlen(body);
	int rc = pwrite_all(fd, body, n, 0, path);
	close(fd);
	return rc;
}

/*
 * read_all -- read up to `cap-1` bytes from path into buf, NUL-
 * terminate, return the byte count.  -1 on failure.
 */
static ssize_t read_all(const char *path, char *buf, size_t cap)
{
	int fd = open(path, O_RDONLY);
	if (fd < 0) {
		complain("open(%s) for read: %s", path, strerror(errno));
		return -1;
	}
	ssize_t n = read(fd, buf, cap - 1);
	close(fd);
	if (n < 0) {
		complain("read(%s): %s", path, strerror(errno));
		return -1;
	}
	buf[n] = '\0';
	return n;
}

/*
 * feature_probe_noreplace -- try a no-op rename with RENAME_NOREPLACE;
 * if the kernel or server returns EINVAL / ENOSYS / ENOTSUP, the flag
 * is not supported over this mount (common on Linux NFS clients with
 * kernel < 6.1 where the client doesn't pass flags through) and the
 * whole test SKIPs cleanly.  This must run before case_noreplace_*
 * so that case-level failure logic doesn't false-alarm on the gap.
 */
static void feature_probe_noreplace(void)
{
	char src[64], dst[64];
	snprintf(src, sizeof(src), "t_rn.probe.a.%ld", (long)getpid());
	snprintf(dst, sizeof(dst), "t_rn.probe.b.%ld", (long)getpid());
	unlink(src); unlink(dst);

	if (write_tiny(src, "probe\n") < 0) {
		complain("feature_probe: write: %s", strerror(errno));
		return;
	}

	if (renameat2(AT_FDCWD, src, AT_FDCWD, dst, RENAME_NOREPLACE) == 0) {
		/* Supported.  Clean up the probe file (now at dst). */
		unlink(dst);
		return;
	}

	int saved = errno;
	unlink(src);
	unlink(dst);
	if (saved == EINVAL || saved == ENOSYS || saved == ENOTSUP) {
		skip("%s: renameat2 RENAME_NOREPLACE not supported "
		     "by this kernel/server (returned %s); Linux NFS "
		     "client needs ~6.1+ for flag passthrough",
		     myname, strerror(saved));
	}
	complain("feature_probe: unexpected errno %s", strerror(saved));
}

static void case_noreplace_to_empty(void)
{
	char src[64], dst[64];
	snprintf(src, sizeof(src), "t_rn.a.%ld", (long)getpid());
	snprintf(dst, sizeof(dst), "t_rn.b.%ld", (long)getpid());
	unlink(src); unlink(dst);

	if (write_tiny(src, "AAA\n") < 0) return;

	if (renameat2(AT_FDCWD, src, AT_FDCWD, dst, RENAME_NOREPLACE) != 0) {
		complain("case1a: renameat2 NOREPLACE to empty: %s",
			 strerror(errno));
		unlink(src);
		unlink(dst);
		return;
	}

	char buf[32];
	if (read_all(dst, buf, sizeof(buf)) < 0 || strcmp(buf, "AAA\n") != 0)
		complain("case1a: post-rename content wrong (got %s)",
			 buf);
	if (access(src, F_OK) == 0)
		complain("case1a: source still exists after rename");

	unlink(dst);
}

static void case_noreplace_collision(void)
{
	char src[64], dst[64];
	snprintf(src, sizeof(src), "t_rn.a.%ld", (long)getpid());
	snprintf(dst, sizeof(dst), "t_rn.b.%ld", (long)getpid());
	unlink(src); unlink(dst);

	if (write_tiny(src, "AAA\n") < 0) return;
	if (write_tiny(dst, "BBB\n") < 0) { unlink(src); return; }

	errno = 0;
	int rc = renameat2(AT_FDCWD, src, AT_FDCWD, dst, RENAME_NOREPLACE);
	if (rc == 0) {
		complain("case1b: renameat2 NOREPLACE unexpectedly "
			 "succeeded when target exists");
	} else if (errno != EEXIST) {
		complain("case1b: expected EEXIST, got %s", strerror(errno));
	}

	/* Source and target contents should both be unchanged. */
	char a[32], b[32];
	if (read_all(src, a, sizeof(a)) < 0 || strcmp(a, "AAA\n") != 0)
		complain("case1b: source corrupted after failed NOREPLACE "
			 "(got %s)",
			 a);
	if (read_all(dst, b, sizeof(b)) < 0 || strcmp(b, "BBB\n") != 0)
		complain("case1b: target corrupted after failed NOREPLACE "
			 "(got %s)",
			 b);

	unlink(src);
	unlink(dst);
}

static void case_exchange(void)
{
	char src[64], dst[64];
	snprintf(src, sizeof(src), "t_rx.a.%ld", (long)getpid());
	snprintf(dst, sizeof(dst), "t_rx.b.%ld", (long)getpid());
	unlink(src); unlink(dst);

	if (write_tiny(src, "source\n") < 0) return;
	if (write_tiny(dst, "target\n") < 0) { unlink(src); return; }

	errno = 0;
	int rc = renameat2(AT_FDCWD, src, AT_FDCWD, dst, RENAME_EXCHANGE);
	if (rc != 0) {
		/*
		 * Not every NFS server implements atomic EXCHANGE.
		 * NOTE rather than FAIL for ENOSYS / ENOTSUP / EINVAL
		 * on the assumption that EINVAL here usually means the
		 * kernel or server lacks EXCHANGE support rather than
		 * a bad call (the call shape is correct).
		 */
		if (errno == ENOSYS || errno == ENOTSUP || errno == EINVAL) {
			if (!Sflag)
				printf("NOTE: %s: case2 RENAME_EXCHANGE "
				       "returned %s (server/kernel may not "
				       "support atomic exchange)\n",
				       myname, strerror(errno));
			unlink(src);
			unlink(dst);
			return;
		}
		complain("case2: renameat2 EXCHANGE: %s", strerror(errno));
		unlink(src);
		unlink(dst);
		return;
	}

	char a[32], b[32];
	if (read_all(src, a, sizeof(a)) < 0 || strcmp(a, "target\n") != 0)
		complain("case2: after swap, src holds %s (expected "
			 "target)",
			 a);
	if (read_all(dst, b, sizeof(b)) < 0 || strcmp(b, "source\n") != 0)
		complain("case2: after swap, dst holds %s (expected "
			 "source)",
			 b);

	unlink(src);
	unlink(dst);
}

static void case_both_flags(void)
{
	char src[64], dst[64];
	snprintf(src, sizeof(src), "t_rn.c.%ld", (long)getpid());
	snprintf(dst, sizeof(dst), "t_rn.d.%ld", (long)getpid());
	unlink(src); unlink(dst);

	if (write_tiny(src, "x\n") < 0) return;
	if (write_tiny(dst, "y\n") < 0) { unlink(src); return; }

	errno = 0;
	int rc = renameat2(AT_FDCWD, src, AT_FDCWD, dst,
			   RENAME_NOREPLACE | RENAME_EXCHANGE);
	if (rc == 0)
		complain("case3: renameat2 with both NOREPLACE and "
			 "EXCHANGE unexpectedly succeeded");
	else if (errno != EINVAL)
		complain("case3: expected EINVAL, got %s", strerror(errno));

	unlink(src);
	unlink(dst);
}

static void case_missing_source(void)
{
	char src[64], dst[64];
	snprintf(src, sizeof(src), "t_rn.missing.%ld", (long)getpid());
	snprintf(dst, sizeof(dst), "t_rn.e.%ld", (long)getpid());

	errno = 0;
	int rc = renameat2(AT_FDCWD, src, AT_FDCWD, dst, RENAME_NOREPLACE);
	if (rc == 0) {
		complain("case4: renameat2 from nonexistent source "
			 "succeeded");
		unlink(dst);
	} else if (errno != ENOENT) {
		complain("case4: expected ENOENT, got %s", strerror(errno));
	}
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
		"renameat2 atomic flags -> NFSv4 RENAME semantics");
	cd_or_skip(myname, dir, Nflag);

	feature_probe_noreplace();

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	case_noreplace_to_empty();
	case_noreplace_collision();
	case_exchange();
	case_both_flags();
	case_missing_source();

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}

#endif /* RENAME_NOREPLACE / RENAME_EXCHANGE */
#endif /* __linux__ */
