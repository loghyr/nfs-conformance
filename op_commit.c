/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_commit.c -- exercise NFSv4 COMMIT (RFC 7530 S18.3) via fsync(2)
 * and fdatasync(2).
 *
 * Cases:
 *
 *   1. pwrite + fsync, then reopen on a separate fd and re-read.
 *      After fsync returns, any subsequent opener must see the data.
 *      If the client caches writes without driving COMMIT, a reopen
 *      may see stale bytes or a short file.
 *      (POSIX.1-1990 fsync(), S6.6.1)
 *
 *   2. pwrite + fdatasync, then reopen and re-read.  fdatasync may
 *      skip some metadata updates but must flush data blocks; NFSv4
 *      COMMIT flushes data, so this path must behave like case 1.
 *      (POSIX.1b fdatasync(); standardised in POSIX.1-2008 fdatasync())
 *
 *   3. Append-and-flush log pattern: pwrite 1 KiB, fsync, pwrite
 *      another 1 KiB at the next offset, fsync, for 8 rounds total.
 *      Reopen and verify every 1 KiB chunk in order.  Exercises
 *      COMMIT after every WRITE -- worst case for server-side log
 *      commit batching.
 *      (POSIX.1-1990 fsync(), S6.6.1)
 *
 *   4. fsync on an O_RDONLY fd opened after a separate O_WRONLY fd
 *      wrote.  POSIX allows fsync on any fd for a file whose content
 *      has been modified; the NFS client must not reject fsync based
 *      on the fd's open mode.
 *      (POSIX.1-1990 fsync() S6.6.1: fsync applies to the file
 *      referenced by the fd, not to the access mode of the fd)
 *
 *   5. fsync of a zero-byte file: must succeed; tests that COMMIT
 *      does not require preceding WRITEs.
 *      (POSIX.1-1990 fsync(), S6.6.1)
 *
 *   6. fsync after unlink of a hardlink.  Create A, link A -> A_link,
 *      fsync A, unlink A_link, fsync A, close.  Reopen A on a fresh
 *      fd (so the client must LOOKUP+GETATTR against the server) and
 *      verify: A still exists, nlink == 1, A_link absent.  This is
 *      the NFS-reachable equivalent of xfstests generic/039: the
 *      post-fsync invariant "the name-space reflects what fsync
 *      persisted" must hold even after a sibling link was removed.
 *      (POSIX.1-1990 fsync() S6.6.1 + POSIX.1-2008 link()/unlink()
 *      parent-directory update guarantees)
 *
 *   7. fallocate extend + fsync + close + reopen: reads from the
 *      newly-allocated-but-never-written range must return zeros.
 *      Adapts xfstests generic/042's "no stale content exposed after
 *      fallocate + crash" invariant to NFS (crash replaced by
 *      close+reopen which forces a fresh server-side READ).  Skipped
 *      on platforms without fallocate(2) / posix_fallocate(3).
 *
 * Portable: POSIX.1-1990 S6.6.1 (fsync) / POSIX.1-2008 fdatasync()
 * across Linux / FreeBSD / macOS / Solaris.  Case 7 uses
 * posix_fallocate(3) where available.
 */

#define _POSIX_C_SOURCE 200809L

#include "tests.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

int Hflag = 0;
int Sflag = 0;
int Tflag = 0;
int Fflag = 0;
int Nflag = 0;

static const char *myname = "op_commit";

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  exercise fsync/fdatasync -> NFSv4 COMMIT (RFC 7530 S18.3)\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

/* case 1 ---------------------------------------------------------------- */

static void case_fsync_roundtrip(void)
{
	char f[64];
	snprintf(f, sizeof(f), "t_cm.fs.%ld", (long)getpid());
	unlink(f);

	int fd = open(f, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("case1: open: %s", strerror(errno));
		return;
	}

	unsigned char buf[4096];
	fill_pattern(buf, sizeof(buf), 1);
	if (pwrite_all(fd, buf, sizeof(buf), 0, "case1: pwrite") != 0) {
		close(fd); unlink(f); return;
	}
	if (fsync(fd) != 0) {
		complain("case1: fsync: %s", strerror(errno));
		close(fd); unlink(f); return;
	}
	close(fd);

	/* Reopen on a fresh fd; must see all 4 KiB written. */
	fd = open(f, O_RDONLY);
	if (fd < 0) {
		complain("case1: reopen: %s", strerror(errno));
		unlink(f); return;
	}

	unsigned char rbuf[4096];
	if (pread_all(fd, rbuf, sizeof(rbuf), 0, "case1: pread after fsync") != 0) {
		close(fd); unlink(f); return;
	}
	size_t off = check_pattern(rbuf, sizeof(rbuf), 1);
	if (off != 0)
		complain("case1: data mismatch at byte %zu after fsync "
			 "(COMMIT did not persist writes)", off - 1);

	close(fd);
	unlink(f);
}

/* case 2 ---------------------------------------------------------------- */

static void case_fdatasync_roundtrip(void)
{
	char f[64];
	snprintf(f, sizeof(f), "t_cm.fd.%ld", (long)getpid());
	unlink(f);

	int fd = open(f, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("case2: open: %s", strerror(errno));
		return;
	}

	unsigned char buf[4096];
	fill_pattern(buf, sizeof(buf), 2);
	if (pwrite_all(fd, buf, sizeof(buf), 0, "case2: pwrite") != 0) {
		close(fd); unlink(f); return;
	}
	if (fdatasync(fd) != 0) {
		complain("case2: fdatasync: %s", strerror(errno));
		close(fd); unlink(f); return;
	}
	close(fd);

	fd = open(f, O_RDONLY);
	if (fd < 0) {
		complain("case2: reopen: %s", strerror(errno));
		unlink(f); return;
	}

	unsigned char rbuf[4096];
	if (pread_all(fd, rbuf, sizeof(rbuf), 0, "case2: pread after fdatasync") != 0) {
		close(fd); unlink(f); return;
	}
	size_t off = check_pattern(rbuf, sizeof(rbuf), 2);
	if (off != 0)
		complain("case2: data mismatch at byte %zu after fdatasync",
			 off - 1);

	close(fd);
	unlink(f);
}

/* case 3 ---------------------------------------------------------------- */

static void case_log_style(void)
{
	char f[64];
	snprintf(f, sizeof(f), "t_cm.lg.%ld", (long)getpid());
	unlink(f);

	int fd = open(f, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("case3: open: %s", strerror(errno));
		return;
	}

	const size_t chunk = 1024;
	const int rounds = 8;
	unsigned char chunkbuf[1024];
	for (int i = 0; i < rounds; i++) {
		/* Each 1 KiB chunk has seed = i so we can verify order. */
		fill_pattern(chunkbuf, chunk, (unsigned)(3000 + i));
		if (pwrite_all(fd, chunkbuf, chunk,
			       (off_t)(i * (off_t)chunk),
			       "case3: pwrite") != 0) {
			close(fd); unlink(f); return;
		}
		if (fsync(fd) != 0) {
			complain("case3: fsync after round %d: %s", i,
				 strerror(errno));
			close(fd); unlink(f); return;
		}
	}
	close(fd);

	fd = open(f, O_RDONLY);
	if (fd < 0) {
		complain("case3: reopen: %s", strerror(errno));
		unlink(f); return;
	}

	unsigned char rbuf[1024];
	for (int i = 0; i < rounds; i++) {
		if (pread_all(fd, rbuf, chunk,
			      (off_t)(i * (off_t)chunk),
			      "case3: pread chunk") != 0) {
			close(fd); unlink(f); return;
		}
		size_t off = check_pattern(rbuf, chunk, (unsigned)(3000 + i));
		if (off != 0) {
			complain("case3: chunk %d mismatch at byte %zu "
				 "(log-style fsync did not persist round)",
				 i, off - 1);
			break;
		}
	}

	close(fd);
	unlink(f);
}

/* case 4 ---------------------------------------------------------------- */

static void case_fsync_ronly_fd(void)
{
	char f[64];
	snprintf(f, sizeof(f), "t_cm.ro.%ld", (long)getpid());
	unlink(f);

	int wfd = open(f, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (wfd < 0) {
		complain("case4: open W: %s", strerror(errno));
		return;
	}
	unsigned char buf[512];
	fill_pattern(buf, sizeof(buf), 4);
	if (pwrite_all(wfd, buf, sizeof(buf), 0, "case4: pwrite") != 0) {
		close(wfd); unlink(f); return;
	}

	/*
	 * Flush dirty pages via the write fd while the write-mode stateid
	 * is still current.  Some Linux NFS client versions incorrectly
	 * use the O_RDONLY stateid for page writeback triggered by
	 * fsync(rfd) below, causing NFS4ERR_OPENMODE and an infinite
	 * retry loop in the kernel (D-state hang).  Flushing via wfd
	 * first works around this client bug while still testing that
	 * fsync() on an O_RDONLY fd succeeds on NFS.
	 */
	if (fsync(wfd) != 0) {
		complain("case4: fsync wfd: %s", strerror(errno));
		close(wfd); unlink(f); return;
	}

	int rfd = open(f, O_RDONLY);
	if (rfd < 0) {
		complain("case4: open R: %s", strerror(errno));
		close(wfd); unlink(f); return;
	}
	/*
	 * POSIX fsync(2): "The fsync() function shall request that all
	 * data for the open file descriptor named by fildes is to be
	 * transferred to the storage device."  No mode restriction.
	 * With dirty pages already flushed, this sends COMMIT or a no-op.
	 */
	if (fsync(rfd) != 0) {
		complain("case4: fsync on O_RDONLY fd: %s", strerror(errno));
		close(rfd); close(wfd); unlink(f); return;
	}
	close(rfd);
	close(wfd);
	unlink(f);
}

/* case 6 ---------------------------------------------------------------- */

static void case_fsync_after_unlink_hardlink(void)
{
	char a[64], b[64];
	snprintf(a, sizeof(a), "t_cm.hl.%ld", (long)getpid());
	snprintf(b, sizeof(b), "t_cm.hl.%ld.lnk", (long)getpid());
	unlink(a);
	unlink(b);

	int fd = open(a, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("case6: open a: %s", strerror(errno));
		return;
	}

	unsigned char buf[256];
	fill_pattern(buf, sizeof(buf), 6);
	if (pwrite_all(fd, buf, sizeof(buf), 0, "case6: pwrite a") != 0) {
		close(fd); unlink(a); return;
	}
	if (fsync(fd) != 0) {
		complain("case6: fsync a: %s", strerror(errno));
		close(fd); unlink(a); return;
	}

	if (link(a, b) != 0) {
		complain("case6: link a -> b: %s", strerror(errno));
		close(fd); unlink(a); return;
	}
	/*
	 * Now unlink the hardlink.  After this returns, a still exists
	 * (nlink drops 2 -> 1) and b is gone.  fsync(a) must persist
	 * both the unlink of b and the updated nlink of a.
	 */
	if (unlink(b) != 0) {
		complain("case6: unlink b: %s", strerror(errno));
		close(fd); unlink(a); return;
	}
	if (fsync(fd) != 0) {
		complain("case6: fsync after unlink: %s", strerror(errno));
		close(fd); unlink(a); return;
	}
	close(fd);

	/*
	 * Fresh fd forces LOOKUP + GETATTR on the server.  If the client
	 * cached stale dirent state or the server's fsync didn't cover
	 * the parent dir, we'd see either nlink=2, a missing, or b still
	 * there.  All three are bugs.
	 */
	int fd2 = open(a, O_RDONLY);
	if (fd2 < 0) {
		complain("case6: reopen a: %s (fsync did not persist "
			 "the unlink of the sibling link)", strerror(errno));
		unlink(a); return;
	}
	struct stat st;
	if (fstat(fd2, &st) != 0) {
		complain("case6: fstat a: %s", strerror(errno));
	} else if (st.st_nlink != 1) {
		complain("case6: a.nlink=%ld after unlink of b (expected 1)",
			 (long)st.st_nlink);
	}
	close(fd2);

	/* b must be gone. */
	if (access(b, F_OK) == 0) {
		complain("case6: b still present after fsync + reopen "
			 "(unlink not persisted)");
		unlink(b);
	} else if (errno != ENOENT) {
		complain("case6: access(b) unexpected errno: %s",
			 strerror(errno));
	}

	unlink(a);
}

/* case 7 ---------------------------------------------------------------- */

/*
 * posix_fallocate is POSIX.1-2008 but not every libc implements it.
 * Linux glibc and FreeBSD 9+ have it; macOS does not (it offers the
 * non-portable fcntl(F_PREALLOCATE) instead).
 */
#if defined(__linux__) || defined(__FreeBSD__)
# define HAVE_POSIX_FALLOCATE 1
#else
# define HAVE_POSIX_FALLOCATE 0
#endif

static void case_fsync_after_fallocate(void)
{
#if HAVE_POSIX_FALLOCATE
	char f[64];
	snprintf(f, sizeof(f), "t_cm.fa.%ld", (long)getpid());
	unlink(f);

	int fd = open(f, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("case7: open: %s", strerror(errno));
		return;
	}

	const off_t sz = 64 * 1024;
	int r = posix_fallocate(fd, 0, sz);
	if (r != 0) {
		/*
		 * EINVAL / ENOSYS / EOPNOTSUPP from posix_fallocate are
		 * environmental (some filesystems / NFS setups refuse
		 * ALLOCATE).  Skip-as-NOTE rather than FAIL.
		 */
		if (r == EINVAL || r == ENOSYS || r == EOPNOTSUPP) {
			if (!Sflag)
				printf("NOTE: %s: case7 posix_fallocate %s - "
				       "skipping\n", myname, strerror(r));
			close(fd); unlink(f); return;
		}
		complain("case7: posix_fallocate: %s", strerror(r));
		close(fd); unlink(f); return;
	}
	if (fsync(fd) != 0) {
		complain("case7: fsync: %s", strerror(errno));
		close(fd); unlink(f); return;
	}
	close(fd);

	fd = open(f, O_RDONLY);
	if (fd < 0) {
		complain("case7: reopen: %s", strerror(errno));
		unlink(f); return;
	}

	unsigned char *rbuf = malloc((size_t)sz);
	if (!rbuf) {
		complain("case7: malloc");
		close(fd); unlink(f); return;
	}
	if (pread_all(fd, rbuf, (size_t)sz, 0,
		      "case7: pread allocated range") == 0) {
		if (!all_zero(rbuf, (size_t)sz))
			complain("case7: stale content in "
				 "fallocate-but-never-written range "
				 "(server exposed uninitialised disk bytes)");
	}
	free(rbuf);
	close(fd);
	unlink(f);
#else
	if (!Sflag)
		printf("NOTE: %s: case7 posix_fallocate unavailable - "
		       "skipping\n", myname);
#endif
}

/* case 5 ---------------------------------------------------------------- */

static void case_fsync_empty(void)
{
	char f[64];
	snprintf(f, sizeof(f), "t_cm.em.%ld", (long)getpid());
	unlink(f);

	int fd = open(f, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("case5: open: %s", strerror(errno));
		return;
	}
	if (fsync(fd) != 0)
		complain("case5: fsync on empty file: %s", strerror(errno));
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
		"fsync/fdatasync -> NFSv4 COMMIT (RFC 7530 S18.3)");
	cd_or_skip(myname, dir, Nflag);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_fsync_roundtrip", case_fsync_roundtrip());
	RUN_CASE("case_fdatasync_roundtrip", case_fdatasync_roundtrip());
	RUN_CASE("case_log_style", case_log_style());
	RUN_CASE("case_fsync_ronly_fd", case_fsync_ronly_fd());
	RUN_CASE("case_fsync_empty", case_fsync_empty());
	RUN_CASE("case_fsync_after_unlink_hardlink",
		 case_fsync_after_unlink_hardlink());
	RUN_CASE("case_fsync_after_fallocate",
		 case_fsync_after_fallocate());

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}
