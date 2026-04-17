/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_direct_io.c -- exercise O_DIRECT per-open cache-bypass on NFS.
 *
 * O_DIRECT is a per-open flag (not a mount option) that asks the
 * NFS client to bypass its page cache for this file descriptor.
 * Writes go straight to the server; reads pull fresh data from the
 * server.  It is the primary alternative to mount-level cache
 * bypass (-o noac / -o lookupcache=none).
 *
 * Cases:
 *
 *   1. O_DIRECT open succeeds.  Some NFS configurations refuse it
 *      (EINVAL); treat as NOTE rather than FAIL.
 *
 *   2. Aligned round-trip.  posix_memalign a 4 KiB buffer, write it
 *      via O_DIRECT, read it back (via fresh buffered fd, to avoid
 *      O_DIRECT read-alignment quirks on the verify path), verify
 *      byte-for-byte.
 *
 *   3. Cross-fd visibility.  Writer opens O_DIRECT, writes a pattern.
 *      Reader opens a *separate* buffered fd (after the writer's
 *      write but before its close) and reads.  On NFS the O_DIRECT
 *      write has already hit the server, so the reader's open does
 *      a GETATTR and its read should pull the fresh data.  This is
 *      the core coherence semantic of O_DIRECT on NFS.
 *
 *   4. Unaligned I/O behavior.  Write a 1000-byte stack buffer.
 *      Linux historically returns EINVAL on block devices; NFS is
 *      typically more permissive.  Record whichever outcome as a
 *      NOTE rather than asserting.
 *
 *   5. Large I/O.  Write 4 * 4 KiB via O_DIRECT, close, reopen
 *      buffered, read back, verify.  Exercises the path where a
 *      single O_DIRECT write crosses multiple wsize chunks.
 *
 *   6. Failed write must not expose stale content.  Seed the file
 *      with pattern A (4 KiB, persisted), then issue an O_DIRECT
 *      write with an intentionally-unaligned buffer that the kernel
 *      is expected to reject (EINVAL).  Reopen and verify the file
 *      still reads back as pattern A.  Inspired by xfstests
 *      generic/250, which used dm-error to force a mid-transaction
 *      failure; NFS has no dm layer, so we exercise the weaker but
 *      still meaningful invariant that a rejected write must be
 *      all-or-nothing, never a partial update that exposes a
 *      mixture of old and new bytes.
 *
 * Platform:
 *   Linux   : O_DIRECT from <fcntl.h> with _GNU_SOURCE.
 *   macOS   : no O_DIRECT; F_NOCACHE has different (advisory)
 *             semantics — not the same contract.  Test skips.
 *   Others  : test skips.
 */

#if defined(__linux__)
# define _GNU_SOURCE
#endif

#include "tests.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifdef O_DIRECT
# define HAVE_O_DIRECT 1
#else
# define HAVE_O_DIRECT 0
#endif

int Hflag = 0;
int Sflag = 0;
int Tflag = 0;
int Fflag = 0;
int Nflag = 0;

static const char *myname = "op_direct_io";

#define DIO_ALIGN 4096U
#define DIO_SIZE  4096U

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  exercise O_DIRECT per-open cache-bypass on NFS\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

#if HAVE_O_DIRECT

static void *aligned_alloc_or_null(size_t size)
{
	void *p = NULL;
	if (posix_memalign(&p, DIO_ALIGN, size) != 0)
		return NULL;
	return p;
}

static void case_direct_open(void)
{
	char a[64];
	snprintf(a, sizeof(a), "t_dio.op.%ld", (long)getpid());
	unlink(a);

	int fd = open(a, O_RDWR | O_CREAT | O_DIRECT, 0644);
	if (fd < 0) {
		if (errno == EINVAL) {
			if (!Sflag)
				printf("NOTE: %s: case1 server/client refuses "
				       "O_DIRECT (EINVAL) — some NFS "
				       "configurations reject it\n", myname);
		} else {
			complain("case1: open O_DIRECT: %s", strerror(errno));
		}
		unlink(a);
		return;
	}
	close(fd);
	unlink(a);
}

static void case_direct_round_trip(void)
{
	char a[64];
	snprintf(a, sizeof(a), "t_dio.rt.%ld", (long)getpid());
	unlink(a);

	void *buf = aligned_alloc_or_null(DIO_SIZE);
	if (!buf) {
		complain("case2: posix_memalign: %s", strerror(errno));
		return;
	}
	memset(buf, 0xAB, DIO_SIZE);

	int fd = open(a, O_RDWR | O_CREAT | O_DIRECT, 0644);
	if (fd < 0) {
		if (errno == EINVAL) {
			if (!Sflag)
				printf("NOTE: %s: case2 O_DIRECT refused, "
				       "skipping\n", myname);
		} else {
			complain("case2: open O_DIRECT: %s", strerror(errno));
		}
		free(buf);
		unlink(a);
		return;
	}

	ssize_t w = write(fd, buf, DIO_SIZE);
	close(fd);
	if (w != (ssize_t)DIO_SIZE) {
		complain("case2: write: %zd / %u: %s",
			 w, DIO_SIZE, strerror(errno));
		free(buf);
		unlink(a);
		return;
	}

	int rfd = open(a, O_RDONLY);
	if (rfd < 0) {
		complain("case2: reopen: %s", strerror(errno));
		free(buf);
		unlink(a);
		return;
	}
	unsigned char *verify = malloc(DIO_SIZE);
	if (!verify) {
		complain("case2: malloc verify");
		close(rfd); free(buf); unlink(a); return;
	}
	ssize_t r = read(rfd, verify, DIO_SIZE);
	close(rfd);
	if (r != (ssize_t)DIO_SIZE) {
		complain("case2: read: %zd / %u: %s",
			 r, DIO_SIZE, strerror(errno));
	} else if (memcmp(verify, buf, DIO_SIZE) != 0) {
		complain("case2: data mismatch after O_DIRECT write + "
			 "buffered read");
	}

	free(verify);
	free(buf);
	unlink(a);
}

static void case_direct_cross_visibility(void)
{
	char a[64];
	snprintf(a, sizeof(a), "t_dio.cv.%ld", (long)getpid());
	unlink(a);

	void *buf = aligned_alloc_or_null(DIO_SIZE);
	if (!buf) {
		complain("case3: posix_memalign: %s", strerror(errno));
		return;
	}
	memset(buf, 0x5A, DIO_SIZE);

	int wfd = open(a, O_RDWR | O_CREAT | O_DIRECT, 0644);
	if (wfd < 0) {
		if (errno == EINVAL) {
			if (!Sflag)
				printf("NOTE: %s: case3 O_DIRECT refused, "
				       "skipping\n", myname);
		} else {
			complain("case3: open O_DIRECT: %s", strerror(errno));
		}
		free(buf);
		unlink(a);
		return;
	}

	ssize_t w = write(wfd, buf, DIO_SIZE);
	if (w != (ssize_t)DIO_SIZE) {
		complain("case3: write: %zd: %s", w, strerror(errno));
		close(wfd);
		free(buf);
		unlink(a);
		return;
	}

	/*
	 * Fresh reader fd before the writer closes.  The writer's
	 * O_DIRECT write has already reached the server, so the
	 * reader's open-time GETATTR sees the current size and the
	 * first read pulls the bytes.
	 */
	int rfd = open(a, O_RDONLY);
	if (rfd < 0) {
		complain("case3: reader open: %s", strerror(errno));
		close(wfd);
		free(buf);
		unlink(a);
		return;
	}
	unsigned char *verify = malloc(DIO_SIZE);
	if (!verify) {
		complain("case3: malloc verify");
		close(rfd); close(wfd); free(buf); unlink(a); return;
	}
	ssize_t r = read(rfd, verify, DIO_SIZE);
	close(rfd);
	close(wfd);

	if (r != (ssize_t)DIO_SIZE) {
		complain("case3: reader saw short read %zd (O_DIRECT data "
			 "not visible to fresh reader fd)", r);
	} else if (memcmp(verify, buf, DIO_SIZE) != 0) {
		complain("case3: reader saw stale data (O_DIRECT write not "
			 "reflected server-side before reader's open)");
	}

	free(verify);
	free(buf);
	unlink(a);
}

static void case_direct_unaligned(void)
{
	char a[64];
	snprintf(a, sizeof(a), "t_dio.un.%ld", (long)getpid());
	unlink(a);

	int fd = open(a, O_RDWR | O_CREAT | O_DIRECT, 0644);
	if (fd < 0) {
		if (errno == EINVAL) {
			if (!Sflag)
				printf("NOTE: %s: case4 O_DIRECT refused, "
				       "skipping\n", myname);
		} else {
			complain("case4: open O_DIRECT: %s", strerror(errno));
		}
		unlink(a);
		return;
	}

	char buf[1000];
	memset(buf, 0xC3, sizeof(buf));
	errno = 0;
	ssize_t w = write(fd, buf, sizeof(buf));
	if (w < 0) {
		if (errno != EINVAL && !Sflag)
			printf("NOTE: %s: case4 unaligned O_DIRECT write "
			       "returned %s (Linux block devices typically "
			       "return EINVAL)\n", myname, strerror(errno));
	} else if (!Sflag) {
		printf("NOTE: %s: case4 unaligned O_DIRECT write accepted "
		       "(%zd bytes) — NFS is typically more permissive than "
		       "block devices about alignment\n", myname, w);
	}
	close(fd);
	unlink(a);
}

static void case_direct_large(void)
{
	char a[64];
	snprintf(a, sizeof(a), "t_dio.lg.%ld", (long)getpid());
	unlink(a);

	const size_t sz = DIO_SIZE * 4;
	void *buf = aligned_alloc_or_null(sz);
	if (!buf) {
		complain("case5: posix_memalign: %s", strerror(errno));
		return;
	}
	for (size_t i = 0; i < sz; i++)
		((unsigned char *)buf)[i] = (unsigned char)(i & 0xFF);

	int fd = open(a, O_RDWR | O_CREAT | O_DIRECT, 0644);
	if (fd < 0) {
		if (errno == EINVAL) {
			if (!Sflag)
				printf("NOTE: %s: case5 O_DIRECT refused, "
				       "skipping\n", myname);
		} else {
			complain("case5: open O_DIRECT: %s", strerror(errno));
		}
		free(buf);
		unlink(a);
		return;
	}
	ssize_t w = write(fd, buf, sz);
	close(fd);
	if (w != (ssize_t)sz) {
		complain("case5: write: %zd / %zu: %s",
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
	void *vbuf = malloc(sz);
	if (!vbuf) {
		complain("case5: malloc: %s", strerror(errno));
		close(rfd);
		free(buf);
		unlink(a);
		return;
	}
	ssize_t r = read(rfd, vbuf, sz);
	close(rfd);
	if (r != (ssize_t)sz)
		complain("case5: read: %zd / %zu: %s",
			 r, sz, strerror(errno));
	else if (memcmp(vbuf, buf, sz) != 0)
		complain("case5: large O_DIRECT round-trip data mismatch");

	free(buf);
	free(vbuf);
	unlink(a);
}

static void case_failed_write_no_stale_data(void)
{
	char a[64];
	snprintf(a, sizeof(a), "t_dio.st.%ld", (long)getpid());
	unlink(a);

	void *aligned = aligned_alloc_or_null(DIO_SIZE);
	if (!aligned) {
		complain("case6: posix_memalign: %s", strerror(errno));
		return;
	}
	fill_pattern(aligned, DIO_SIZE, 0xA5A5);

	/* Phase 1: seed pattern A via O_DIRECT, persist, close. */
	int fd = open(a, O_RDWR | O_CREAT | O_DIRECT, 0644);
	if (fd < 0) {
		if (errno == EINVAL) {
			if (!Sflag)
				printf("NOTE: %s: case6 O_DIRECT refused, "
				       "skipping\n", myname);
		} else {
			complain("case6: open O_DIRECT: %s", strerror(errno));
		}
		free(aligned);
		unlink(a);
		return;
	}
	if (pwrite_all(fd, aligned, DIO_SIZE, 0,
		       "case6: seed pattern A") != 0) {
		close(fd); free(aligned); unlink(a); return;
	}
	if (fsync(fd) != 0) {
		complain("case6: fsync: %s", strerror(errno));
		close(fd); free(aligned); unlink(a); return;
	}
	close(fd);

	/*
	 * Phase 2: attempt an O_DIRECT write that the kernel should
	 * reject.  A 1000-byte write from an unaligned stack buffer
	 * typically fails with EINVAL on Linux; some NFS setups accept
	 * it.  Either way, the next reopen+read must still show
	 * pattern A (never a partial overwrite).
	 */
	fd = open(a, O_RDWR | O_DIRECT);
	if (fd < 0) {
		complain("case6: reopen O_DIRECT: %s", strerror(errno));
		free(aligned);
		unlink(a);
		return;
	}
	char bad[1000];
	memset(bad, 0x5A, sizeof(bad));
	errno = 0;
	ssize_t n = pwrite(fd, bad, sizeof(bad), 0);
	int saved = errno;
	close(fd);

	/* Phase 3: buffered reopen, verify pattern A is intact. */
	int rfd = open(a, O_RDONLY);
	if (rfd < 0) {
		complain("case6: buffered reopen: %s", strerror(errno));
		free(aligned);
		unlink(a);
		return;
	}
	unsigned char *rbuf = malloc(DIO_SIZE);
	if (!rbuf) {
		complain("case6: malloc");
		close(rfd); free(aligned); unlink(a); return;
	}
	if (pread_all(rfd, rbuf, DIO_SIZE, 0,
		      "case6: read after pwrite attempt") == 0) {
		size_t miss = check_pattern(rbuf, DIO_SIZE, 0xA5A5);
		/*
		 * Two legal outcomes:
		 *   (a) pwrite returned -1: file content must be
		 *       unchanged (the integrity invariant from
		 *       xfstests generic/250).  miss != 0 here is the
		 *       real bug -- partial update after a rejected
		 *       write.
		 *   (b) pwrite returned >= 0: the kernel accepted the
		 *       unaligned write (common on NFS, which is more
		 *       permissive than block devices).  Any content
		 *       mutation is expected and not a finding.
		 */
		if (n < 0) {
			if (miss)
				complain("case6: pattern A corrupted at "
					 "byte %zu after pwrite returned "
					 "-1/%s (rejected write must be "
					 "all-or-nothing, not a partial "
					 "update)",
					 miss - 1, strerror(saved));
		} else if (!Sflag) {
			printf("NOTE: %s: case6 unaligned O_DIRECT pwrite "
			       "accepted (%zd bytes); content mutation is "
			       "expected -- NFS is permissive about "
			       "alignment\n", myname, n);
		}
	}
	free(rbuf);
	close(rfd);
	free(aligned);
	unlink(a);
}

#endif /* HAVE_O_DIRECT */

int main(int argc, char **argv)
{
	const char *dir = ".";

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
		"O_DIRECT per-open cache-bypass on NFS");
	cd_or_skip(myname, dir, Nflag);

#if !HAVE_O_DIRECT
	skip("%s: O_DIRECT not available on this platform "
	     "(macOS has F_NOCACHE with different semantics)", myname);
#else
	struct timespec t0, t1;
	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_direct_open", case_direct_open());
	RUN_CASE("case_direct_round_trip", case_direct_round_trip());
	RUN_CASE("case_direct_cross_visibility", case_direct_cross_visibility());
	RUN_CASE("case_direct_unaligned", case_direct_unaligned());
	RUN_CASE("case_direct_large", case_direct_large());
	RUN_CASE("case_failed_write_no_stale_data",
		 case_failed_write_no_stale_data());

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
#endif
}
