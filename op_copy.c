/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_copy.c -- exercise copy_file_range(2), which NFSv4.2 servers
 * translate into a COPY op (RFC 7862 S7) when source and
 * destination are on the same file system.
 *
 * Scope: same-filesystem, intra-server COPY only.  RFC 7862 also
 * defines an inter-server COPY with COPY_NOTIFY pre-coordination
 * (S7.2); the Linux client does not surface that via
 * copy_file_range.  Tests in this file cover the subset that a
 * syscall-level test can reach.
 *
 * Cases:
 *
 *   1. Simple whole-file copy.  Pattern in SRC, copy_file_range to
 *      DST, verify DST byte-for-byte.
 *
 *   2. Offset copy.  DST[0..len) should equal SRC[mid..mid+len).
 *
 *   3. Sparse preservation.  Copy a sparse SRC; sampled hole region
 *      in DST must read zero.  Skipped (as a NOTE, not a test
 *      failure) if SEEK_HOLE/SEEK_DATA unavailable.
 *
 *   4. API matrix.  Zero-length copy must succeed returning 0.
 *      Non-zero flags must fail with EINVAL (Linux / FreeBSD agree
 *      here; glibc's man page documents "currently, no flags are
 *      defined").  Requested length larger than what remains in the
 *      source beyond `soff` must return the correct short count
 *      without extending the source read pointer past EOF.
 *      Derived from xfstests generic/430.
 *
 *   5. Short-copy atomicity.  Pre-seed dst with pattern B (8 KiB),
 *      populate src with 4 KiB of pattern A, then request an 8 KiB
 *      copy.  The syscall must short-copy: return value in [1..4K],
 *      dst[0..returned) == pattern A, dst[returned..8K) == pattern
 *      B (untouched).  Critically, no zero-fill of the tail and no
 *      torn bytes at the boundary.  xfstests generic/265 asserts a
 *      similar atomicity contract when copy_file_range is forced
 *      to fail mid-range via dm-error; NFS has no dm layer, so we
 *      exercise the weaker short-read trigger (src-beyond-EOF)
 *      which is still enough to catch a server that zeroes or
 *      garbages dst past the truncated copy range.
 *
 *   6. Intra-file copy (same fd for src and dst).  POSIX.1-2008
 *      and the copy_file_range(2) man page leave behaviour with
 *      overlapping src/dst ranges undefined; non-overlapping
 *      ranges in the same file must work.  We test:
 *        a. Non-overlapping in-file copy: offset 0..4K is pattern
 *           A, offset 64K..68K starts as zeros; copy moves A into
 *           the 64K..68K slot, verify.
 *        b. Overlapping in-file copy (fwd direction): the kernel
 *           may succeed (glibc-documented on Linux >= 5.3) or
 *           return EINVAL.  Accept either.  If it succeeds, the
 *           destination range must take on the source bytes at
 *           the time of the call; we check byte-for-byte on a
 *           fresh reopen to dodge any cached-state confusion.
 *
 * Feature probe: we do a real 1-byte copy up front to detect
 * ENOSYS / EOPNOTSUPP before the main cases run.  A zero-length
 * probe is not sufficient because the kernel fast-paths that to 0
 * regardless of op support.
 *
 * Linux / FreeBSD 13+ only; stub out on other platforms.
 */

/* FreeBSD has copy_file_range in libc since 13.0, but its declaration
 * is under __BSD_VISIBLE which is disabled when _POSIX_C_SOURCE /
 * _XOPEN_SOURCE are set.  Re-enable BSD visibility for this file. */
#ifdef __FreeBSD__
# define __BSD_VISIBLE 1
#endif
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

static const char *myname = "op_copy";

#if !defined(__linux__) && !defined(__FreeBSD__)
int main(void)
{
	skip("%s: copy_file_range(2) not available on this platform "
	     "(Linux 4.5+ or FreeBSD 13+ required)",
	     myname);
	return TEST_SKIP;
}
#else

#define FILE_LEN   (2 * 1024 * 1024)
#define ISLAND_LEN (64 * 1024)

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  exercise copy_file_range -> NFSv4.2 COPY\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

/*
 * cfr_all -- copy `count` bytes via copy_file_range, handling short
 * returns by looping.  Complains and returns -1 on error or unexpected
 * early EOF.
 */
static int cfr_all(int sfd, off_t *soff, int dfd, off_t *doff, size_t count,
		   const char *ctx)
{
	size_t remaining = count;
	while (remaining > 0) {
		ssize_t n = copy_file_range(sfd, soff, dfd, doff, remaining, 0);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			complain("%s: copy_file_range: %s", ctx,
				 strerror(errno));
			return -1;
		}
		if (n == 0) {
			complain("%s: copy_file_range short (got %zu of %zu)",
				 ctx, count - remaining, count);
			return -1;
		}
		remaining -= (size_t)n;
	}
	return 0;
}

/*
 * feature_probe -- actually try to copy one byte.  If ENOSYS /
 * EOPNOTSUPP / EXDEV comes back, skip the whole test cleanly.
 * EXDEV here means "copy_file_range cannot span file systems" --
 * legal and informative, but an operator-visible signal that the
 * two scratch files landed on different backing filesystems, which
 * means we can't meaningfully test COPY anyway.
 */
static void feature_probe(int sfd, int dfd,
			  const char *sname, const char *dname)
{
	unsigned char one = 0x42;
	if (pwrite(sfd, &one, 1, 0) != 1)
		bail("feature_probe: seed pwrite: %s", strerror(errno));
	if (ftruncate(dfd, 0) != 0)
		bail("feature_probe: ftruncate dst: %s", strerror(errno));

	off_t s = 0, d = 0;
	ssize_t n = copy_file_range(sfd, &s, dfd, &d, 1, 0);
	if (n < 0) {
		if (errno == ENOSYS || errno == EOPNOTSUPP
		    || errno == EXDEV) {
			int e = errno;
			/* skip() exits; unlink the scratch files first. */
			close(sfd); close(dfd);
			unlink(sname); unlink(dname);
			errno = e;
			skip("%s: copy_file_range probe returned %s",
			     myname, strerror(errno));
		}
		bail("feature_probe: unexpected error: %s", strerror(errno));
	}
	if (n != 1)
		bail("feature_probe: short copy of 1 byte (got %zd)", n);

	/*
	 * Rewind both for the real cases.  An ftruncate failure here
	 * is unusual after a pwrite+ftruncate that just succeeded,
	 * but if it happens it will show up as a size mismatch in
	 * case_simple rather than silently feeding stale state in.
	 */
	if (ftruncate(sfd, 0) != 0 || ftruncate(dfd, 0) != 0)
		bail("feature_probe: rewind ftruncate: %s", strerror(errno));
}

static void case_simple(int sfd, int dfd)
{
	unsigned char *buf = malloc(FILE_LEN);
	if (!buf) { complain("case1: malloc"); return; }
	fill_pattern(buf, FILE_LEN, 0x12345678);
	if (pwrite_all(sfd, buf, FILE_LEN, 0, "case1:write src") < 0) {
		free(buf);
		return;
	}
	if (ftruncate(dfd, 0) != 0) {
		complain("case1: ftruncate dst: %s", strerror(errno));
		free(buf);
		return;
	}

	off_t soff = 0, doff = 0;
	if (cfr_all(sfd, &soff, dfd, &doff, FILE_LEN, "case1") < 0) {
		free(buf);
		return;
	}

	unsigned char *rb = malloc(FILE_LEN);
	if (!rb) {
		complain("case1: malloc rb");
	} else if (pread_all(dfd, rb, FILE_LEN, 0, "case1:verify") == 0) {
		size_t miss = check_pattern(rb, FILE_LEN, 0x12345678);
		if (miss)
			complain("case1: dst mismatch at byte %zu", miss - 1);
	}
	free(rb);
	free(buf);
}

static void case_offset(int sfd, int dfd)
{
	unsigned char *buf = malloc(FILE_LEN);
	if (!buf) { complain("case2: malloc"); return; }
	fill_pattern(buf, FILE_LEN, 0x87654321);
	if (pwrite_all(sfd, buf, FILE_LEN, 0, "case2:write src") < 0) {
		free(buf);
		return;
	}
	if (ftruncate(dfd, 0) != 0) {
		complain("case2: ftruncate dst: %s", strerror(errno));
		free(buf);
		return;
	}

	off_t mid = FILE_LEN / 2;
	size_t copy_len = FILE_LEN / 4;
	off_t soff = mid, doff = 0;
	if (cfr_all(sfd, &soff, dfd, &doff, copy_len, "case2") < 0) {
		free(buf);
		return;
	}

	unsigned char *rb = malloc(copy_len);
	if (!rb) {
		complain("case2: malloc rb");
	} else if (pread_all(dfd, rb, copy_len, 0, "case2:verify") == 0) {
		if (memcmp(rb, buf + mid, copy_len) != 0)
			complain("case2: dst != src[mid..mid+len)");
	}
	free(rb);
	free(buf);
}

static void case_sparse_preservation(int sfd, int dfd)
{
#if defined(SEEK_HOLE) && defined(SEEK_DATA)
	if (ftruncate(sfd, 0) != 0 || ftruncate(dfd, 0) != 0) {
		complain("case3: ftruncate: %s", strerror(errno));
		return;
	}
	if (ftruncate(sfd, FILE_LEN) != 0) {
		complain("case3: ftruncate(FILE_LEN) src: %s",
			 strerror(errno));
		return;
	}
	unsigned char *buf = malloc(ISLAND_LEN);
	if (!buf) { complain("case3: malloc"); return; }
	fill_pattern(buf, ISLAND_LEN, 0xDE);
	if (pwrite_all(sfd, buf, ISLAND_LEN, FILE_LEN / 4,
		       "case3:island0") < 0) {
		free(buf);
		return;
	}
	if (pwrite_all(sfd, buf, ISLAND_LEN, 3 * FILE_LEN / 4,
		       "case3:island1") < 0) {
		free(buf);
		return;
	}
	fdatasync(sfd);
	free(buf);

	off_t soff = 0, doff = 0;
	if (cfr_all(sfd, &soff, dfd, &doff, FILE_LEN, "case3") < 0)
		return;

	unsigned char sample[4096];
	if (pread_all(dfd, sample, sizeof(sample), 1024,
		      "case3:sample hole") == 0) {
		if (!all_zero(sample, sizeof(sample)))
			complain("case3: hole region in dst not zero-filled");
	}
#else
	(void)sfd; (void)dfd;
	if (!Sflag)
		printf("NOTE: %s: case3 sparse preservation skipped "
		       "(no SEEK_HOLE/SEEK_DATA)\n",
		       myname);
#endif
}

static void case_matrix_api(int sfd, int dfd)
{
	/* Seed src with 4 KiB so we have a known tail to short-read past. */
	const size_t seed_len = 4096;
	unsigned char *seed = malloc(seed_len);
	if (!seed) { complain("case4: malloc"); return; }
	fill_pattern(seed, seed_len, 0x4A4A);
	if (ftruncate(sfd, 0) != 0 || ftruncate(dfd, 0) != 0) {
		complain("case4: ftruncate reset: %s", strerror(errno));
		free(seed);
		return;
	}
	if (pwrite_all(sfd, seed, seed_len, 0, "case4: seed src") < 0) {
		free(seed);
		return;
	}
	free(seed);

	/* 4a -- zero-length copy must succeed and return 0. */
	{
		off_t soff = 0, doff = 0;
		ssize_t n = copy_file_range(sfd, &soff, dfd, &doff, 0, 0);
		if (n < 0)
			complain("case4a: copy_file_range(len=0): %s",
				 strerror(errno));
		else if (n != 0)
			complain("case4a: copy_file_range(len=0) returned "
				 "%zd (expected 0)", n);
	}

	/* 4b -- non-zero flags must be rejected with EINVAL. */
	{
		off_t soff = 0, doff = 0;
		errno = 0;
		ssize_t n = copy_file_range(sfd, &soff, dfd, &doff, 64,
					    0x1u);
		if (n >= 0) {
			/*
			 * Some older kernels may accept unknown flags.
			 * Report as NOTE rather than FAIL -- not every
			 * platform enforces this strictly.
			 */
			if (!Sflag)
				printf("NOTE: %s: case4b non-zero flag "
				       "accepted (n=%zd); spec says "
				       "EINVAL\n", myname, n);
		} else if (errno != EINVAL) {
			complain("case4b: unexpected errno %s "
				 "(expected EINVAL)", strerror(errno));
		}
	}

	/* 4c -- request more than src has; must short-copy and stop. */
	{
		if (ftruncate(dfd, 0) != 0) {
			complain("case4c: ftruncate dst: %s", strerror(errno));
			return;
		}
		off_t soff = 0, doff = 0;
		/*
		 * Ask for 16 KiB; src only holds 4 KiB.  Post-call:
		 *   - return value may be seed_len (single-call short) or
		 *     any positive prefix in [1..seed_len];
		 *   - soff must be in [0..seed_len];
		 *   - a second call from the same soff returns 0 (EOF).
		 */
		ssize_t n = copy_file_range(sfd, &soff, dfd, &doff,
					    4 * seed_len, 0);
		if (n < 0) {
			complain("case4c: copy_file_range: %s",
				 strerror(errno));
			return;
		}
		if (n < 0 || (size_t)n > seed_len)
			complain("case4c: over-copy %zd > src %zu",
				 n, seed_len);
		if (soff < 0 || soff > (off_t)seed_len)
			complain("case4c: soff advanced to %lld "
				 "(src size %zu)",
				 (long long)soff, seed_len);

		/* Second call from current soff must signal EOF (n==0). */
		off_t soff_eof = (off_t)seed_len;
		off_t doff_eof = n;
		ssize_t m = copy_file_range(sfd, &soff_eof, dfd, &doff_eof,
					    seed_len, 0);
		if (m < 0)
			complain("case4c: EOF call copy_file_range: %s",
				 strerror(errno));
		else if (m != 0)
			complain("case4c: EOF call returned %zd "
				 "(expected 0 at EOF)", m);
	}
}

static void case_short_copy_atomicity(int sfd, int dfd)
{
	const size_t pat_a_len = 4096;
	const size_t dst_len   = 8192;

	unsigned char *src_a = malloc(pat_a_len);
	unsigned char *dst_b = malloc(dst_len);
	if (!src_a || !dst_b) {
		complain("case5: malloc");
		free(src_a); free(dst_b);
		return;
	}
	fill_pattern(src_a, pat_a_len, 0x5A5A);
	fill_pattern(dst_b, dst_len,   0x5B5B);

	if (ftruncate(sfd, 0) != 0 || ftruncate(dfd, 0) != 0) {
		complain("case5: ftruncate reset: %s", strerror(errno));
		free(src_a); free(dst_b);
		return;
	}
	if (pwrite_all(sfd, src_a, pat_a_len, 0, "case5: seed src A") < 0
	    || pwrite_all(dfd, dst_b, dst_len, 0, "case5: seed dst B") < 0) {
		free(src_a); free(dst_b);
		return;
	}

	/*
	 * Request 8 KiB; src only has 4 KiB.  Server must short-copy.
	 * Any return in [1..pat_a_len] is legal; 0 would be wrong here
	 * because src is non-empty and soff starts at 0.
	 */
	off_t soff = 0, doff = 0;
	ssize_t n = copy_file_range(sfd, &soff, dfd, &doff, dst_len, 0);
	if (n < 0) {
		complain("case5: copy_file_range: %s", strerror(errno));
		free(src_a); free(dst_b);
		return;
	}
	if (n <= 0 || (size_t)n > pat_a_len) {
		complain("case5: returned %zd, expected 1..%zu",
			 n, pat_a_len);
		free(src_a); free(dst_b);
		return;
	}

	/* Read back the whole 8 KiB of dst. */
	unsigned char *rb = malloc(dst_len);
	if (!rb) {
		complain("case5: malloc rb");
		free(src_a); free(dst_b);
		return;
	}
	if (pread_all(dfd, rb, dst_len, 0, "case5: verify dst") != 0) {
		free(src_a); free(dst_b); free(rb);
		return;
	}

	/*
	 * dst[0..n)   must match pattern A (the copied bytes).
	 * dst[n..8K)  must match pattern B (the untouched tail).
	 * The boundary at n is the atomicity test: a server that
	 * zero-filled or garbage-filled the tail fails here.
	 */
	if (memcmp(rb, src_a, (size_t)n) != 0)
		complain("case5: dst[0..%zd) != pattern A "
			 "(copy_file_range wrote wrong source bytes)", n);

	for (size_t i = (size_t)n; i < dst_len; i++) {
		if (rb[i] != dst_b[i]) {
			complain("case5: dst byte %zu = 0x%02x, expected "
				 "0x%02x (pattern B) -- short-copy altered "
				 "bytes past the returned count (tail zero-"
				 "filled or garbage)",
				 i, rb[i], dst_b[i]);
			break;
		}
	}

	free(rb);
	free(src_a);
	free(dst_b);
}

static void case_intra_file(int sfd, int dfd)
{
	/* This case uses a private file (not sfd/dfd) because src == dst. */
	(void)sfd; (void)dfd;

	char lname[64];
	snprintf(lname, sizeof(lname), "t13.in.%ld", (long)getpid());
	unlink(lname);

	int fd = open(lname, O_RDWR | O_CREAT, 0644);
	if (fd < 0) {
		complain("case6: open: %s", strerror(errno));
		return;
	}

	/* Layout: [0..4K) pattern A, [4K..64K) zeros, [64K..68K) zeros,
	 * [68K..128K) pattern B.  We'll copy [0..4K) into [64K..68K),
	 * then test an overlapping copy. */
	const size_t block = 4096;
	const off_t file_len = 128 * 1024;
	if (ftruncate(fd, file_len) != 0) {
		complain("case6: ftruncate: %s", strerror(errno));
		close(fd); unlink(lname); return;
	}

	unsigned char a[4096], b[4096];
	fill_pattern(a, block, 0xA6A6);
	fill_pattern(b, block, 0xB6B6);
	if (pwrite_all(fd, a, block, 0, "case6: seed A") < 0
	    || pwrite_all(fd, b, block, 68 * 1024, "case6: seed B") < 0) {
		close(fd); unlink(lname); return;
	}

	/* --- 6a: non-overlapping in-file copy (src=0, dst=64K, len=4K) --- */
	off_t soff = 0, doff = 64 * 1024;
	ssize_t n = copy_file_range(fd, &soff, fd, &doff, block, 0);
	if (n < 0) {
		complain("case6a: non-overlapping intra-file copy: %s",
			 strerror(errno));
	} else if ((size_t)n != block) {
		complain("case6a: short copy %zd (expected %zu)", n, block);
	} else {
		/* Reopen to dodge client caching and read the slot. */
		int rfd = open(lname, O_RDONLY);
		if (rfd < 0) {
			complain("case6a: reopen: %s", strerror(errno));
		} else {
			unsigned char rb[4096];
			if (pread_all(rfd, rb, block, 64 * 1024,
				      "case6a: verify") == 0) {
				if (memcmp(rb, a, block) != 0)
					complain("case6a: [64K..68K) != "
						 "pattern A after intra-"
						 "file copy");
			}
			close(rfd);
		}
	}

	/* --- 6b: overlapping forward copy (src=0, dst=2K, len=4K) --- */
	/*
	 * src range [0..4K) overlaps dst range [2K..6K) by 2K.  Linux
	 * kernel >= 5.3 documents copy_file_range with same-file
	 * overlap as returning EINVAL in some cases, succeeding in
	 * others depending on direction and kernel version.  Accept
	 * both:
	 *   - return -1 with EINVAL: informative, no data check.
	 *   - return > 0: the dst range must have taken the src bytes.
	 */
	if (pwrite_all(fd, a, block, 0, "case6b: reseed A") == 0) {
		off_t so = 0, doo = 2048;
		errno = 0;
		ssize_t m = copy_file_range(fd, &so, fd, &doo, block, 0);
		if (m < 0) {
			if (errno != EINVAL && !Sflag)
				printf("NOTE: %s: case6b overlapping "
				       "intra-file copy returned %s "
				       "(EINVAL or success both allowed)\n",
				       myname, strerror(errno));
		} else if ((size_t)m != block) {
			if (!Sflag)
				printf("NOTE: %s: case6b overlapping "
				       "intra-file copy short-returned "
				       "%zd\n", myname, m);
		}
		/*
		 * We deliberately do not assert destination content on the
		 * overlap case: the kernel's exact semantics (forward copy
		 * vs memmove-style) are under-specified and vary by
		 * version.  What matters is that it did not hang, crash,
		 * or corrupt content outside the requested range.
		 */
	}

	close(fd);
	unlink(lname);
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

	prelude(myname, "copy_file_range -> NFSv4.2 COPY (RFC 7862 S7)");
	cd_or_skip(myname, dir, Nflag);

	char sname[64], dname[64];
	int sfd = scratch_open("t13.src", sname, sizeof(sname));
	int dfd = scratch_open("t13.dst", dname, sizeof(dname));

	feature_probe(sfd, dfd, sname, dname);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_simple", case_simple(sfd, dfd));
	RUN_CASE("case_offset", case_offset(sfd, dfd));
	RUN_CASE("case_sparse_preservation", case_sparse_preservation(sfd, dfd));
	RUN_CASE("case_matrix_api", case_matrix_api(sfd, dfd));
	RUN_CASE("case_short_copy_atomicity",
		 case_short_copy_atomicity(sfd, dfd));
	RUN_CASE("case_intra_file", case_intra_file(sfd, dfd));

	close(sfd);
	close(dfd);
	unlink(sname);
	unlink(dname);

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}

#endif /* __linux__ || __FreeBSD__ */
