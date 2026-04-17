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
static void feature_probe(int sfd, int dfd)
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
			skip("%s: copy_file_range probe returned %s",
			     myname, strerror(errno));
		}
		bail("feature_probe: unexpected error: %s", strerror(errno));
	}
	if (n != 1)
		bail("feature_probe: short copy of 1 byte (got %zd)", n);

	/* Rewind both for the real cases. */
	ftruncate(sfd, 0);
	ftruncate(dfd, 0);
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

	feature_probe(sfd, dfd);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_simple", case_simple(sfd, dfd));
	RUN_CASE("case_offset", case_offset(sfd, dfd));
	RUN_CASE("case_sparse_preservation", case_sparse_preservation(sfd, dfd));

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
