/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_clone.c -- exercise ioctl(FICLONE), which NFSv4.2 servers
 * translate into a CLONE op (RFC 7862 S11) when source and
 * destination are on the same file system and the backing
 * filesystem supports block-level reflinks (btrfs, xfs with
 * reflink=1, zfs, etc.).
 *
 * Linux-only.  Runtime SKIP on EOPNOTSUPP / EXDEV / ENOSYS --
 * unsupported backend is a legitimate configuration, not a bug.
 *
 * Cases:
 *
 *   1. Basic whole-file clone.  DST content == SRC content after
 *      ioctl(FICLONE).
 *
 *   2. Copy-on-write semantics.  Modify SRC after cloning; DST
 *      must remain unchanged.  This is the critical property that
 *      distinguishes a reflink from a hard link.
 *
 *   3. Clone + truncate src.  Clone, truncate SRC to 0, verify DST
 *      still has the full pre-clone content.  Catches backends that
 *      implement CLONE as a delayed-copy optimisation and lose the
 *      shared blocks when the "original" holder shrinks.
 *
 *   4. Clone + unlink src.  Clone, close + unlink SRC, verify DST
 *      is still readable and byte-for-byte identical to the pre-
 *      unlink content.  A refcount-per-extent implementation must
 *      keep the shared blocks alive for DST; a buggy one may drop
 *      them when SRC's inode is removed.
 *
 *   5. Partial range clone (FICLONERANGE).  Clone a middle byte
 *      range from SRC into DST; bytes outside the cloned range in
 *      DST must remain untouched.  Exercises the range-addressed
 *      variant that FICLONE (whole-file) does not.  Derived from
 *      the clone matrix in xfstests generic/110-149.
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

static const char *myname = "op_clone";

#if !defined(__linux__)
int main(void)
{
	skip("%s: ioctl(FICLONE) is Linux-only", myname);
	return TEST_SKIP;
}
#else

#include <sys/ioctl.h>
#include <linux/fs.h> /* FICLONE, FICLONERANGE, struct file_clone_range */

#ifndef FICLONE
int main(void)
{
	skip("%s: FICLONE ioctl not defined in this kernel's <linux/fs.h>",
	     myname);
	return TEST_SKIP;
}
#else

#define FILE_LEN (1 * 1024 * 1024)

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  exercise FICLONE -> NFSv4.2 CLONE\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

/*
 * do_ficlone -- call ioctl(FICLONE).  Used by the test cases AFTER
 * feature_probe() has already passed, so unexpected errors here
 * are real conformance failures -- the caller complains.
 */
static int do_ficlone(int dfd, int sfd)
{
	if (ioctl(dfd, FICLONE, sfd) == 0)
		return 0;
	return -1;
}

/*
 * feature_probe -- 1-byte FICLONE to detect unsupported backends.
 * On EOPNOTSUPP / EXDEV / ENOSYS, unlink scratch files and skip.
 * Must run BEFORE the test cases so an unsupported mount doesn't
 * leak t15.src / t15.dst.
 */
static void feature_probe(int sfd, int dfd,
			  const char *sname, const char *dname)
{
	unsigned char one = 0x42;
	if (pwrite(sfd, &one, 1, 0) != 1)
		bail("feature_probe: seed pwrite: %s", strerror(errno));
	if (ftruncate(dfd, 1) != 0)
		bail("feature_probe: ftruncate dst: %s", strerror(errno));
	fdatasync(sfd);

	if (ioctl(dfd, FICLONE, sfd) != 0) {
		if (errno == EOPNOTSUPP || errno == EXDEV
		    || errno == ENOSYS || errno == EINVAL) {
			int e = errno;
			close(sfd); close(dfd);
			unlink(sname); unlink(dname);
			errno = e;
			skip("%s: FICLONE probe returned %s; backend does "
			     "not support reflinks",
			     myname, strerror(errno));
		}
		bail("feature_probe: FICLONE: %s", strerror(errno));
	}

	/* Rewind both for the real cases. */
	ftruncate(sfd, 0);
	ftruncate(dfd, 0);
}

static void case_basic_clone(int sfd, int dfd)
{
	unsigned char *buf = malloc(FILE_LEN);
	if (!buf) { complain("case1: malloc"); return; }
	fill_pattern(buf, FILE_LEN, 0xC10E);
	if (pwrite_all(sfd, buf, FILE_LEN, 0, "case1:src") < 0) {
		free(buf);
		return;
	}
	fdatasync(sfd);

	if (do_ficlone(dfd, sfd) != 0) {
		complain("case1: ioctl(FICLONE): %s", strerror(errno));
		free(buf);
		return;
	}

	struct stat dst_st;
	if (fstat(dfd, &dst_st) != 0) {
		complain("case1: fstat dst: %s", strerror(errno));
		free(buf);
		return;
	}
	if (dst_st.st_size != FILE_LEN) {
		complain("case1: dst size %lld != src size %d",
			 (long long)dst_st.st_size, FILE_LEN);
		free(buf);
		return;
	}

	unsigned char *rb = malloc(FILE_LEN);
	if (!rb) {
		complain("case1: malloc rb");
	} else if (pread_all(dfd, rb, FILE_LEN, 0, "case1:verify") == 0) {
		size_t miss = check_pattern(rb, FILE_LEN, 0xC10E);
		if (miss)
			complain("case1: clone content mismatch at byte %zu",
				 miss - 1);
	}
	free(rb);
	free(buf);
}

static void case_cow_semantics(int sfd, int dfd)
{
	/* Reset both files so the state from case 1 doesn't leak in. */
	if (ftruncate(sfd, 0) != 0 || ftruncate(dfd, 0) != 0) {
		complain("case2: ftruncate: %s", strerror(errno));
		return;
	}

	unsigned char *buf = malloc(FILE_LEN);
	if (!buf) { complain("case2: malloc"); return; }
	fill_pattern(buf, FILE_LEN, 0xB01);
	if (pwrite_all(sfd, buf, FILE_LEN, 0, "case2:src") < 0) {
		free(buf);
		return;
	}
	fdatasync(sfd);

	if (do_ficlone(dfd, sfd) != 0) {
		complain("case2: ficlone: %s", strerror(errno));
		free(buf);
		return;
	}

	/* Mutate source halfway through */
	unsigned char mark[4096];
	memset(mark, 0x5A, sizeof(mark));
	if (pwrite_all(sfd, mark, sizeof(mark), FILE_LEN / 2,
		       "case2:mutate src") < 0) {
		free(buf);
		return;
	}
	fdatasync(sfd);

	/* DST should still hold the ORIGINAL pattern */
	unsigned char *rb = malloc(FILE_LEN);
	if (!rb) {
		complain("case2: malloc rb");
	} else if (pread_all(dfd, rb, FILE_LEN, 0, "case2:verify dst") == 0) {
		size_t miss = check_pattern(rb, FILE_LEN, 0xB01);
		if (miss)
			complain("case2: dst was affected by src mutation "
				 "at byte %zu (CoW broken)",
				 miss - 1);
	}
	free(rb);
	free(buf);
}

static void case_clone_then_truncate_src(int sfd, int dfd)
{
	if (ftruncate(sfd, 0) != 0 || ftruncate(dfd, 0) != 0) {
		complain("case3: ftruncate reset: %s", strerror(errno));
		return;
	}
	unsigned char *buf = malloc(FILE_LEN);
	if (!buf) { complain("case3: malloc"); return; }
	fill_pattern(buf, FILE_LEN, 0xC103);
	if (pwrite_all(sfd, buf, FILE_LEN, 0, "case3:src") < 0) {
		free(buf);
		return;
	}
	fdatasync(sfd);

	if (do_ficlone(dfd, sfd) != 0) {
		complain("case3: ficlone: %s", strerror(errno));
		free(buf);
		return;
	}

	/* Now shrink src to nothing.  A well-behaved CoW backend keeps
	 * the shared extents alive for dst; a delayed-copy backend that
	 * treats src as the canonical holder may lose them. */
	if (ftruncate(sfd, 0) != 0) {
		complain("case3: truncate src: %s", strerror(errno));
		free(buf);
		return;
	}
	fdatasync(sfd);

	struct stat dst_st;
	if (fstat(dfd, &dst_st) != 0) {
		complain("case3: fstat dst: %s", strerror(errno));
		free(buf);
		return;
	}
	if (dst_st.st_size != FILE_LEN) {
		complain("case3: dst size %lld != %d after truncating src "
			 "(shared extents lost when src shrank)",
			 (long long)dst_st.st_size, FILE_LEN);
		free(buf);
		return;
	}

	unsigned char *rb = malloc(FILE_LEN);
	if (!rb) {
		complain("case3: malloc rb");
	} else if (pread_all(dfd, rb, FILE_LEN, 0,
			     "case3:verify dst") == 0) {
		size_t miss = check_pattern(rb, FILE_LEN, 0xC103);
		if (miss)
			complain("case3: dst mismatch at byte %zu after "
				 "truncating src (CoW retention broken)",
				 miss - 1);
	}
	free(rb);
	free(buf);
}

static void case_clone_then_unlink_src(void)
{
	/*
	 * This case uses private scratch files (not main's sfd/dfd)
	 * because it unlinks the source and closes its fd -- we don't
	 * want to interfere with other cases that follow.
	 */
	char lsname[64], ldname[64];
	snprintf(lsname, sizeof(lsname), "t15.src.u.%ld", (long)getpid());
	snprintf(ldname, sizeof(ldname), "t15.dst.u.%ld", (long)getpid());
	unlink(lsname);
	unlink(ldname);

	int lsfd = open(lsname, O_RDWR | O_CREAT, 0644);
	int ldfd = open(ldname, O_RDWR | O_CREAT, 0644);
	if (lsfd < 0 || ldfd < 0) {
		complain("case4: open scratch: %s", strerror(errno));
		if (lsfd >= 0) close(lsfd);
		if (ldfd >= 0) close(ldfd);
		unlink(lsname);
		unlink(ldname);
		return;
	}

	unsigned char *buf = malloc(FILE_LEN);
	if (!buf) {
		complain("case4: malloc");
		close(lsfd); close(ldfd);
		unlink(lsname); unlink(ldname);
		return;
	}
	fill_pattern(buf, FILE_LEN, 0xC104);
	if (pwrite_all(lsfd, buf, FILE_LEN, 0, "case4:src") < 0) {
		close(lsfd); close(ldfd);
		unlink(lsname); unlink(ldname);
		free(buf);
		return;
	}
	fdatasync(lsfd);

	if (do_ficlone(ldfd, lsfd) != 0) {
		complain("case4: ficlone: %s", strerror(errno));
		close(lsfd); close(ldfd);
		unlink(lsname); unlink(ldname);
		free(buf);
		return;
	}

	/* Drop the source: close fd then unlink the name. */
	close(lsfd);
	if (unlink(lsname) != 0) {
		complain("case4: unlink src: %s", strerror(errno));
		close(ldfd);
		unlink(ldname);
		free(buf);
		return;
	}

	/* Verify dst still holds the pre-unlink content. */
	unsigned char *rb = malloc(FILE_LEN);
	if (!rb) {
		complain("case4: malloc rb");
	} else if (pread_all(ldfd, rb, FILE_LEN, 0,
			     "case4:verify dst") == 0) {
		size_t miss = check_pattern(rb, FILE_LEN, 0xC104);
		if (miss)
			complain("case4: dst mismatch at byte %zu after "
				 "unlinking src (shared extents dropped "
				 "when src inode was removed)",
				 miss - 1);
	}
	free(rb);
	free(buf);

	close(ldfd);
	unlink(ldname);
}

static void case_clone_partial_range(int sfd, int dfd)
{
#ifndef FICLONERANGE
	if (!Sflag)
		printf("NOTE: %s: case5 FICLONERANGE unavailable, "
		       "skipping partial-range clone\n", myname);
	(void)sfd; (void)dfd;
#else
	if (ftruncate(sfd, 0) != 0 || ftruncate(dfd, 0) != 0) {
		complain("case5: ftruncate reset: %s", strerror(errno));
		return;
	}

	/* src = pattern A over the full range; dst = pattern B. */
	unsigned char *src_buf = malloc(FILE_LEN);
	unsigned char *dst_buf = malloc(FILE_LEN);
	if (!src_buf || !dst_buf) {
		complain("case5: malloc");
		free(src_buf); free(dst_buf);
		return;
	}
	fill_pattern(src_buf, FILE_LEN, 0xC105);
	fill_pattern(dst_buf, FILE_LEN, 0xD105);
	if (pwrite_all(sfd, src_buf, FILE_LEN, 0, "case5:src") < 0
	    || pwrite_all(dfd, dst_buf, FILE_LEN, 0, "case5:dst") < 0) {
		free(src_buf); free(dst_buf);
		return;
	}
	fdatasync(sfd);
	fdatasync(dfd);

	/*
	 * Clone the middle 256 KiB from src to dst at the same offset.
	 * Ranges must be block-aligned on most backends; 256 KiB at
	 * offset 256 KiB satisfies 4 KiB / 64 KiB / 128 KiB alignments
	 * comfortably.
	 */
	struct file_clone_range fcr = {
		.src_fd     = sfd,
		.src_offset = FILE_LEN / 4,
		.src_length = FILE_LEN / 2,
		.dest_offset = FILE_LEN / 4,
	};
	if (ioctl(dfd, FICLONERANGE, &fcr) != 0) {
		if (errno == EOPNOTSUPP || errno == EINVAL) {
			if (!Sflag)
				printf("NOTE: %s: case5 FICLONERANGE %s "
				       "(backend may require different "
				       "alignment) - skipping\n",
				       myname, strerror(errno));
			free(src_buf); free(dst_buf);
			return;
		}
		complain("case5: FICLONERANGE: %s", strerror(errno));
		free(src_buf); free(dst_buf);
		return;
	}

	/* Read dst back; compare. */
	unsigned char *rb = malloc(FILE_LEN);
	if (!rb) {
		complain("case5: malloc rb");
		free(src_buf); free(dst_buf);
		return;
	}
	if (pread_all(dfd, rb, FILE_LEN, 0,
		      "case5:verify dst") != 0) {
		free(src_buf); free(dst_buf); free(rb);
		return;
	}

	/* dst[0..FILE_LEN/4) must still be pattern B. */
	if (memcmp(rb, dst_buf, FILE_LEN / 4) != 0)
		complain("case5: dst head [0..%d) altered by "
			 "FICLONERANGE on middle range "
			 "(clone leaked past requested offset)",
			 FILE_LEN / 4);

	/* dst[FILE_LEN/4..3*FILE_LEN/4) must now match pattern A. */
	if (memcmp(rb + FILE_LEN / 4,
		   src_buf + FILE_LEN / 4,
		   FILE_LEN / 2) != 0)
		complain("case5: dst middle did not take on src pattern "
			 "after FICLONERANGE");

	/* dst[3*FILE_LEN/4..FILE_LEN) must still be pattern B. */
	if (memcmp(rb + 3 * FILE_LEN / 4,
		   dst_buf + 3 * FILE_LEN / 4,
		   FILE_LEN / 4) != 0)
		complain("case5: dst tail altered by FICLONERANGE on "
			 "middle range (clone leaked past requested length)");

	free(rb);
	free(src_buf);
	free(dst_buf);
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

	prelude(myname, "ioctl(FICLONE) -> NFSv4.2 CLONE (RFC 7862 S11)");
	cd_or_skip(myname, dir, Nflag);

	char sname[64], dname[64];
	int sfd = scratch_open("t15.src", sname, sizeof(sname));
	int dfd = scratch_open("t15.dst", dname, sizeof(dname));

	feature_probe(sfd, dfd, sname, dname);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_basic_clone", case_basic_clone(sfd, dfd));
	RUN_CASE("case_cow_semantics", case_cow_semantics(sfd, dfd));
	RUN_CASE("case_clone_then_truncate_src",
		 case_clone_then_truncate_src(sfd, dfd));
	RUN_CASE("case_clone_then_unlink_src",
		 case_clone_then_unlink_src());
	RUN_CASE("case_clone_partial_range",
		 case_clone_partial_range(sfd, dfd));

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

#endif /* FICLONE */
#endif /* __linux__ */
