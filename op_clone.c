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
 * Range-partial clone (FICLONERANGE) is out of scope for this file
 * per the one-concern-per-test convention; if added it goes in a
 * separate op_clone_range.
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
#include <linux/fs.h> /* FICLONE */

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
 * do_ficlone -- call ioctl(FICLONE).  On EOPNOTSUPP / EXDEV /
 * ENOSYS call skip() -- those mean the backend cannot support
 * reflinks, which is a configuration fact, not a bug.
 */
static int do_ficlone(int dfd, int sfd)
{
	if (ioctl(dfd, FICLONE, sfd) == 0)
		return 0;
	if (errno == EOPNOTSUPP || errno == EXDEV || errno == ENOSYS) {
		skip("%s: FICLONE returned %s; backend does not support "
		     "reflinks",
		     myname, strerror(errno));
	}
	return -1;
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

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_basic_clone", case_basic_clone(sfd, dfd));
	RUN_CASE("case_cow_semantics", case_cow_semantics(sfd, dfd));

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
