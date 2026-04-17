/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_rename_nlink.c -- exercise NFSv4 RENAME (RFC 7530 S18.26) with
 * focus on parent-directory nlink accounting.
 *
 * op_rename_atomic tests the atomicity and data-preservation aspects
 * of rename.  This test focuses on the nlink bookkeeping that NFS
 * servers must get right for directories -- the "." and ".." entries
 * mean directory nlink is (2 + number_of_subdirectories), and
 * cross-parent renames must update BOTH parent directories' nlink.
 *
 * Cases:
 *
 *   1. Move directory cross-parent.  mkdir src/sub, mkdir dst.
 *      Rename src/sub to dst/sub.  Report src nlink -= 1 and dst
 *      nlink += 1 if deviating (NOTE only -- see link-count
 *      discussion below).
 *
 *   2. Rename-replace directory.  mkdir p/a, mkdir p/b.  Rename
 *      p/a to p/b (replacing b).  Report p nlink -= 1 if deviating
 *      (NOTE only).
 *
 *   3. Move regular file cross-parent.  Parent nlink MUST NOT
 *      change for a file rename.  (A file contributes zero links
 *      to its parent directory, so the parent's nlink is
 *      unaffected.)
 *
 *   4. Parent mtime/ctime advance.  Both source and destination
 *      parent directories MUST have mtime/ctime advance after a
 *      cross-parent rename.
 *      (POSIX.1-2008 rename(), "Upon successful completion" clause)
 *
 * Directory link-count discussion:
 *   The traditional Unix convention is st_nlink == 2 + number of
 *   subdirectories, counting the parent's entry plus the ".." entry
 *   from each subdirectory.  POSIX.1-2008 does NOT mandate this
 *   convention; stat() only requires st_nlink to be a count of
 *   hard links >= 1.  Many modern filesystems and NFS server
 *   backends report a constant st_nlink for every directory.  Cases
 *   1 and 2 emit a NOTE when the traditional convention is not
 *   followed rather than failing an otherwise-POSIX-conformant
 *   server.
 *
 * Portable: POSIX.1-2008 rename() across Linux / FreeBSD / macOS / Solaris.
 */

#define _GNU_SOURCE
#define _DARWIN_C_SOURCE

#include "tests.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifdef __APPLE__
#define ST_MTIM st_mtimespec
#else
#define ST_MTIM st_mtim
#endif

int Hflag = 0;
int Sflag = 0;
int Tflag = 0;
int Fflag = 0;
int Nflag = 0;

static const char *myname = "op_rename_nlink";

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  exercise rename nlink accounting -> NFSv4 RENAME "
		"(RFC 7530 S18.26)\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

static void case_cross_parent_dir(void)
{
	char src[64], dst[64], sub[128], newsub[128];
	snprintf(src, sizeof(src), "t_rnl.s.%ld", (long)getpid());
	snprintf(dst, sizeof(dst), "t_rnl.d.%ld", (long)getpid());
	snprintf(sub, sizeof(sub), "%s/sub", src);
	snprintf(newsub, sizeof(newsub), "%s/sub", dst);

	rmdir(newsub); rmdir(sub); rmdir(src); rmdir(dst);
	if (mkdir(src, 0755) != 0 || mkdir(dst, 0755) != 0 ||
	    mkdir(sub, 0755) != 0) {
		complain("case1: setup: %s", strerror(errno));
		rmdir(sub); rmdir(src); rmdir(dst);
		return;
	}

	struct stat st_src_before, st_dst_before;
	if (stat(src, &st_src_before) != 0 ||
	    stat(dst, &st_dst_before) != 0) {
		complain("case1: stat before: %s", strerror(errno));
		rmdir(sub); rmdir(src); rmdir(dst);
		return;
	}

	if (rename(sub, newsub) != 0) {
		complain("case1: rename: %s", strerror(errno));
		rmdir(sub); rmdir(newsub); rmdir(src); rmdir(dst);
		return;
	}

	struct stat st_src_after, st_dst_after;
	if (stat(src, &st_src_after) != 0 ||
	    stat(dst, &st_dst_after) != 0) {
		complain("case1: stat after: %s", strerror(errno));
		rmdir(newsub); rmdir(src); rmdir(dst);
		return;
	}

	/*
	 * POSIX.1-2008 does NOT require the traditional Unix
	 * "st_nlink == 2 + number_of_subdirectories" convention for
	 * directories; st_nlink need only be >= 1.  Many modern
	 * filesystems (and NFS server backends) report a constant
	 * st_nlink = 1 or 2 for every directory.  Report the observed
	 * delta as a NOTE rather than failing the server for
	 * conforming-to-POSIX-but-not-to-tradition behaviour.
	 */
	if (st_src_after.st_nlink != st_src_before.st_nlink - 1 && !Sflag)
		printf("NOTE: %s: case1 src nlink %lu -> %lu (traditional "
		       "Unix expects -1 after moving a subdirectory out; "
		       "POSIX.1-2008 only requires st_nlink >= 1)\n",
		       myname,
		       (unsigned long)st_src_before.st_nlink,
		       (unsigned long)st_src_after.st_nlink);

	if (st_dst_after.st_nlink != st_dst_before.st_nlink + 1 && !Sflag)
		printf("NOTE: %s: case1 dst nlink %lu -> %lu (traditional "
		       "Unix expects +1 after receiving a subdirectory; "
		       "POSIX.1-2008 only requires st_nlink >= 1)\n",
		       myname,
		       (unsigned long)st_dst_before.st_nlink,
		       (unsigned long)st_dst_after.st_nlink);

	rmdir(newsub);
	rmdir(src);
	rmdir(dst);
}

static void case_rename_replace_dir(void)
{
	char p[64], a[128], b[128];
	snprintf(p, sizeof(p), "t_rnl.p.%ld", (long)getpid());
	snprintf(a, sizeof(a), "%s/a", p);
	snprintf(b, sizeof(b), "%s/b", p);

	rmdir(a); rmdir(b); rmdir(p);
	if (mkdir(p, 0755) != 0 || mkdir(a, 0755) != 0 ||
	    mkdir(b, 0755) != 0) {
		complain("case2: setup: %s", strerror(errno));
		rmdir(a); rmdir(b); rmdir(p);
		return;
	}

	struct stat st_before;
	if (stat(p, &st_before) != 0) {
		complain("case2: stat before: %s", strerror(errno));
		rmdir(a); rmdir(b); rmdir(p);
		return;
	}

	/* Rename a over b — net loss of one directory. */
	if (rename(a, b) != 0) {
		complain("case2: rename(a, b): %s", strerror(errno));
		rmdir(a); rmdir(b); rmdir(p);
		return;
	}

	struct stat st_after;
	if (stat(p, &st_after) != 0) {
		complain("case2: stat after: %s", strerror(errno));
		rmdir(b); rmdir(p);
		return;
	}

	/* See case1 note: POSIX.1-2008 does not require the
	 * "nlink = 2 + number_of_subdirectories" convention. */
	if (st_after.st_nlink != st_before.st_nlink - 1 && !Sflag)
		printf("NOTE: %s: case2 parent nlink %lu -> %lu "
		       "(traditional Unix expects -1 after rename-replace "
		       "removed one subdir; POSIX.1-2008 only requires "
		       "st_nlink >= 1)\n",
		       myname,
		       (unsigned long)st_before.st_nlink,
		       (unsigned long)st_after.st_nlink);

	rmdir(b);
	rmdir(p);
}

static void case_file_no_nlink_change(void)
{
	char src[64], dst[64], sf[128], df[128];
	snprintf(src, sizeof(src), "t_rnl.fs.%ld", (long)getpid());
	snprintf(dst, sizeof(dst), "t_rnl.fd.%ld", (long)getpid());
	snprintf(sf, sizeof(sf), "%s/f", src);
	snprintf(df, sizeof(df), "%s/f", dst);

	unlink(df); unlink(sf); rmdir(src); rmdir(dst);
	if (mkdir(src, 0755) != 0 || mkdir(dst, 0755) != 0) {
		complain("case3: setup: %s", strerror(errno));
		rmdir(src); rmdir(dst);
		return;
	}

	int fd = open(sf, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("case3: create: %s", strerror(errno));
		rmdir(src); rmdir(dst);
		return;
	}
	close(fd);

	struct stat st_src_before, st_dst_before;
	stat(src, &st_src_before);
	stat(dst, &st_dst_before);

	if (rename(sf, df) != 0) {
		complain("case3: rename: %s", strerror(errno));
		unlink(sf); unlink(df); rmdir(src); rmdir(dst);
		return;
	}

	struct stat st_src_after, st_dst_after;
	stat(src, &st_src_after);
	stat(dst, &st_dst_after);

	if (st_src_after.st_nlink != st_src_before.st_nlink)
		complain("case3: src nlink changed from %lu to %lu "
			 "(regular file rename must not change parent nlink)",
			 (unsigned long)st_src_before.st_nlink,
			 (unsigned long)st_src_after.st_nlink);
	if (st_dst_after.st_nlink != st_dst_before.st_nlink)
		complain("case3: dst nlink changed from %lu to %lu",
			 (unsigned long)st_dst_before.st_nlink,
			 (unsigned long)st_dst_after.st_nlink);

	unlink(df);
	rmdir(src);
	rmdir(dst);
}

static void case_parent_timestamps(void)
{
	char src[64], dst[64], sf[128], df[128];
	snprintf(src, sizeof(src), "t_rnl.ts.%ld", (long)getpid());
	snprintf(dst, sizeof(dst), "t_rnl.td.%ld", (long)getpid());
	snprintf(sf, sizeof(sf), "%s/f", src);
	snprintf(df, sizeof(df), "%s/f", dst);

	unlink(df); unlink(sf); rmdir(src); rmdir(dst);
	if (mkdir(src, 0755) != 0 || mkdir(dst, 0755) != 0) {
		complain("case4: setup: %s", strerror(errno));
		rmdir(src); rmdir(dst);
		return;
	}

	int fd = open(sf, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("case4: create: %s", strerror(errno));
		rmdir(src); rmdir(dst);
		return;
	}
	close(fd);

	sleep_ms(50);
	struct stat st_src_before, st_dst_before;
	stat(src, &st_src_before);
	stat(dst, &st_dst_before);

	sleep_ms(50);
	if (rename(sf, df) != 0) {
		complain("case4: rename: %s", strerror(errno));
		unlink(sf); unlink(df); rmdir(src); rmdir(dst);
		return;
	}

	struct stat st_src_after, st_dst_after;
	stat(src, &st_src_after);
	stat(dst, &st_dst_after);

	/*
	 * Use st_mtim (nanosecond precision) rather than st_mtime
	 * (second precision).  The rename and stat can both land in the
	 * same wall-clock second when the kernel NFS client caches mtime
	 * at second granularity; nanoseconds distinguish them.
	 */
	if (!(st_src_after.ST_MTIM.tv_sec > st_src_before.ST_MTIM.tv_sec ||
	      (st_src_after.ST_MTIM.tv_sec == st_src_before.ST_MTIM.tv_sec &&
	       st_src_after.ST_MTIM.tv_nsec > st_src_before.ST_MTIM.tv_nsec)))
		complain("case4: src parent mtime did not advance");
	if (!(st_dst_after.ST_MTIM.tv_sec > st_dst_before.ST_MTIM.tv_sec ||
	      (st_dst_after.ST_MTIM.tv_sec == st_dst_before.ST_MTIM.tv_sec &&
	       st_dst_after.ST_MTIM.tv_nsec > st_dst_before.ST_MTIM.tv_nsec)))
		complain("case4: dst parent mtime did not advance");

	unlink(df);
	rmdir(src);
	rmdir(dst);
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
		"rename nlink accounting -> NFSv4 RENAME (RFC 7530 S18.26)");
	cd_or_skip(myname, dir, Nflag);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_cross_parent_dir", case_cross_parent_dir());
	RUN_CASE("case_rename_replace_dir", case_rename_replace_dir());
	RUN_CASE("case_file_no_nlink_change", case_file_no_nlink_change());
	RUN_CASE("case_parent_timestamps", case_parent_timestamps());

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}
