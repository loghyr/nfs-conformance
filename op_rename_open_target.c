/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_rename_open_target.c -- rename corner cases when source or
 * target is held open.
 *
 * POSIX guarantees: rename(A, B) where B is an existing open file
 * leaves the open fd VALID.  The fd now refers to an unlinked-but-
 * live object; reads and writes continue to work; the file is
 * reclaimed when the last fd closes.  On NFS, servers that do not
 * implement the silly-rename pattern (or that tear down server state
 * aggressively) will hand ESTALE on the orphaned fd — a real-world
 * conformance failure.
 *
 * Ported from cthon04 basic/test6 with modern POSIX framing and
 * hardlink / cross-directory corner cases the original did not
 * cover.
 *
 * Cases:
 *
 *   1. Rename-over-open-target: A has content "src", B has content
 *      "dst".  Open B, then rename(A, B).  The open fd on original
 *      B must still be readable and return "dst".  Path B must now
 *      contain "src".  Close, verify.
 *
 *   2. Rename-when-source-open: open A, rename(A, B).  The open fd
 *      remains valid and its data is now at path B.  Original path
 *      A no longer exists.
 *
 *   3. Silly-rename-style: open A, unlink A, rename B over the
 *      already-unlinked inode's path position.  Reader on open fd
 *      continues to see the original inode.
 *
 *   4. Cross-directory rename of open target: /d1/A and /d2/B
 *      exist; open /d2/B; rename /d1/A → /d2/B.  Open fd on /d2/B
 *      still reads original B data; /d2/B now contains A's data.
 *
 *   5. Rename between hardlinks to same inode (POSIX.1-2024): A
 *      and B are hardlinks to the same file.  rename(A, B) must
 *      succeed as a no-op; both paths remain; link count unchanged.
 *
 *   6. Rename-self: rename(A, A) succeeds as a no-op; inode
 *      unchanged; open fd (if any) unaffected.
 *
 * Portable: POSIX on Linux / macOS / FreeBSD.
 */

#define _POSIX_C_SOURCE 200809L

#include "tests.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
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

static const char *myname = "op_rename_open_target";

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  rename corner cases with source/target held open\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

static int write_all(int fd, const void *buf, size_t n)
{
	const char *p = buf;
	while (n) {
		ssize_t w = write(fd, p, n);
		if (w <= 0) return -1;
		p += w; n -= w;
	}
	return 0;
}

static int create_with(const char *path, const char *content)
{
	int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) return -1;
	if (write_all(fd, content, strlen(content)) != 0) {
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

static void case_rename_over_open_target(void)
{
	char a[64], b[64];
	snprintf(a, sizeof(a), "t_rot.a.%ld", (long)getpid());
	snprintf(b, sizeof(b), "t_rot.b.%ld", (long)getpid());
	unlink(a); unlink(b);

	if (create_with(a, "src") != 0 || create_with(b, "dst") != 0) {
		complain("case1: create: %s", strerror(errno));
		unlink(a); unlink(b);
		return;
	}

	int fd = open(b, O_RDONLY);
	if (fd < 0) {
		complain("case1: open B: %s", strerror(errno));
		unlink(a); unlink(b);
		return;
	}

	if (rename(a, b) != 0) {
		complain("case1: rename: %s", strerror(errno));
		close(fd); unlink(a); unlink(b);
		return;
	}

	/* Open fd on old-B must still read "dst". */
	char buf[16] = {0};
	ssize_t r = read(fd, buf, sizeof(buf));
	close(fd);
	if (r < 0) {
		if (errno == ESTALE)
			complain("case1: open fd on renamed-over target "
				 "returned ESTALE (NFS server did not "
				 "preserve the orphaned inode)");
		else
			complain("case1: read on open fd: %s",
				 strerror(errno));
	} else if (strncmp(buf, "dst", 3) != 0) {
		complain("case1: open fd on renamed-over target read "
			 "'%s', expected 'dst' (preserved B inode)", buf);
	}

	/* Path B must now contain A's content. */
	int rfd = open(b, O_RDONLY);
	if (rfd >= 0) {
		char buf2[16] = {0};
		ssize_t r2 = read(rfd, buf2, sizeof(buf2));
		close(rfd);
		if (r2 >= 0 && strncmp(buf2, "src", 3) != 0)
			complain("case1: path B after rename read '%s', "
				 "expected 'src' (A's data)", buf2);
	} else {
		complain("case1: reopen B post-rename: %s", strerror(errno));
	}

	unlink(b);
}

static void case_rename_source_open(void)
{
	char a[64], b[64];
	snprintf(a, sizeof(a), "t_rot.sa.%ld", (long)getpid());
	snprintf(b, sizeof(b), "t_rot.sb.%ld", (long)getpid());
	unlink(a); unlink(b);

	if (create_with(a, "srcdata") != 0) {
		complain("case2: create: %s", strerror(errno));
		return;
	}
	int fd = open(a, O_RDONLY);
	if (fd < 0) {
		complain("case2: open A: %s", strerror(errno));
		unlink(a);
		return;
	}

	if (rename(a, b) != 0) {
		complain("case2: rename: %s", strerror(errno));
		close(fd); unlink(a);
		return;
	}

	char buf[16] = {0};
	ssize_t r = read(fd, buf, sizeof(buf));
	close(fd);
	if (r < 0)
		complain("case2: read open fd after rename: %s",
			 strerror(errno));
	else if (strncmp(buf, "srcdata", 7) != 0)
		complain("case2: open fd data mismatch after rename "
			 "('%s' vs 'srcdata')", buf);

	if (access(a, F_OK) == 0)
		complain("case2: source path A still exists after rename");

	unlink(b);
}

static void case_silly_rename_style(void)
{
	char a[64], b[64];
	snprintf(a, sizeof(a), "t_rot.xa.%ld", (long)getpid());
	snprintf(b, sizeof(b), "t_rot.xb.%ld", (long)getpid());
	unlink(a); unlink(b);

	if (create_with(a, "orig-a") != 0 || create_with(b, "subst-b") != 0) {
		complain("case3: create: %s", strerror(errno));
		unlink(a); unlink(b);
		return;
	}

	int fd = open(a, O_RDONLY);
	if (fd < 0) {
		complain("case3: open A: %s", strerror(errno));
		unlink(a); unlink(b);
		return;
	}
	if (unlink(a) != 0) {
		complain("case3: unlink A: %s", strerror(errno));
		close(fd); unlink(b); return;
	}
	if (rename(b, a) != 0) {
		complain("case3: rename B->A: %s", strerror(errno));
		close(fd); unlink(b); return;
	}

	char buf[16] = {0};
	ssize_t r = read(fd, buf, sizeof(buf));
	close(fd);
	if (r < 0)
		complain("case3: read on unlinked+replaced inode: %s",
			 strerror(errno));
	else if (strncmp(buf, "orig-a", 6) != 0)
		complain("case3: fd data leak across silly-rename "
			 "('%s' vs 'orig-a')", buf);

	unlink(a);
}

static void case_cross_dir_rename_open_target(void)
{
	char d1[64], d2[64], a[128], b[128];
	snprintf(d1, sizeof(d1), "t_rot.d1.%ld", (long)getpid());
	snprintf(d2, sizeof(d2), "t_rot.d2.%ld", (long)getpid());
	rmdir(d1); rmdir(d2);
	if (mkdir(d1, 0755) != 0 || mkdir(d2, 0755) != 0) {
		complain("case4: mkdir: %s", strerror(errno));
		rmdir(d1); rmdir(d2);
		return;
	}
	snprintf(a, sizeof(a), "%s/A", d1);
	snprintf(b, sizeof(b), "%s/B", d2);
	if (create_with(a, "cross-src") != 0 ||
	    create_with(b, "cross-dst") != 0) {
		complain("case4: create: %s", strerror(errno));
		goto out;
	}

	int fd = open(b, O_RDONLY);
	if (fd < 0) {
		complain("case4: open B: %s", strerror(errno));
		goto out;
	}
	if (rename(a, b) != 0) {
		complain("case4: cross-dir rename: %s", strerror(errno));
		close(fd);
		goto out;
	}

	char buf[16] = {0};
	ssize_t r = read(fd, buf, sizeof(buf));
	close(fd);
	if (r < 0) {
		if (errno == ESTALE)
			complain("case4: cross-dir rename made open fd "
				 "ESTALE");
		else
			complain("case4: read open fd: %s", strerror(errno));
	} else if (strncmp(buf, "cross-dst", 9) != 0) {
		complain("case4: cross-dir open fd read '%s', expected "
			 "'cross-dst'", buf);
	}

out:
	unlink(a);
	unlink(b);
	rmdir(d1);
	rmdir(d2);
}

static void case_rename_between_hardlinks(void)
{
	char a[64], b[64];
	snprintf(a, sizeof(a), "t_rot.ha.%ld", (long)getpid());
	snprintf(b, sizeof(b), "t_rot.hb.%ld", (long)getpid());
	unlink(a); unlink(b);

	if (create_with(a, "hl") != 0) {
		complain("case5: create: %s", strerror(errno));
		return;
	}
	if (link(a, b) != 0) {
		complain("case5: link: %s", strerror(errno));
		unlink(a);
		return;
	}

	struct stat st_before;
	if (stat(a, &st_before) != 0) {
		complain("case5: stat: %s", strerror(errno));
		goto out;
	}
	if (st_before.st_nlink != 2) {
		complain("case5: nlink before = %u, expected 2",
			 (unsigned)st_before.st_nlink);
		goto out;
	}

	/* POSIX.1-2024: rename of two paths that are the same file
	 * must succeed as a no-op. */
	if (rename(a, b) != 0) {
		if (errno == EBUSY && !Sflag)
			printf("NOTE: %s: case5 rename(A,B) of hardlinks "
			       "returned EBUSY — POSIX.1-2024 requires "
			       "success, pre-2024 semantics allowed "
			       "removal of A\n", myname);
		else
			complain("case5: rename(hardlinks): %s",
				 strerror(errno));
		goto out;
	}

	struct stat st_after_a, st_after_b;
	int have_a = (stat(a, &st_after_a) == 0);
	int have_b = (stat(b, &st_after_b) == 0);

	if (!have_a && !Sflag) {
		/* Pre-2024 permissible: A removed. */
		printf("NOTE: %s: case5 rename(A,B) of hardlinks removed "
		       "A (pre-POSIX.1-2024 semantics)\n", myname);
	} else if (have_a && have_b) {
		if (st_after_a.st_ino != st_before.st_ino ||
		    st_after_b.st_ino != st_before.st_ino)
			complain("case5: inode changed after hardlink "
				 "rename (A,B)");
		if (st_after_a.st_nlink != 2)
			complain("case5: nlink after = %u, expected 2 "
				 "(POSIX.1-2024 no-op)",
				 (unsigned)st_after_a.st_nlink);
	}

out:
	unlink(a);
	unlink(b);
}

static void case_rename_self(void)
{
	char a[64];
	snprintf(a, sizeof(a), "t_rot.se.%ld", (long)getpid());
	unlink(a);

	if (create_with(a, "self") != 0) {
		complain("case6: create: %s", strerror(errno));
		return;
	}
	struct stat st_before;
	if (stat(a, &st_before) != 0) {
		complain("case6: stat: %s", strerror(errno));
		unlink(a);
		return;
	}
	if (rename(a, a) != 0) {
		complain("case6: rename(A,A): %s", strerror(errno));
		unlink(a);
		return;
	}
	struct stat st_after;
	if (stat(a, &st_after) != 0) {
		complain("case6: stat after: %s", strerror(errno));
		unlink(a);
		return;
	}
	if (st_after.st_ino != st_before.st_ino)
		complain("case6: inode changed after rename(A,A)");

	unlink(a);
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
		"rename with source or target held open");
	cd_or_skip(myname, dir, Nflag);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_rename_over_open_target",
		 case_rename_over_open_target());
	RUN_CASE("case_rename_source_open",
		 case_rename_source_open());
	RUN_CASE("case_silly_rename_style",
		 case_silly_rename_style());
	RUN_CASE("case_cross_dir_rename_open_target",
		 case_cross_dir_rename_open_target());
	RUN_CASE("case_rename_between_hardlinks",
		 case_rename_between_hardlinks());
	RUN_CASE("case_rename_self", case_rename_self());

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}
