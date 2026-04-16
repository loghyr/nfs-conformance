/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_rename_self.c -- exercise rename() edge cases where source and
 * destination refer to the same file (POSIX.1-2024 Issue 8
 * clarification, retroactively applicable).
 *
 * POSIX.1-2024 tightened the semantics: if old and new refer to the
 * same file (same inode — whether via the same name, hard links, or
 * symlink resolution), rename must succeed as a no-op.  Prior
 * standards were ambiguous, and some NFS servers incorrectly return
 * errors or unlink one name.
 *
 * Cases:
 *
 *   1. [POSIX] rename(a, a) — same path.  Must succeed as a no-op.
 *      File must still exist with the same inode and data.
 *
 *   2. [POSIX] rename(a, b) where a and b are hard links to the
 *      same inode.  Must succeed as a no-op.  BOTH names must
 *      survive.  nlink must not change.  This is the case that
 *      POSIX.1-2024 explicitly clarified.
 *
 *   3. [POSIX] rename(a, a) on a directory.  Must succeed as a
 *      no-op.  Directory still exists, nlink unchanged.
 *
 *   4. [POSIX] rename(symlink, target) where the symlink points
 *      to target.  This is NOT the same file — rename should
 *      replace target with the symlink.  Verifies the server
 *      does NOT treat "resolves to same inode" as "same name".
 *      (rename operates on directory entries, not resolved inodes.)
 *
 *   5. renameat(dirfd, name, dirfd, name).  Same-path rename via
 *      the *at variant with a real directory fd.  Must succeed.
 *
 *   6. rename(a, b) hardlinks, verify data preserved.  Write a
 *      pattern, create hardlink, rename one over the other, verify
 *      data is intact and accessible via surviving name.
 *
 * Portable: POSIX across Linux / FreeBSD / macOS / Solaris.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

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

static const char *myname = "op_rename_self";

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  exercise rename() same-file edge cases "
		"(POSIX.1-2024 clarification)\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

static void case_same_path(void)
{
	char a[64];
	snprintf(a, sizeof(a), "t_rs.sp.%ld", (long)getpid());
	unlink(a);

	int fd = open(a, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) { complain("case1: create: %s", strerror(errno)); return; }
	close(fd);

	struct stat st_before;
	if (stat(a, &st_before) != 0) {
		complain("case1: stat before: %s", strerror(errno));
		unlink(a);
		return;
	}

	if (rename(a, a) != 0) {
		complain("case1: rename(a, a) failed: %s "
			 "(POSIX: must succeed as no-op)", strerror(errno));
		unlink(a);
		return;
	}

	struct stat st_after;
	if (stat(a, &st_after) != 0) {
		complain("case1: file vanished after rename(a, a)");
		return;
	}
	if (st_after.st_ino != st_before.st_ino)
		complain("case1: inode changed after rename(a, a)");

	unlink(a);
}

static void case_hardlink_self(void)
{
	char a[64], b[64];
	snprintf(a, sizeof(a), "t_rs.ha.%ld", (long)getpid());
	snprintf(b, sizeof(b), "t_rs.hb.%ld", (long)getpid());
	unlink(a); unlink(b);

	int fd = open(a, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) { complain("case2: create: %s", strerror(errno)); return; }
	close(fd);

	if (link(a, b) != 0) {
		if (errno == EOPNOTSUPP || errno == ENOTSUP) {
			if (!Sflag)
				printf("NOTE: %s: case2 skipped (hard links "
				       "not supported)\n", myname);
			unlink(a);
			return;
		}
		complain("case2: link: %s", strerror(errno));
		unlink(a);
		return;
	}

	struct stat st_before;
	if (stat(a, &st_before) != 0) {
		complain("case2: stat before: %s", strerror(errno));
		unlink(a); unlink(b);
		return;
	}

	if (rename(a, b) != 0) {
		complain("case2: rename(a, b) where both are hardlinks to "
			 "same inode: %s (POSIX.1-2024: must succeed as "
			 "no-op)", strerror(errno));
		unlink(a); unlink(b);
		return;
	}

	/* BOTH names must survive. */
	struct stat st_a, st_b;
	int a_exists = (stat(a, &st_a) == 0);
	int b_exists = (stat(b, &st_b) == 0);

	if (!b_exists)
		complain("case2: name 'b' vanished after rename");
	if (!a_exists) {
		/*
		 * This is the common failure mode: the server treats
		 * rename(a, b) as "unlink a, link b" which removes a.
		 * POSIX.1-2024 says this is wrong when a and b are the
		 * same file.
		 */
		complain("case2: name 'a' vanished after rename(a, b) "
			 "where both are hardlinks to same inode — "
			 "server incorrectly unlinked the source "
			 "(POSIX.1-2024 requires no-op)");
	}
	if (a_exists && b_exists) {
		if (st_a.st_nlink != st_before.st_nlink)
			complain("case2: nlink changed from %lu to %lu "
				 "(must be unchanged)",
				 (unsigned long)st_before.st_nlink,
				 (unsigned long)st_a.st_nlink);
	}

	unlink(a); unlink(b);
}

static void case_dir_same_path(void)
{
	char d[64];
	snprintf(d, sizeof(d), "t_rs.dd.%ld", (long)getpid());
	rmdir(d);
	if (mkdir(d, 0755) != 0) {
		complain("case3: mkdir: %s", strerror(errno));
		return;
	}

	struct stat st_before;
	stat(d, &st_before);

	if (rename(d, d) != 0) {
		complain("case3: rename(dir, dir) failed: %s",
			 strerror(errno));
		rmdir(d);
		return;
	}

	struct stat st_after;
	if (stat(d, &st_after) != 0) {
		complain("case3: directory vanished after rename(d, d)");
		return;
	}
	if (st_after.st_nlink != st_before.st_nlink)
		complain("case3: dir nlink changed after self-rename");

	rmdir(d);
}

static void case_symlink_to_target(void)
{
	char target[64], link[64];
	snprintf(target, sizeof(target), "t_rs.st.%ld", (long)getpid());
	snprintf(link, sizeof(link), "t_rs.sl.%ld", (long)getpid());
	unlink(target); unlink(link);

	int fd = open(target, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) { complain("case4: create: %s", strerror(errno)); return; }
	close(fd);

	if (symlink(target, link) != 0) {
		complain("case4: symlink: %s", strerror(errno));
		unlink(target);
		return;
	}

	/*
	 * rename(link, target): the symlink "link" points to "target".
	 * These resolve to the same inode, but rename operates on
	 * directory entries, NOT resolved inodes.  This should replace
	 * "target" (the regular file) with "link" (the symlink).
	 */
	if (rename(link, target) != 0) {
		complain("case4: rename(symlink, target): %s",
			 strerror(errno));
		unlink(link);
		unlink(target);
		return;
	}

	struct stat st;
	if (lstat(target, &st) != 0) {
		complain("case4: lstat(target) after rename: %s",
			 strerror(errno));
		return;
	}

	if (!S_ISLNK(st.st_mode))
		complain("case4: after rename(symlink, target), 'target' "
			 "should be a symlink (S_IFLNK) but got mode 0%o "
			 "(server may have resolved the symlink before "
			 "renaming)", st.st_mode & S_IFMT);

	/* The original "link" name should be gone. */
	errno = 0;
	if (lstat(link, &st) == 0)
		complain("case4: symlink name still exists after rename");

	unlink(target);
	unlink(link);
}

static void case_renameat_same(void)
{
	char sub[64], file[128];
	snprintf(sub, sizeof(sub), "t_rs.ra.%ld", (long)getpid());
	snprintf(file, sizeof(file), "%s/f", sub);

	unlink(file); rmdir(sub);
	if (mkdir(sub, 0755) != 0) {
		complain("case5: mkdir: %s", strerror(errno));
		return;
	}

	int fd = open(file, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("case5: create: %s", strerror(errno));
		rmdir(sub);
		return;
	}
	close(fd);

	int dirfd = open(sub, O_RDONLY | O_DIRECTORY);
	if (dirfd < 0) {
		complain("case5: open dir: %s", strerror(errno));
		unlink(file);
		rmdir(sub);
		return;
	}

	if (renameat(dirfd, "f", dirfd, "f") != 0)
		complain("case5: renameat(dirfd, f, dirfd, f): %s "
			 "(must succeed as no-op)", strerror(errno));

	struct stat st;
	if (fstatat(dirfd, "f", &st, 0) != 0)
		complain("case5: file vanished after renameat self");

	close(dirfd);
	unlink(file);
	rmdir(sub);
}

static void case_hardlink_data_preserved(void)
{
	char a[64], b[64];
	snprintf(a, sizeof(a), "t_rs.dp.a.%ld", (long)getpid());
	snprintf(b, sizeof(b), "t_rs.dp.b.%ld", (long)getpid());
	unlink(a); unlink(b);

	int fd = open(a, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) { complain("case6: create: %s", strerror(errno)); return; }

	unsigned char wbuf[256];
	fill_pattern(wbuf, sizeof(wbuf), 77);
	if (pwrite_all(fd, wbuf, sizeof(wbuf), 0, "case6: write") != 0) {
		close(fd);
		unlink(a);
		return;
	}
	close(fd);

	if (link(a, b) != 0) {
		if (errno == EOPNOTSUPP || errno == ENOTSUP) {
			if (!Sflag)
				printf("NOTE: %s: case6 skipped (hard links "
				       "not supported)\n", myname);
			unlink(a);
			return;
		}
		complain("case6: link: %s", strerror(errno));
		unlink(a);
		return;
	}

	if (rename(a, b) != 0) {
		complain("case6: rename: %s", strerror(errno));
		unlink(a); unlink(b);
		return;
	}

	/* At least 'b' must exist with correct data. */
	fd = open(b, O_RDONLY);
	if (fd < 0) {
		complain("case6: open(b) after rename: %s", strerror(errno));
		unlink(a); unlink(b);
		return;
	}

	unsigned char rbuf[256];
	if (pread_all(fd, rbuf, sizeof(rbuf), 0, "case6: read") == 0) {
		size_t mis = check_pattern(rbuf, sizeof(rbuf), 77);
		if (mis)
			complain("case6: data corrupted at byte %zu after "
				 "hardlink self-rename", mis - 1);
	}
	close(fd);
	unlink(a);
	unlink(b);
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
		"rename() same-file edge cases (POSIX.1-2024 clarification)");
	cd_or_skip(myname, dir, Nflag);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_same_path", case_same_path());
	RUN_CASE("case_hardlink_self", case_hardlink_self());
	RUN_CASE("case_dir_same_path", case_dir_same_path());
	RUN_CASE("case_symlink_to_target", case_symlink_to_target());
	RUN_CASE("case_renameat_same", case_renameat_same());
	RUN_CASE("case_hardlink_data_preserved",
		 case_hardlink_data_preserved());

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}
