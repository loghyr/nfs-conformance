/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_symlink_nofollow.c -- exercise AT_SYMLINK_NOFOLLOW semantics
 * across the *at() syscall family (POSIX.1-2008).
 *
 * AT_SYMLINK_NOFOLLOW is the single biggest conformance gap in NFS
 * server implementations.  It controls whether a syscall operates on
 * the symlink object itself or follows the symlink to its target.
 * Tools like tar, rsync, and cp -a depend on this to preserve
 * symlink ownership and timestamps during archive/restore operations.
 *
 * On the wire, AT_SYMLINK_NOFOLLOW maps to NFSv4 GETATTR/SETATTR
 * on the symlink's own filehandle (obtained via LOOKUP without
 * following) rather than the target's filehandle.
 *
 * Cases:
 *
 *   1. [POSIX] fstatat(AT_SYMLINK_NOFOLLOW).  Create a symlink
 *      to a regular file.  fstatat with AT_SYMLINK_NOFOLLOW must
 *      return S_IFLNK; without the flag must return S_IFREG.
 *
 *   2. [POSIX] fstatat(AT_SYMLINK_NOFOLLOW) on dangling symlink.
 *      The symlink target does not exist.  fstatat without flag
 *      returns ENOENT; with AT_SYMLINK_NOFOLLOW succeeds and
 *      returns S_IFLNK.
 *
 *   3. [POSIX] utimensat(AT_SYMLINK_NOFOLLOW).  Set timestamps on
 *      the symlink itself.  Verify the symlink's mtime changed but
 *      the target's mtime did NOT change.  Some NFS servers silently
 *      follow the symlink and modify the target — this catches that.
 *
 *   4. [POSIX] fchownat(AT_SYMLINK_NOFOLLOW).  Requires root.
 *      Change ownership of the symlink itself.  Verify via lstat
 *      that the symlink's uid changed but the target's uid did NOT.
 *      This is the operation tar/rsync use to preserve symlink
 *      ownership.
 *
 *   5. [POSIX] linkat(AT_SYMLINK_FOLLOW) vs default.  linkat
 *      without AT_SYMLINK_FOLLOW should create a hard linkname to the
 *      symlink itself (or EOPNOTSUPP on filesystems that don't
 *      support hard links to symlinks).  With AT_SYMLINK_FOLLOW,
 *      the hard linkname should reference the target.
 *
 *   6. [POSIX] O_NOFOLLOW.  open(symlink, O_NOFOLLOW) must fail
 *      with ELOOP (or EMLINK on some systems).  Exercises the NFS
 *      OPEN path's symlink detection.
 *
 *   7. [POSIX] O_NOFOLLOW on regular file.  open(regular_file,
 *      O_NOFOLLOW) must succeed.  The flag only rejects symlinks.
 *
 *   8. [POSIX] O_NOFOLLOW on symlink chain.  Symlink -> symlink ->
 *      file.  open with O_NOFOLLOW on the first symlink must fail
 *      (it IS a symlink), even though the ultimate target exists.
 *
 * Portable: POSIX.1-2008 across Linux / FreeBSD / macOS / Solaris.
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

int Hflag = 0;
int Sflag = 0;
int Tflag = 0;
int Fflag = 0;
int Nflag = 0;

static const char *myname = "op_symlink_nofollow";

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  exercise AT_SYMLINK_NOFOLLOW across *at() syscalls "
		"(POSIX.1-2008)\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

static void case_fstatat_nofollow(void)
{
	char target[64], linkname[64];
	snprintf(target, sizeof(target), "t_snf.t1.%ld", (long)getpid());
	snprintf(linkname, sizeof(linkname), "t_snf.l1.%ld", (long)getpid());
	unlink(target); unlink(linkname);

	int fd = open(target, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) { complain("case1: create target: %s", strerror(errno)); return; }
	close(fd);

	if (symlink(target, linkname) != 0) {
		complain("case1: symlink: %s", strerror(errno));
		unlink(target);
		return;
	}

	struct stat st_follow, st_nofollow;
	if (fstatat(AT_FDCWD, linkname, &st_follow, 0) != 0) {
		complain("case1: fstatat(follow): %s", strerror(errno));
		goto out;
	}
	if (fstatat(AT_FDCWD, linkname, &st_nofollow, AT_SYMLINK_NOFOLLOW) != 0) {
		complain("case1: fstatat(AT_SYMLINK_NOFOLLOW): %s",
			 strerror(errno));
		goto out;
	}

	if (!S_ISREG(st_follow.st_mode))
		complain("case1: fstatat(follow) expected S_IFREG, got 0%o",
			 st_follow.st_mode & S_IFMT);
	if (!S_ISLNK(st_nofollow.st_mode))
		complain("case1: fstatat(AT_SYMLINK_NOFOLLOW) expected "
			 "S_IFLNK, got 0%o (NFS server may be following "
			 "the symlink on GETATTR)",
			 st_nofollow.st_mode & S_IFMT);
out:
	unlink(linkname);
	unlink(target);
}

static void case_fstatat_dangling(void)
{
	char linkname[64];
	snprintf(linkname, sizeof(linkname), "t_snf.d2.%ld", (long)getpid());
	unlink(linkname);

	if (symlink("nonexistent_target_xyzzy", linkname) != 0) {
		complain("case2: symlink: %s", strerror(errno));
		return;
	}

	struct stat st;
	errno = 0;
	if (fstatat(AT_FDCWD, linkname, &st, 0) == 0)
		complain("case2: fstatat(follow) on dangling symlink "
			 "succeeded (expected ENOENT)");
	else if (errno != ENOENT)
		complain("case2: fstatat(follow) expected ENOENT, got %s",
			 strerror(errno));

	if (fstatat(AT_FDCWD, linkname, &st, AT_SYMLINK_NOFOLLOW) != 0) {
		complain("case2: fstatat(AT_SYMLINK_NOFOLLOW) on dangling "
			 "symlink: %s (must succeed — operates on the "
			 "symlink itself)", strerror(errno));
		goto out;
	}
	if (!S_ISLNK(st.st_mode))
		complain("case2: fstatat(NOFOLLOW) on dangling expected "
			 "S_IFLNK, got 0%o", st.st_mode & S_IFMT);
out:
	unlink(linkname);
}

static void case_utimensat_nofollow(void)
{
	char target[64], linkname[64];
	snprintf(target, sizeof(target), "t_snf.t3.%ld", (long)getpid());
	snprintf(linkname, sizeof(linkname), "t_snf.l3.%ld", (long)getpid());
	unlink(target); unlink(linkname);

	int fd = open(target, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) { complain("case3: create: %s", strerror(errno)); return; }
	close(fd);

	if (symlink(target, linkname) != 0) {
		complain("case3: symlink: %s", strerror(errno));
		unlink(target);
		return;
	}

	/* Set target to a known baseline. */
	struct timespec ts_target[2] = {{ 500, 0 }, { 500, 0 }};
	utimensat(AT_FDCWD, target, ts_target, 0);

	/* Set the symlink's own timestamps via AT_SYMLINK_NOFOLLOW. */
	struct timespec ts_link[2] = {{ 999, 111 }, { 999, 222 }};
	if (utimensat(AT_FDCWD, linkname, ts_link, AT_SYMLINK_NOFOLLOW) != 0) {
		if (errno == ENOTSUP || errno == EOPNOTSUPP) {
			if (!Sflag)
				printf("NOTE: %s: case3 utimensat "
				       "AT_SYMLINK_NOFOLLOW not supported "
				       "on this filesystem/server\n", myname);
			goto out;
		}
		complain("case3: utimensat(AT_SYMLINK_NOFOLLOW): %s",
			 strerror(errno));
		goto out;
	}

	/* Verify target's mtime was NOT changed. */
	struct stat st_target;
	if (stat(target, &st_target) != 0) {
		complain("case3: stat target: %s", strerror(errno));
		goto out;
	}
	if (st_target.st_mtime != 500)
		complain("case3: target mtime changed to %ld (expected 500 "
			 "unchanged) — NFS server followed the symlink on "
			 "SETATTR instead of operating on the symlink itself",
			 (long)st_target.st_mtime);

out:
	unlink(linkname);
	unlink(target);
}

static void case_fchownat_nofollow(void)
{
	if (getuid() != 0) {
		if (!Sflag)
			printf("NOTE: %s: case4 skipped (requires root for "
			       "fchownat)\n", myname);
		return;
	}

	char target[64], linkname[64];
	snprintf(target, sizeof(target), "t_snf.t4.%ld", (long)getpid());
	snprintf(linkname, sizeof(linkname), "t_snf.l4.%ld", (long)getpid());
	unlink(target); unlink(linkname);

	int fd = open(target, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) { complain("case4: create: %s", strerror(errno)); return; }
	close(fd);

	/* Ensure target is owned by root. */
	chown(target, 0, 0);

	if (symlink(target, linkname) != 0) {
		complain("case4: symlink: %s", strerror(errno));
		unlink(target);
		return;
	}

	/* Change symlink ownership to nobody (65534). */
	if (fchownat(AT_FDCWD, linkname, 65534, 65534,
		     AT_SYMLINK_NOFOLLOW) != 0) {
		if (errno == EOPNOTSUPP || errno == ENOTSUP) {
			if (!Sflag)
				printf("NOTE: %s: case4 fchownat "
				       "AT_SYMLINK_NOFOLLOW not supported\n",
				       myname);
			goto out;
		}
		complain("case4: fchownat(AT_SYMLINK_NOFOLLOW): %s",
			 strerror(errno));
		goto out;
	}

	/* Verify symlink owned by nobody. */
	struct stat st_link;
	if (lstat(linkname, &st_link) != 0) {
		complain("case4: lstat linkname: %s", strerror(errno));
		goto out;
	}
	if (st_link.st_uid != 65534)
		complain("case4: symlink uid %u, expected 65534",
			 (unsigned)st_link.st_uid);

	/* Verify target still owned by root. */
	struct stat st_target;
	if (stat(target, &st_target) != 0) {
		complain("case4: stat target: %s", strerror(errno));
		goto out;
	}
	if (st_target.st_uid != 0)
		complain("case4: target uid changed to %u (expected 0 "
			 "unchanged) — NFS server followed the symlink "
			 "on SETATTR instead of operating on the symlink "
			 "(tar/rsync depend on this for archive fidelity)",
			 (unsigned)st_target.st_uid);
out:
	unlink(linkname);
	unlink(target);
}

static void case_linkat_follow(void)
{
	char target[64], linkname[64], hardlink[64];
	snprintf(target, sizeof(target), "t_snf.t5.%ld", (long)getpid());
	snprintf(linkname, sizeof(linkname), "t_snf.l5.%ld", (long)getpid());
	snprintf(hardlink, sizeof(hardlink), "t_snf.h5.%ld", (long)getpid());
	unlink(target); unlink(linkname); unlink(hardlink);

	int fd = open(target, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) { complain("case5: create: %s", strerror(errno)); return; }
	close(fd);

	if (symlink(target, linkname) != 0) {
		complain("case5: symlink: %s", strerror(errno));
		unlink(target);
		return;
	}

	/* linkat with AT_SYMLINK_FOLLOW: hard linkname to the TARGET. */
	if (linkat(AT_FDCWD, linkname, AT_FDCWD, hardlink,
		   AT_SYMLINK_FOLLOW) != 0) {
		complain("case5: linkat(AT_SYMLINK_FOLLOW): %s",
			 strerror(errno));
		goto out;
	}

	struct stat st_target, st_hardlink;
	if (stat(target, &st_target) != 0 || stat(hardlink, &st_hardlink) != 0) {
		complain("case5: stat: %s", strerror(errno));
		goto out;
	}

	if (st_target.st_ino != st_hardlink.st_ino)
		complain("case5: linkat(AT_SYMLINK_FOLLOW) ino %lu != "
			 "target ino %lu (should be same inode)",
			 (unsigned long)st_hardlink.st_ino,
			 (unsigned long)st_target.st_ino);

	/* linkat without AT_SYMLINK_FOLLOW: hard linkname to the SYMLINK.
	 * Many filesystems (including NFS) don't support hard links to
	 * symlinks — EOPNOTSUPP/EPERM is acceptable. */
	char hardlink2[64];
	snprintf(hardlink2, sizeof(hardlink2), "t_snf.h5b.%ld", (long)getpid());
	unlink(hardlink2);
	errno = 0;
	if (linkat(AT_FDCWD, linkname, AT_FDCWD, hardlink2, 0) == 0) {
		struct stat st_hl2;
		if (lstat(hardlink2, &st_hl2) == 0 && S_ISLNK(st_hl2.st_mode)) {
			/* Good: created a hard linkname to the symlink itself. */
		} else if (lstat(hardlink2, &st_hl2) == 0 &&
			   st_hl2.st_ino == st_target.st_ino) {
			if (!Sflag)
				printf("NOTE: %s: case5 linkat(0) followed "
				       "the symlink (some servers do this)\n",
				       myname);
		}
		unlink(hardlink2);
	} else if (errno != EOPNOTSUPP && errno != EPERM &&
		   errno != ENOTSUP && errno != EMLINK) {
		complain("case5: linkat(0) unexpected error: %s",
			 strerror(errno));
	}

out:
	unlink(hardlink);
	unlink(linkname);
	unlink(target);
}

static void case_open_nofollow(void)
{
	char target[64], linkname[64];
	snprintf(target, sizeof(target), "t_snf.t6.%ld", (long)getpid());
	snprintf(linkname, sizeof(linkname), "t_snf.l6.%ld", (long)getpid());
	unlink(target); unlink(linkname);

	int fd = open(target, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) { complain("case6: create: %s", strerror(errno)); return; }
	close(fd);

	if (symlink(target, linkname) != 0) {
		complain("case6: symlink: %s", strerror(errno));
		unlink(target);
		return;
	}

	errno = 0;
	fd = open(linkname, O_RDONLY | O_NOFOLLOW);
	if (fd >= 0) {
		complain("case6: open(symlink, O_NOFOLLOW) succeeded "
			 "(must fail with ELOOP)");
		close(fd);
	} else if (errno != ELOOP && errno != EMLINK) {
		complain("case6: expected ELOOP, got %s", strerror(errno));
	}

	unlink(linkname);
	unlink(target);
}

static void case_open_nofollow_regular(void)
{
	char a[64];
	snprintf(a, sizeof(a), "t_snf.r7.%ld", (long)getpid());
	unlink(a);

	int fd = open(a, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) { complain("case7: create: %s", strerror(errno)); return; }
	close(fd);

	fd = open(a, O_RDONLY | O_NOFOLLOW);
	if (fd < 0)
		complain("case7: open(regular, O_NOFOLLOW) failed: %s "
			 "(must succeed — O_NOFOLLOW only rejects symlinks)",
			 strerror(errno));
	else
		close(fd);

	unlink(a);
}

static void case_open_nofollow_chain(void)
{
	char target[64], link1[64], link2[64];
	snprintf(target, sizeof(target), "t_snf.t8.%ld", (long)getpid());
	snprintf(link1, sizeof(link1), "t_snf.c8a.%ld", (long)getpid());
	snprintf(link2, sizeof(link2), "t_snf.c8b.%ld", (long)getpid());
	unlink(target); unlink(link1); unlink(link2);

	int fd = open(target, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) { complain("case8: create: %s", strerror(errno)); return; }
	close(fd);

	if (symlink(target, link2) != 0 || symlink(link2, link1) != 0) {
		complain("case8: symlink chain: %s", strerror(errno));
		unlink(link1); unlink(link2); unlink(target);
		return;
	}

	errno = 0;
	fd = open(link1, O_RDONLY | O_NOFOLLOW);
	if (fd >= 0) {
		complain("case8: open(symlink->symlink->file, O_NOFOLLOW) "
			 "succeeded (must fail — the path IS a symlink)");
		close(fd);
	} else if (errno != ELOOP && errno != EMLINK) {
		complain("case8: expected ELOOP, got %s", strerror(errno));
	}

	unlink(link1);
	unlink(link2);
	unlink(target);
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
		"AT_SYMLINK_NOFOLLOW / O_NOFOLLOW across *at() syscalls "
		"(POSIX.1-2008)");
	cd_or_skip(myname, dir, Nflag);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("fstatat_nofollow", case_fstatat_nofollow());
	RUN_CASE("fstatat_dangling", case_fstatat_dangling());
	RUN_CASE("utimensat_nofollow", case_utimensat_nofollow());
	RUN_CASE("fchownat_nofollow", case_fchownat_nofollow());
	RUN_CASE("linkat_follow", case_linkat_follow());
	RUN_CASE("open_nofollow", case_open_nofollow());
	RUN_CASE("open_nofollow_regular", case_open_nofollow_regular());
	RUN_CASE("open_nofollow_chain", case_open_nofollow_chain());

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}
