/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_stale_handle.c -- exercise ESTALE (stale file handle) handling
 * on NFS.
 *
 * ESTALE is the #1 NFS user complaint.  It occurs when a client
 * holds a reference (fd or cached filehandle) to an object that has
 * been removed or replaced on the server.  A correct NFS client must
 * report ESTALE to the application rather than returning stale data
 * or silently failing.
 *
 * Cases:
 *
 *   1. Open file, unlink by name, read via fd.  The fd should
 *      still work (silly rename).  Already tested in op_unlink
 *      case 7, but included here as baseline.
 *
 *   2. Open file, unlink by name, stat by name.  Must return
 *      ENOENT (the name is gone).  The fd (if held) remains valid.
 *
 *   3. Open directory fd, rmdir from another path, readdir via fd.
 *      Should return ENOENT or succeed with empty results (the
 *      kernel may have cached the directory).  On NFS this tests
 *      the READDIR-on-removed-directory path.
 *
 *   4. Create, open, rename the file.  The fd should track the
 *      inode, not the name.  Write via fd, fstat — must still
 *      work after the name changed.
 *
 *   5. Hard-link open file, unlink original.  Access via fd must
 *      succeed.  Access via the surviving link name must succeed.
 *
 * Portable: POSIX across Linux / FreeBSD / macOS / Solaris.
 */

#define _POSIX_C_SOURCE 200809L

#include "tests.h"

#include <dirent.h>
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

static const char *myname = "op_stale_handle";

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  exercise ESTALE / stale file handle scenarios\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

static void case_open_unlink_read(void)
{
	char name[64];
	int fd = scratch_open("t_sh.or", name, sizeof(name));

	unsigned char wbuf[128];
	fill_pattern(wbuf, sizeof(wbuf), 1);
	if (pwrite_all(fd, wbuf, sizeof(wbuf), 0, "case1: write") != 0) {
		close(fd); unlink(name); return;
	}

	if (unlink(name) != 0) {
		complain("case1: unlink: %s", strerror(errno));
		close(fd); return;
	}

	unsigned char rbuf[128];
	if (pread_all(fd, rbuf, sizeof(rbuf), 0, "case1: read after unlink") == 0) {
		size_t mis = check_pattern(rbuf, sizeof(rbuf), 1);
		if (mis)
			complain("case1: data corrupted at byte %zu after "
				 "unlink (silly rename path)", mis - 1);
	}
	close(fd);
}

static void case_unlink_stat_enoent(void)
{
	char name[64];
	int fd = scratch_open("t_sh.se", name, sizeof(name));
	close(fd);

	if (unlink(name) != 0) {
		complain("case2: unlink: %s", strerror(errno));
		return;
	}

	struct stat st;
	errno = 0;
	if (stat(name, &st) == 0)
		complain("case2: stat after unlink succeeded (expected ENOENT)");
	else if (errno != ENOENT)
		complain("case2: expected ENOENT, got %s", strerror(errno));
}

static void case_rmdir_readdir(void)
{
	char d[64];
	snprintf(d, sizeof(d), "t_sh.rd.%ld", (long)getpid());
	rmdir(d);
	if (mkdir(d, 0755) != 0) {
		complain("case3: mkdir: %s", strerror(errno));
		return;
	}

	int dirfd = open(d, O_RDONLY | O_DIRECTORY);
	if (dirfd < 0) {
		complain("case3: open dir: %s", strerror(errno));
		rmdir(d);
		return;
	}

	if (rmdir(d) != 0) {
		complain("case3: rmdir: %s", strerror(errno));
		close(dirfd);
		return;
	}

	DIR *dp = fdopendir(dup(dirfd));
	if (dp) {
		struct dirent *de;
		errno = 0;
		while ((de = readdir(dp)) != NULL)
			;
		if (errno != 0 && errno != ENOENT && errno != ESTALE) {
			if (!Sflag)
				printf("NOTE: %s: case3 readdir on removed "
				       "dir: %s\n", myname, strerror(errno));
		}
		closedir(dp);
	} else {
		if (errno != ENOENT && errno != ESTALE && errno != EBADF) {
			if (!Sflag)
				printf("NOTE: %s: case3 fdopendir on removed "
				       "dir: %s\n", myname, strerror(errno));
		}
	}
	close(dirfd);
}

static void case_rename_fd_tracks_inode(void)
{
	char old[64], new_name[64];
	int fd = scratch_open("t_sh.ri", old, sizeof(old));
	snprintf(new_name, sizeof(new_name), "t_sh.rn.%ld", (long)getpid());
	unlink(new_name);

	unsigned char wbuf[64];
	fill_pattern(wbuf, sizeof(wbuf), 4);
	if (pwrite_all(fd, wbuf, sizeof(wbuf), 0, "case4: write") != 0) {
		close(fd); unlink(old); return;
	}

	if (rename(old, new_name) != 0) {
		complain("case4: rename: %s", strerror(errno));
		close(fd); unlink(old); return;
	}

	/* fd should still reference the inode. */
	struct stat st;
	if (fstat(fd, &st) != 0)
		complain("case4: fstat after rename: %s", strerror(errno));

	unsigned char rbuf[64];
	if (pread_all(fd, rbuf, sizeof(rbuf), 0, "case4: read after rename") == 0) {
		size_t mis = check_pattern(rbuf, sizeof(rbuf), 4);
		if (mis)
			complain("case4: data via fd corrupted after rename "
				 "at byte %zu", mis - 1);
	}

	/* Write more via fd. */
	fill_pattern(wbuf, sizeof(wbuf), 5);
	if (pwrite_all(fd, wbuf, sizeof(wbuf), 64, "case4: write2") != 0) {
		close(fd); unlink(new_name); return;
	}

	if (fstat(fd, &st) != 0)
		complain("case4: fstat after write2: %s", strerror(errno));
	else if (st.st_size != 128)
		complain("case4: size %lld after write2, expected 128",
			 (long long)st.st_size);

	close(fd);
	unlink(new_name);
	unlink(old);
}

static void case_hardlink_unlink_original(void)
{
	char a[64], b[64];
	int fd = scratch_open("t_sh.ha", a, sizeof(a));
	snprintf(b, sizeof(b), "t_sh.hb.%ld", (long)getpid());
	unlink(b);

	unsigned char wbuf[64];
	fill_pattern(wbuf, sizeof(wbuf), 6);
	if (pwrite_all(fd, wbuf, sizeof(wbuf), 0, "case5: write") != 0) {
		close(fd); unlink(a); return;
	}

	if (link(a, b) != 0) {
		if (errno == EOPNOTSUPP || errno == ENOTSUP) {
			if (!Sflag)
				printf("NOTE: %s: case5 skipped (hard links "
				       "not supported)\n", myname);
			close(fd); unlink(a); return;
		}
		complain("case5: link: %s", strerror(errno));
		close(fd); unlink(a); return;
	}

	if (unlink(a) != 0) {
		complain("case5: unlink original: %s", strerror(errno));
		close(fd); unlink(b); return;
	}

	/* fd still valid. */
	unsigned char rbuf[64];
	if (pread_all(fd, rbuf, sizeof(rbuf), 0, "case5: read via fd") == 0) {
		size_t mis = check_pattern(rbuf, sizeof(rbuf), 6);
		if (mis)
			complain("case5: fd data corrupted at byte %zu", mis - 1);
	}

	/* Second name still valid. */
	int fd2 = open(b, O_RDONLY);
	if (fd2 < 0) {
		complain("case5: open via second link: %s", strerror(errno));
	} else {
		if (pread_all(fd2, rbuf, sizeof(rbuf), 0, "case5: read via link") == 0) {
			size_t mis = check_pattern(rbuf, sizeof(rbuf), 6);
			if (mis)
				complain("case5: link data corrupted at byte %zu",
					 mis - 1);
		}
		close(fd2);
	}

	close(fd);
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

	prelude(myname, "ESTALE / stale file handle scenarios");
	cd_or_skip(myname, dir, Nflag);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_open_unlink_read", case_open_unlink_read());
	RUN_CASE("case_unlink_stat_enoent", case_unlink_stat_enoent());
	RUN_CASE("case_rmdir_readdir", case_rmdir_readdir());
	RUN_CASE("case_rename_fd_tracks_inode", case_rename_fd_tracks_inode());
	RUN_CASE("case_hardlink_unlink_original", case_hardlink_unlink_original());

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}
