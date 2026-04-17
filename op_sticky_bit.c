/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_sticky_bit.c -- exercise sticky-bit (S_ISVTX) semantics on
 * directories (the /tmp permission model).
 *
 * POSIX.1-2008: when the sticky bit is set on a directory, a file
 * in that directory may be renamed or unlinked only by the file's
 * owner, the directory's owner, or the superuser.  This test
 * exercises the parts that do not require a second uid:
 *
 *   - S_ISVTX round-trip: chmod +t sets the bit; stat reads it back.
 *   - Sticky bit is preserved across close / reopen.
 *   - Owner of a file in a sticky dir can still unlink / rename it.
 *
 * The full enforcement test (that a DIFFERENT user cannot unlink
 * someone else's file in a sticky dir) requires privilege-dropping
 * and is not attempted here; we emit a NOTE explaining the gap.
 * Use pjdfstest or xfstests for the multi-uid story.
 *
 * Cases:
 *
 *   1. S_ISVTX round-trip: mkdir, chmod 01777, stat verifies
 *      (mode & S_ISVTX) is set.
 *
 *   2. Sticky bit persists: close any implicit handles, re-stat,
 *      bit still set.
 *
 *   3. Owner can unlink their own file in a sticky dir.  This is
 *      the permissive half of the model -- owners are unaffected
 *      by S_ISVTX.
 *
 *   4. Owner can rename their own file within a sticky dir.
 *
 *   5. NOTE: cross-user enforcement requires a second uid and
 *      is skipped here.
 *
 * Portable: POSIX.  On NFS the sticky bit must propagate to the
 * server (SETATTR with mode including 01000); some servers mask
 * sticky on non-root files.
 */

#define _POSIX_C_SOURCE 200809L

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

static const char *myname = "op_sticky_bit";

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  exercise sticky-bit (S_ISVTX) on directories\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

static void case_isvtx_round_trip(void)
{
	char d[64];
	snprintf(d, sizeof(d), "t_sb.rt.%ld", (long)getpid());
	rmdir(d);

	if (mkdir(d, 0755) != 0) {
		complain("case1: mkdir: %s", strerror(errno));
		return;
	}
	if (chmod(d, 01777) != 0) {
		complain("case1: chmod +t 1777: %s", strerror(errno));
		rmdir(d);
		return;
	}

	struct stat st;
	if (stat(d, &st) != 0) {
		complain("case1: stat: %s", strerror(errno));
		rmdir(d);
		return;
	}
	if (!(st.st_mode & S_ISVTX))
		complain("case1: S_ISVTX not set after chmod 01777 "
			 "(server did not propagate sticky bit)");
	if ((st.st_mode & 0777) != 0777)
		complain("case1: mode bits 0%o, expected 0777",
			 st.st_mode & 0777);

	rmdir(d);
}

static void case_isvtx_persists(void)
{
	char d[64];
	snprintf(d, sizeof(d), "t_sb.pp.%ld", (long)getpid());
	rmdir(d);
	if (mkdir(d, 0755) != 0) { complain("case2: mkdir: %s", strerror(errno)); return; }
	if (chmod(d, 01755) != 0) {
		complain("case2: chmod: %s", strerror(errno));
		rmdir(d); return;
	}

	/* Open and close the dir to ensure no implicit state held.
	 * Then re-stat via a fresh path lookup. */
	int fd = open(d, O_RDONLY);
	if (fd >= 0) close(fd);

	struct stat st;
	if (stat(d, &st) != 0) {
		complain("case2: stat: %s", strerror(errno));
		rmdir(d); return;
	}
	if (!(st.st_mode & S_ISVTX))
		complain("case2: S_ISVTX not preserved after open+close+stat");

	rmdir(d);
}

static void case_owner_unlink(void)
{
	char d[64], f[128];
	snprintf(d, sizeof(d), "t_sb.ou.%ld", (long)getpid());
	snprintf(f, sizeof(f), "%s/victim", d);
	rmdir(d);

	if (mkdir(d, 01777) != 0) {
		complain("case3: mkdir +t: %s", strerror(errno));
		return;
	}

	int fd = open(f, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("case3: create: %s", strerror(errno));
		rmdir(d); return;
	}
	close(fd);

	if (unlink(f) != 0)
		complain("case3: owner cannot unlink own file in sticky "
			 "dir: %s (server erroneously enforcing S_ISVTX "
			 "against owner)", strerror(errno));

	rmdir(d);
}

static void case_owner_rename(void)
{
	char d[64], a[128], b[128];
	snprintf(d, sizeof(d), "t_sb.or.%ld", (long)getpid());
	snprintf(a, sizeof(a), "%s/a", d);
	snprintf(b, sizeof(b), "%s/b", d);
	rmdir(d);

	if (mkdir(d, 01777) != 0) {
		complain("case4: mkdir +t: %s", strerror(errno));
		return;
	}
	int fd = open(a, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("case4: create: %s", strerror(errno));
		rmdir(d); return;
	}
	close(fd);

	if (rename(a, b) != 0)
		complain("case4: owner cannot rename own file in sticky "
			 "dir: %s", strerror(errno));

	unlink(b);
	rmdir(d);
}

static void case_cross_user_note(void)
{
	if (!Sflag)
		printf("NOTE: %s: case5 cross-uid sticky-bit enforcement "
		       "(EACCES when non-owner tries to unlink) is not "
		       "tested here -- requires privilege dropping or a "
		       "second user.  Use pjdfstest for that coverage.\n",
		       myname);
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

	prelude(myname, "sticky-bit (S_ISVTX) propagation and owner path");
	cd_or_skip(myname, dir, Nflag);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_isvtx_round_trip", case_isvtx_round_trip());
	RUN_CASE("case_isvtx_persists", case_isvtx_persists());
	RUN_CASE("case_owner_unlink", case_owner_unlink());
	RUN_CASE("case_owner_rename", case_owner_rename());
	RUN_CASE("case_cross_user_note", case_cross_user_note());

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}
