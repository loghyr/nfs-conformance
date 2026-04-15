/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_readdir.c -- exercise NFSv4 READDIR op (RFC 7530 S18.23) via
 * opendir(3) / readdir(3) / rewinddir(3) / closedir(3).
 *
 * Cases:
 *
 *   1. Basic enumeration.  Create three files in a scratch subdirectory,
 *      opendir, collect all entry names, verify each appears exactly once.
 *
 *   2. Mixed object types.  Create a regular file, a subdirectory, and
 *      a symlink in a scratch dir; enumerate and verify each entry appears.
 *      Types are checked with lstat() not d_type -- NFSv4 servers may
 *      return DT_UNKNOWN for all entries.
 *
 *   3. Large directory (chunked reply).  Create N_LARGE entries in a
 *      scratch directory; verify every one is returned.  At typical NFSv4
 *      READDIR reply sizes (8 KB) this forces multiple READDIR round-trips,
 *      exercising the cookie / cookie-verifier continuation path.  TLS
 *      record-boundary bugs are most likely to surface here.
 *
 *   4. Empty directory.  mkdir a fresh subdir, opendir, verify no real
 *      entries (excluding "." and "..").
 *
 *   5. ENOENT path.  opendir() on a nonexistent path returns NULL /
 *      errno == ENOENT.
 *
 *   6. rewinddir.  Read a directory with three files to end, rewinddir,
 *      read again; verify both passes return the same non-dot entry count.
 *
 * Portable: POSIX across Linux / FreeBSD / macOS / Solaris.
 */

#define _POSIX_C_SOURCE 200809L

#include "tests.h"

#include <dirent.h>
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

static const char *myname = "op_readdir";

/*
 * Number of entries to create for the large-directory / chunked-reply
 * case.  256 files at ~20 bytes per name fill several 8 KB READDIR
 * replies and reliably trigger multi-round-trip cookie continuation.
 */
#define N_LARGE 256

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  exercise opendir/readdir -> NFSv4 READDIR (RFC 7530 S18.23)\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

/*
 * count_entries -- return the number of non-"." non-".." entries in
 * dirpath, or -1 on opendir failure (errno preserved).
 */
static int count_entries(const char *dirpath)
{
	DIR *dp = opendir(dirpath);
	if (!dp)
		return -1;
	int n = 0;
	struct dirent *de;
	while ((de = readdir(dp)) != NULL) {
		if (strcmp(de->d_name, ".") == 0 ||
		    strcmp(de->d_name, "..") == 0)
			continue;
		n++;
	}
	closedir(dp);
	return n;
}

/*
 * rmdir_r1 -- remove a directory that contains regular files, symlinks,
 * and empty subdirectories (one level deep only).  Used for cleanup.
 */
static void rmdir_r1(const char *dirpath)
{
	DIR *dp = opendir(dirpath);
	if (!dp) return;
	struct dirent *de;
	char path[512];
	while ((de = readdir(dp)) != NULL) {
		if (strcmp(de->d_name, ".") == 0 ||
		    strcmp(de->d_name, "..") == 0)
			continue;
		snprintf(path, sizeof(path), "%s/%s", dirpath, de->d_name);
		if (unlink(path) != 0)
			rmdir(path);
	}
	closedir(dp);
	rmdir(dirpath);
}

static void case_basic(void)
{
	char d[64];
	snprintf(d, sizeof(d), "t_rdir.b.%ld", (long)getpid());
	rmdir_r1(d);

	if (mkdir(d, 0755) != 0) {
		complain("case1: mkdir(%s): %s", d, strerror(errno));
		return;
	}

	const char *names[] = { "alpha", "beta", "gamma" };
	int nnames = 3;
	char path[128];
	for (int i = 0; i < nnames; i++) {
		snprintf(path, sizeof(path), "%s/%s", d, names[i]);
		int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
		if (fd < 0) {
			complain("case1: create %s: %s", path, strerror(errno));
			rmdir_r1(d);
			return;
		}
		close(fd);
	}

	DIR *dp = opendir(d);
	if (!dp) {
		complain("case1: opendir(%s): %s", d, strerror(errno));
		rmdir_r1(d);
		return;
	}

	int found[3] = { 0, 0, 0 };
	struct dirent *de;
	while ((de = readdir(dp)) != NULL) {
		for (int i = 0; i < nnames; i++) {
			if (strcmp(de->d_name, names[i]) == 0) {
				if (found[i])
					complain("case1: entry '%s' seen twice",
						 names[i]);
				found[i]++;
			}
		}
	}
	closedir(dp);

	for (int i = 0; i < nnames; i++) {
		if (!found[i])
			complain("case1: entry '%s' missing from readdir",
				 names[i]);
	}
	rmdir_r1(d);
}

static void case_mixed_types(void)
{
	char d[64];
	snprintf(d, sizeof(d), "t_rdir.mt.%ld", (long)getpid());
	rmdir_r1(d);

	if (mkdir(d, 0755) != 0) {
		complain("case2: mkdir(%s): %s", d, strerror(errno));
		return;
	}

	char fpath[128], sdpath[128], slpath[128];
	snprintf(fpath,  sizeof(fpath),  "%s/reg", d);
	snprintf(sdpath, sizeof(sdpath), "%s/sub", d);
	snprintf(slpath, sizeof(slpath), "%s/lnk", d);

	int fd = open(fpath, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("case2: create regular: %s", strerror(errno));
		rmdir_r1(d); return;
	}
	close(fd);

	if (mkdir(sdpath, 0755) != 0) {
		complain("case2: mkdir subdir: %s", strerror(errno));
		rmdir_r1(d); return;
	}

	if (symlink("reg", slpath) != 0) {
		complain("case2: symlink: %s", strerror(errno));
		rmdir_r1(d); return;
	}

	DIR *dp = opendir(d);
	if (!dp) {
		complain("case2: opendir: %s", strerror(errno));
		rmdir_r1(d); return;
	}

	int saw_reg = 0, saw_sub = 0, saw_lnk = 0;
	struct dirent *de;
	char epath[4096];
	struct stat st;

	while ((de = readdir(dp)) != NULL) {
		if (strcmp(de->d_name, ".") == 0 ||
		    strcmp(de->d_name, "..") == 0)
			continue;
		int n = snprintf(epath, sizeof(epath), "%s/%s", d, de->d_name);
		if (n < 0 || (size_t)n >= sizeof(epath)) {
			complain("case2: path too long: %s/%s", d, de->d_name);
			continue;
		}
		if (lstat(epath, &st) != 0) {
			complain("case2: lstat(%s): %s", epath, strerror(errno));
			continue;
		}
		if (strcmp(de->d_name, "reg") == 0) {
			saw_reg++;
			if (!S_ISREG(st.st_mode))
				complain("case2: 'reg' has mode 0%o "
					 "(expected S_IFREG)",
					 st.st_mode & S_IFMT);
		} else if (strcmp(de->d_name, "sub") == 0) {
			saw_sub++;
			if (!S_ISDIR(st.st_mode))
				complain("case2: 'sub' has mode 0%o "
					 "(expected S_IFDIR)",
					 st.st_mode & S_IFMT);
		} else if (strcmp(de->d_name, "lnk") == 0) {
			saw_lnk++;
			if (!S_ISLNK(st.st_mode))
				complain("case2: 'lnk' has mode 0%o "
					 "(expected S_IFLNK)",
					 st.st_mode & S_IFMT);
		}
	}
	closedir(dp);

	if (!saw_reg) complain("case2: 'reg' not found in readdir");
	if (!saw_sub) complain("case2: 'sub' not found in readdir");
	if (!saw_lnk) complain("case2: 'lnk' not found in readdir");
	rmdir_r1(d);
}

static void case_large(void)
{
	char d[64];
	snprintf(d, sizeof(d), "t_rdir.lg.%ld", (long)getpid());
	rmdir_r1(d);

	if (mkdir(d, 0755) != 0) {
		complain("case3: mkdir(%s): %s", d, strerror(errno));
		return;
	}

	char path[128];
	for (int i = 0; i < N_LARGE; i++) {
		snprintf(path, sizeof(path), "%s/f%04d", d, i);
		int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
		if (fd < 0) {
			complain("case3: create f%04d: %s", i,
				 strerror(errno));
			rmdir_r1(d);
			return;
		}
		close(fd);
	}

	int got = count_entries(d);
	if (got < 0) {
		complain("case3: opendir(%s): %s", d, strerror(errno));
	} else if (got != N_LARGE) {
		complain("case3: expected %d entries, got %d "
			 "(chunked READDIR may have lost entries)",
			 N_LARGE, got);
	}
	rmdir_r1(d);
}

static void case_empty(void)
{
	char d[64];
	snprintf(d, sizeof(d), "t_rdir.em.%ld", (long)getpid());
	rmdir(d);

	if (mkdir(d, 0755) != 0) {
		complain("case4: mkdir(%s): %s", d, strerror(errno));
		return;
	}

	int got = count_entries(d);
	if (got < 0) {
		complain("case4: opendir(%s): %s", d, strerror(errno));
	} else if (got != 0) {
		complain("case4: empty dir has %d non-dot entries (expected 0)",
			 got);
	}
	rmdir(d);
}

static void case_enoent(void)
{
	char d[64];
	snprintf(d, sizeof(d), "t_rdir.ne.%ld", (long)getpid());
	rmdir(d);

	errno = 0;
	DIR *dp = opendir(d);
	if (dp != NULL) {
		complain("case5: opendir on missing path unexpectedly "
			 "succeeded");
		closedir(dp);
	} else if (errno != ENOENT) {
		complain("case5: expected ENOENT, got %s", strerror(errno));
	}
}

static void case_rewinddir(void)
{
	char d[64];
	snprintf(d, sizeof(d), "t_rdir.rw.%ld", (long)getpid());
	rmdir_r1(d);

	if (mkdir(d, 0755) != 0) {
		complain("case6: mkdir(%s): %s", d, strerror(errno));
		return;
	}

	const char *names[] = { "x1", "x2", "x3" };
	char path[128];
	for (int i = 0; i < 3; i++) {
		snprintf(path, sizeof(path), "%s/%s", d, names[i]);
		int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
		if (fd < 0) {
			complain("case6: create %s: %s", path, strerror(errno));
			rmdir_r1(d);
			return;
		}
		close(fd);
	}

	DIR *dp = opendir(d);
	if (!dp) {
		complain("case6: opendir: %s", strerror(errno));
		rmdir_r1(d);
		return;
	}

	int pass1 = 0;
	struct dirent *de;
	while ((de = readdir(dp)) != NULL) {
		if (strcmp(de->d_name, ".") != 0 &&
		    strcmp(de->d_name, "..") != 0)
			pass1++;
	}

	rewinddir(dp);

	int pass2 = 0;
	while ((de = readdir(dp)) != NULL) {
		if (strcmp(de->d_name, ".") != 0 &&
		    strcmp(de->d_name, "..") != 0)
			pass2++;
	}
	closedir(dp);

	if (pass1 != 3)
		complain("case6: pass1 saw %d real entries (expected 3)",
			 pass1);
	if (pass2 != 3)
		complain("case6: pass2 (after rewinddir) saw %d real entries "
			 "(expected 3)",
			 pass2);
	rmdir_r1(d);
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
		"opendir/readdir -> NFSv4 READDIR (RFC 7530 S18.23)");
	cd_or_skip(myname, dir, Nflag);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	case_basic();
	case_mixed_types();
	case_large();
	case_empty();
	case_enoent();
	case_rewinddir();

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}
