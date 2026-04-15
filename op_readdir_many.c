/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_readdir_many.c -- stress NFSv4 READDIR (RFC 7530 S18.23)
 * cookie / continuation handling over a large directory.
 *
 * op_readdir exercises the basic READDIR shape with a handful of
 * entries that fit in one reply.  This test creates N entries (1024
 * by default) so the client must issue several READDIR calls, each
 * passing the previous reply's cookie, and the server must return
 * the next batch without losing or duplicating entries.  Bugs
 * around cookie stability, buffer sizing, and EOF handling only
 * show up at this scale.
 *
 * Cases:
 *
 *   1. Create N = 1024 files named t_rm.NNNN.PID, readdir the
 *      scratch directory, verify each name appears exactly once.
 *      Confirms no entries lost across continuations.
 *
 *   2. Re-readdir the same directory with a fresh opendir() handle,
 *      verify the count still matches (cookies are not sticky across
 *      opendir boundaries on well-behaved servers).
 *
 *   3. Readdir while mutating: readdir from the top, halfway through
 *      create one extra file.  The newly-created file may or may not
 *      appear in this pass -- both are POSIX-valid -- but existing
 *      entries must still be returned exactly once.  Verifies the
 *      server does not lose cookies when the directory changes
 *      mid-walk.
 *
 * All created files are removed on PASS.  On FAIL, up to N stragglers
 * may remain; subsequent runs will re-try.
 *
 * Portable: POSIX opendir/readdir/closedir.  No Linux-specific API.
 */

#define _POSIX_C_SOURCE 200809L

#include "tests.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

int Hflag = 0;
int Sflag = 0;
int Tflag = 0;
int Fflag = 0;
int Nflag = 0;

static const char *myname = "op_readdir_many";

#define N_ENTRIES_DEFAULT 1024

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  stress readdir -> NFSv4 READDIR continuation (RFC 7530 S18.23)\n"
		"  -h help  -s silent  -t timing  -f function-only (N=128)\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

/* Create N files; return 0 on success.  Caller owns removal. */
static int create_many(const char *prefix, int n, long pid)
{
	char name[64];
	for (int i = 0; i < n; i++) {
		snprintf(name, sizeof(name), "%s.%04d.%ld", prefix, i, pid);
		int fd = open(name, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		if (fd < 0) {
			complain("create %s: %s", name, strerror(errno));
			return -1;
		}
		close(fd);
	}
	return 0;
}

static void remove_many(const char *prefix, int n, long pid)
{
	char name[64];
	for (int i = 0; i < n; i++) {
		snprintf(name, sizeof(name), "%s.%04d.%ld", prefix, i, pid);
		unlink(name);
	}
}

/*
 * scan_and_count -- readdir the cwd, count entries whose names start
 * with `prefix.` and end with `.PID`.  Marks each seen entry in seen[]
 * (array of length n) by setting seen[index]=1 so duplicates are
 * detectable.  Returns the number of matching entries seen on success,
 * -1 on readdir failure, -2 on duplicate, -3 on out-of-range index.
 */
static int scan_and_count(const char *prefix, int n, long pid,
			  unsigned char *seen)
{
	memset(seen, 0, (size_t)n);
	DIR *dp = opendir(".");
	if (!dp) {
		complain("opendir: %s", strerror(errno));
		return -1;
	}
	int matched = 0;
	char suffix[32];
	snprintf(suffix, sizeof(suffix), ".%ld", pid);
	size_t prefix_len = strlen(prefix);
	size_t suffix_len = strlen(suffix);

	struct dirent *de;
	while ((de = readdir(dp)) != NULL) {
		size_t nl = strlen(de->d_name);
		/* "prefix.NNNN" + suffix ".PID" = prefix_len + 5 + suffix_len */
		if (nl < prefix_len + 5 + suffix_len)
			continue;
		if (strncmp(de->d_name, prefix, prefix_len) != 0)
			continue;
		if (de->d_name[prefix_len] != '.')
			continue;
		if (strcmp(de->d_name + nl - suffix_len, suffix) != 0)
			continue;
		/* Parse four-digit index from positions prefix_len+1..+4 */
		char idxbuf[5];
		memcpy(idxbuf, de->d_name + prefix_len + 1, 4);
		idxbuf[4] = '\0';
		char *endp;
		long idx = strtol(idxbuf, &endp, 10);
		if (*endp != '\0' || idx < 0 || idx >= n) {
			closedir(dp);
			return -3;
		}
		if (seen[idx]) {
			closedir(dp);
			return -2;
		}
		seen[idx] = 1;
		matched++;
	}
	closedir(dp);
	return matched;
}

/* case 1 ---------------------------------------------------------------- */

static void case_walk_all(int n, long pid)
{
	const char *prefix = "t_rm.all";
	if (create_many(prefix, n, pid) != 0) {
		remove_many(prefix, n, pid);
		return;
	}

	unsigned char *seen = calloc((size_t)n, 1);
	if (!seen) {
		complain("case1: calloc(%d)", n);
		remove_many(prefix, n, pid);
		return;
	}

	int matched = scan_and_count(prefix, n, pid, seen);
	if (matched == -1) {
		/* complain already issued */
	} else if (matched == -2) {
		complain("case1: duplicate entry from readdir");
	} else if (matched == -3) {
		complain("case1: out-of-range index parsed from readdir name");
	} else if (matched != n) {
		complain("case1: readdir saw %d entries, expected %d "
			 "(continuation dropped %d entries)",
			 matched, n, n - matched);
		for (int i = 0; i < n && i < 8; i++)
			if (!seen[i])
				fprintf(stderr, "  missing idx %d\n", i);
	}

	free(seen);
	remove_many(prefix, n, pid);
}

/* case 2 ---------------------------------------------------------------- */

static void case_walk_twice(int n, long pid)
{
	const char *prefix = "t_rm.twice";
	if (create_many(prefix, n, pid) != 0) {
		remove_many(prefix, n, pid);
		return;
	}

	unsigned char *seen = calloc((size_t)n, 1);
	if (!seen) {
		complain("case2: calloc(%d)", n);
		remove_many(prefix, n, pid);
		return;
	}

	int m1 = scan_and_count(prefix, n, pid, seen);
	int m2 = scan_and_count(prefix, n, pid, seen);
	if (m1 != n || m2 != n)
		complain("case2: readdir counts differ across passes "
			 "(first=%d second=%d expected=%d)",
			 m1, m2, n);

	free(seen);
	remove_many(prefix, n, pid);
}

/* case 3 ---------------------------------------------------------------- */

static void case_walk_with_mutation(int n, long pid)
{
	const char *prefix = "t_rm.mut";
	if (create_many(prefix, n, pid) != 0) {
		remove_many(prefix, n, pid);
		return;
	}

	unsigned char *seen = calloc((size_t)n, 1);
	if (!seen) {
		complain("case3: calloc(%d)", n);
		remove_many(prefix, n, pid);
		return;
	}

	DIR *dp = opendir(".");
	if (!dp) {
		complain("case3: opendir: %s", strerror(errno));
		free(seen);
		remove_many(prefix, n, pid);
		return;
	}

	char suffix[32];
	snprintf(suffix, sizeof(suffix), ".%ld", pid);
	size_t prefix_len = strlen(prefix);
	size_t suffix_len = strlen(suffix);

	int matched = 0;
	int half = n / 2;
	int dup = 0;
	char extra_name[64];
	snprintf(extra_name, sizeof(extra_name), "%s.X.%ld", prefix, pid);
	int extra_created = 0;

	struct dirent *de;
	while ((de = readdir(dp)) != NULL) {
		size_t nl = strlen(de->d_name);
		/* "prefix.NNNN" + suffix ".PID" = prefix_len + 5 + suffix_len */
		if (nl < prefix_len + 5 + suffix_len)
			continue;
		if (strncmp(de->d_name, prefix, prefix_len) != 0)
			continue;
		if (de->d_name[prefix_len] != '.')
			continue;
		if (strcmp(de->d_name + nl - suffix_len, suffix) != 0)
			continue;
		char idxbuf[5];
		memcpy(idxbuf, de->d_name + prefix_len + 1, 4);
		if (idxbuf[0] == 'X') /* the mid-walk entry */
			continue;
		idxbuf[4] = '\0';
		char *endp;
		long idx = strtol(idxbuf, &endp, 10);
		if (*endp != '\0' || idx < 0 || idx >= n)
			continue;
		if (seen[idx]) {
			dup = 1;
			break;
		}
		seen[idx] = 1;
		matched++;

		if (matched == half && !extra_created) {
			int fd = open(extra_name,
				      O_WRONLY | O_CREAT | O_TRUNC, 0644);
			if (fd >= 0) {
				close(fd);
				extra_created = 1;
			}
		}
	}
	closedir(dp);

	if (dup)
		complain("case3: duplicate entry during mutating readdir");
	else if (matched != n)
		complain("case3: saw %d of %d originals during mutating walk "
			 "(cookie stability broken)",
			 matched, n);

	if (extra_created)
		unlink(extra_name);
	free(seen);
	remove_many(prefix, n, pid);
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
		"readdir continuation -> NFSv4 READDIR (RFC 7530 S18.23)");
	cd_or_skip(myname, dir, Nflag);

	int n = Fflag ? 128 : N_ENTRIES_DEFAULT;
	long pid = (long)getpid();

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	case_walk_all(n, pid);
	case_walk_twice(n, pid);
	case_walk_with_mutation(n, pid);

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}
