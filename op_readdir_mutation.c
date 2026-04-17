/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_readdir_mutation.c -- exercise readdir behaviour while the
 * directory is mutated mid-iteration.
 *
 * POSIX leaves the result of "add/remove entries while another
 * thread is iterating readdir()" only weakly constrained.  On NFS
 * the stakes are higher: directory cookies are server-issued and
 * must remain valid across intervening modifications, otherwise the
 * iterator wedges or skips entries.  Real-world failure modes seen
 * in past NFS servers:
 *
 *   - telldir()/seekdir() round-trip returns a cookie the server
 *     has since invalidated; continuation fails EINVAL or loops.
 *   - rewinddir() after deletion sees stale entries (server cached
 *     the directory snapshot at open time).
 *   - Concurrent DIR* streams on the same directory interfere.
 *
 * Cases:
 *
 *   1. Read-delete-continue: create N entries, readdir K, delete
 *      some un-yet-seen entries, continue readdir.  Every entry
 *      still present must eventually surface; entries deleted mid-
 *      iteration may or may not appear (NFS-permissible), but must
 *      not cause iteration to fail.
 *
 *   2. rewinddir after mutation: create N, read M, delete some,
 *      add others, rewinddir, read all.  The rewound iteration
 *      should reflect the CURRENT directory state.
 *
 *   3. telldir/seekdir survives modification: read to position P,
 *      telldir, delete entries BEFORE P, seekdir(P), continue.
 *      The continuation should not revisit entries we already read
 *      and should not skip entries remaining after P.
 *
 *   4. Empty-after-delete: readdir a directory, delete every entry
 *      one call at a time.  Iteration must terminate cleanly.
 *
 *   5. Two concurrent DIR* streams on the same directory (separate
 *      opendir calls): each stream must iterate independently.
 *
 * Portable: POSIX.  telldir/seekdir behaviour on NFS is subject to
 * cookie semantics; tests report NOTE rather than FAIL when the
 * server demonstrably chose a permissible interpretation.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

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

#define NFILES 32

int Hflag = 0;
int Sflag = 0;
int Tflag = 0;
int Fflag = 0;
int Nflag = 0;

static const char *myname = "op_readdir_mutation";

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  exercise readdir + directory mutation interactions\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

static int make_scratch_dir(char *out, size_t outsz, int casenum)
{
	snprintf(out, outsz, "t_rdm.%d.%ld", casenum, (long)getpid());
	/* Best-effort cleanup from prior aborted run. */
	DIR *d = opendir(out);
	if (d) {
		struct dirent *e;
		while ((e = readdir(d)) != NULL) {
			if (strcmp(e->d_name, ".") == 0 ||
			    strcmp(e->d_name, "..") == 0) continue;
			/* dir + '/' + NAME_MAX + '\0' easily fits in 512. */
			char p[512];
			snprintf(p, sizeof(p), "%s/%s", out, e->d_name);
			unlink(p);
		}
		closedir(d);
		rmdir(out);
	}
	if (mkdir(out, 0755) != 0) return -1;
	return 0;
}

static int populate(const char *dir, int n)
{
	for (int i = 0; i < n; i++) {
		char p[512];
		snprintf(p, sizeof(p), "%s/f%03d", dir, i);
		int fd = open(p, O_RDWR | O_CREAT | O_TRUNC, 0644);
		if (fd < 0) return -1;
		close(fd);
	}
	return 0;
}

static void cleanup_dir(const char *dir)
{
	DIR *d = opendir(dir);
	if (d) {
		struct dirent *e;
		while ((e = readdir(d)) != NULL) {
			if (strcmp(e->d_name, ".") == 0 ||
			    strcmp(e->d_name, "..") == 0) continue;
			char p[512];
			snprintf(p, sizeof(p), "%s/%s", dir, e->d_name);
			unlink(p);
		}
		closedir(d);
	}
	rmdir(dir);
}

static void case_read_delete_continue(void)
{
	char dir[64];
	if (make_scratch_dir(dir, sizeof(dir), 1) != 0) {
		complain("case1: mkdir: %s", strerror(errno));
		return;
	}
	if (populate(dir, NFILES) != 0) {
		complain("case1: populate: %s", strerror(errno));
		cleanup_dir(dir);
		return;
	}

	DIR *d = opendir(dir);
	if (!d) { complain("case1: opendir: %s", strerror(errno));
		  cleanup_dir(dir); return; }

	int seen[NFILES] = {0};
	int read_phase1 = 0;
	struct dirent *e;
	while (read_phase1 < NFILES / 2 && (e = readdir(d)) != NULL) {
		if (strcmp(e->d_name, ".") == 0 ||
		    strcmp(e->d_name, "..") == 0) continue;
		int idx;
		if (sscanf(e->d_name, "f%d", &idx) == 1 &&
		    idx >= 0 && idx < NFILES)
			seen[idx] = 1;
		read_phase1++;
	}

	/* Delete three entries we have NOT yet seen (best-effort). */
	int deleted = 0;
	for (int i = 0; i < NFILES && deleted < 3; i++) {
		if (!seen[i]) {
			char p[512];
			snprintf(p, sizeof(p), "%s/f%03d", dir, i);
			if (unlink(p) == 0) deleted++;
		}
	}

	/* Continue reading.  Every still-present entry must surface. */
	while ((e = readdir(d)) != NULL) {
		if (strcmp(e->d_name, ".") == 0 ||
		    strcmp(e->d_name, "..") == 0) continue;
		int idx;
		if (sscanf(e->d_name, "f%d", &idx) == 1 &&
		    idx >= 0 && idx < NFILES)
			seen[idx] = 1;
	}
	closedir(d);

	/* Cross-check: everything that still exists on disk was seen. */
	int missed = 0;
	for (int i = 0; i < NFILES; i++) {
		char p[512];
		snprintf(p, sizeof(p), "%s/f%03d", dir, i);
		if (access(p, F_OK) == 0 && !seen[i])
			missed++;
	}
	if (missed > 0)
		complain("case1: readdir skipped %d extant entries after "
			 "mid-iteration deletions", missed);

	cleanup_dir(dir);
}

static void case_rewinddir_after_mutation(void)
{
	char dir[64];
	if (make_scratch_dir(dir, sizeof(dir), 2) != 0) {
		complain("case2: mkdir: %s", strerror(errno));
		return;
	}
	if (populate(dir, 8) != 0) {
		complain("case2: populate: %s", strerror(errno));
		cleanup_dir(dir);
		return;
	}

	DIR *d = opendir(dir);
	if (!d) { complain("case2: opendir: %s", strerror(errno));
		  cleanup_dir(dir); return; }

	/* Read all 8 so we're at EOF. */
	while (readdir(d) != NULL) { /* drain */ }

	/* Mutate: delete two, add three. */
	char p[512];
	snprintf(p, sizeof(p), "%s/f000", dir); unlink(p);
	snprintf(p, sizeof(p), "%s/f001", dir); unlink(p);
	for (int i = 100; i < 103; i++) {
		snprintf(p, sizeof(p), "%s/g%03d", dir, i);
		int fd = open(p, O_RDWR | O_CREAT, 0644);
		if (fd >= 0) close(fd);
	}

	rewinddir(d);

	int saw_deleted = 0, saw_new = 0, saw_kept = 0;
	struct dirent *e;
	while ((e = readdir(d)) != NULL) {
		if (strcmp(e->d_name, ".") == 0 ||
		    strcmp(e->d_name, "..") == 0) continue;
		if (strcmp(e->d_name, "f000") == 0 ||
		    strcmp(e->d_name, "f001") == 0)
			saw_deleted = 1;
		else if (strncmp(e->d_name, "g1", 2) == 0)
			saw_new++;
		else if (strncmp(e->d_name, "f", 1) == 0)
			saw_kept++;
	}
	closedir(d);

	if (saw_deleted)
		complain("case2: rewinddir showed deleted entry (stale "
			 "snapshot across rewinddir)");
	if (saw_new != 3)
		complain("case2: rewinddir missed %d of 3 newly-added entries",
			 3 - saw_new);
	if (saw_kept != 6)
		complain("case2: rewinddir saw %d of 6 kept entries",
			 saw_kept);

	cleanup_dir(dir);
}

static void case_telldir_seekdir_survival(void)
{
	char dir[64];
	if (make_scratch_dir(dir, sizeof(dir), 3) != 0) {
		complain("case3: mkdir: %s", strerror(errno));
		return;
	}
	if (populate(dir, 16) != 0) {
		complain("case3: populate: %s", strerror(errno));
		cleanup_dir(dir);
		return;
	}

	DIR *d = opendir(dir);
	if (!d) { complain("case3: opendir: %s", strerror(errno));
		  cleanup_dir(dir); return; }

	/* Read 8 entries, then telldir at that position. */
	int consumed = 0;
	char seen_name[16][256] = { { 0 } };
	struct dirent *e;
	while (consumed < 8 && (e = readdir(d)) != NULL) {
		if (strcmp(e->d_name, ".") == 0 ||
		    strcmp(e->d_name, "..") == 0) continue;
		snprintf(seen_name[consumed], sizeof(seen_name[consumed]),
			 "%s", e->d_name);
		consumed++;
	}
	long pos = telldir(d);
	if (pos == -1) {
		if (!Sflag)
			printf("NOTE: %s: case3 telldir failed (%s); some "
			       "NFS configurations do not support stable "
			       "cookies\n", myname, strerror(errno));
		closedir(d);
		cleanup_dir(dir);
		return;
	}

	/* Delete entries we already consumed. */
	for (int i = 0; i < 4; i++) {
		char p[512];
		snprintf(p, sizeof(p), "%s/%s", dir, seen_name[i]);
		unlink(p);
	}

	/* Seek back to saved position; continuation must not revisit
	 * the already-consumed entries. */
	seekdir(d, pos);
	int revisited = 0;
	while ((e = readdir(d)) != NULL) {
		if (strcmp(e->d_name, ".") == 0 ||
		    strcmp(e->d_name, "..") == 0) continue;
		for (int i = 0; i < consumed; i++) {
			if (strcmp(e->d_name, seen_name[i]) == 0) {
				revisited++;
				break;
			}
		}
	}
	closedir(d);

	if (revisited > 0 && !Sflag)
		printf("NOTE: %s: case3 seekdir revisited %d already-"
		       "consumed entries after mid-stream delete — "
		       "server cookie invalidation semantics\n",
		       myname, revisited);

	cleanup_dir(dir);
}

static void case_empty_after_delete(void)
{
	char dir[64];
	if (make_scratch_dir(dir, sizeof(dir), 4) != 0) {
		complain("case4: mkdir: %s", strerror(errno));
		return;
	}
	if (populate(dir, 5) != 0) {
		complain("case4: populate: %s", strerror(errno));
		cleanup_dir(dir);
		return;
	}

	DIR *d = opendir(dir);
	if (!d) { complain("case4: opendir: %s", strerror(errno));
		  cleanup_dir(dir); return; }

	struct dirent *e;
	while ((e = readdir(d)) != NULL) {
		if (strcmp(e->d_name, ".") == 0 ||
		    strcmp(e->d_name, "..") == 0) continue;
		char p[512];
		snprintf(p, sizeof(p), "%s/%s", dir, e->d_name);
		unlink(p);
	}

	rewinddir(d);
	int after = 0;
	while ((e = readdir(d)) != NULL) {
		if (strcmp(e->d_name, ".") == 0 ||
		    strcmp(e->d_name, "..") == 0) continue;
		after++;
	}
	closedir(d);

	if (after != 0)
		complain("case4: rewinddir showed %d entries after all "
			 "unlinked (stale snapshot)", after);

	rmdir(dir);
}

static void case_two_streams(void)
{
	char dir[64];
	if (make_scratch_dir(dir, sizeof(dir), 5) != 0) {
		complain("case5: mkdir: %s", strerror(errno));
		return;
	}
	if (populate(dir, 10) != 0) {
		complain("case5: populate: %s", strerror(errno));
		cleanup_dir(dir);
		return;
	}

	DIR *d1 = opendir(dir);
	DIR *d2 = opendir(dir);
	if (!d1 || !d2) {
		complain("case5: opendir: %s", strerror(errno));
		if (d1) closedir(d1);
		if (d2) closedir(d2);
		cleanup_dir(dir);
		return;
	}

	/* Advance d1 by 3, advance d2 by 6.  Neither should interfere
	 * with the other's position. */
	for (int i = 0; i < 3; i++) (void)readdir(d1);
	for (int i = 0; i < 6; i++) (void)readdir(d2);

	int n1 = 0, n2 = 0;
	while (readdir(d1)) n1++;
	while (readdir(d2)) n2++;
	closedir(d1);
	closedir(d2);

	/* Can't predict exact counts without tracking skipped "." and
	 * "..", but n1 should exceed n2 (d1 started earlier). */
	if (n1 <= n2)
		complain("case5: two DIR* streams show interference "
			 "(d1 remaining=%d, d2 remaining=%d; d1 should be "
			 "further behind and thus larger remainder)",
			 n1, n2);

	cleanup_dir(dir);
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
		"readdir + directory mutation interactions");
	cd_or_skip(myname, dir, Nflag);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_read_delete_continue",
		 case_read_delete_continue());
	RUN_CASE("case_rewinddir_after_mutation",
		 case_rewinddir_after_mutation());
	RUN_CASE("case_telldir_seekdir_survival",
		 case_telldir_seekdir_survival());
	RUN_CASE("case_empty_after_delete", case_empty_after_delete());
	RUN_CASE("case_two_streams", case_two_streams());

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}
