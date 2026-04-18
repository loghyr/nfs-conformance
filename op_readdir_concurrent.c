/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_readdir_concurrent.c -- concurrent readdir stress, no mutation.
 *
 * The invariant: every worker opens its own DIR* on the same
 * directory and reads to EOF.  Each worker must see every entry
 * exactly once.  If the server tracks READDIR continuation state
 * per-directory-object instead of per-open, one worker's cookie
 * can collide with another's -- producing duplicates, gaps, or
 * leakage of names that don't belong to this directory.
 *
 * NFSv4 READDIR (RFC 7530 S18.23) takes three client-chosen
 * parameters: cookie, cookieverf, dircount (hint on reply byte
 * budget for names), and maxcount (hard cap on reply bytes).  The
 * client chooses these heuristically and userspace cannot set them
 * directly.  We approximate payload-size stress by:
 *
 *   - small per-call user buffers in case_concurrent_tiny_buffer
 *     (Linux-only; uses getdents64(2) directly with a 128-byte
 *     buffer, which drains the NFS client's internal cache more
 *     often and triggers more READDIR RPCs);
 *
 *   - very long entry names in case_long_names, which bloat each
 *     dirent and force smaller entry-counts per server reply.
 *
 * Cases:
 *
 *   1. Concurrent basic.  Populate N entries, fork M workers,
 *      each worker uses readdir(3) to enumerate and records its
 *      observed names.  Each worker must see all N entries, with
 *      no duplicates and no foreign names.
 *
 *   2. Concurrent tiny-buffer (Linux-only).  Same shape as case 1
 *      but each worker calls getdents64(2) with a 128-byte user
 *      buffer -- smaller than any single dirent -- forcing many
 *      getdents64 calls and, via the client's cache drain, many
 *      READDIR RPCs.  Maximises the surface for server-side cookie
 *      confusion.
 *
 *   3. Concurrent long names.  Populate entries with near-NAME_MAX
 *      names (200 characters), so each server-reply dirent is
 *      large and only a handful fit per READDIR; concurrent
 *      iterators must still see all entries.  Checks the small-
 *      dircount server reply path.
 *
 * Portable: POSIX fork + readdir(3).  Case 2 gates on __linux__
 * where getdents64 is exposed directly.
 */

#define _POSIX_C_SOURCE 200809L

#if defined(__linux__)
# define _GNU_SOURCE  /* for getdents64 in <dirent.h> */
#endif

#include "tests.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#if defined(__linux__)
# include <sys/syscall.h>  /* SYS_getdents64 fallback if not in dirent.h */
#endif

int Hflag = 0;
int Sflag = 0;
int Tflag = 0;
int Fflag = 0;
int Nflag = 0;

static const char *myname = "op_readdir_concurrent";

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  concurrent readdir stress (no mutation)\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

/*
 * make_scratch_dir -- create a per-case scratch subdirectory.
 * Cleans any stale state from a prior aborted run before mkdir.
 */
static int make_scratch_dir(char *out, size_t outsz, int casenum)
{
	snprintf(out, outsz, "t_rdc.%d.%ld", casenum, (long)getpid());
	DIR *d = opendir(out);
	if (d) {
		struct dirent *e;
		while ((e = readdir(d)) != NULL) {
			if (strcmp(e->d_name, ".") == 0 ||
			    strcmp(e->d_name, "..") == 0) continue;
			char p[1024];
			snprintf(p, sizeof(p), "%s/%s", out, e->d_name);
			if (unlink(p) != 0 && errno == EISDIR)
				rmdir(p);
		}
		closedir(d);
		rmdir(out);
	}
	if (mkdir(out, 0755) != 0) return -1;
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
			char p[1024];
			snprintf(p, sizeof(p), "%s/%s", dir, e->d_name);
			if (unlink(p) != 0 && errno == EISDIR)
				rmdir(p);
		}
		closedir(d);
	}
	rmdir(dir);
}

/*
 * populate -- create `n` entries named "f%04d" in `dir`.  4-digit
 * suffix lets us scale up to 10 000 entries without colliding.
 */
static int populate(const char *dir, int n)
{
	for (int i = 0; i < n; i++) {
		char p[1024];
		snprintf(p, sizeof(p), "%s/f%04d", dir, i);
		int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		if (fd < 0) return -1;
		close(fd);
	}
	return 0;
}

/*
 * Per-worker observed-set verification shared by all cases.
 * Each worker writes one entry name per line to its temp file.
 * The parent reads each file, checks:
 *   - no duplicates within a worker's stream
 *   - every populated entry seen
 *   - no foreign names
 * Returns 0 if the worker's observation was clean, non-zero count
 * of anomalies otherwise (caller reports).
 */
struct worker_stats {
	int dups;
	int missing;
	int strangers;
	int total_seen;
};

static int verify_worker(const char *obs_path, int n,
			 const char *name_prefix,
			 int prefix_digits,
			 struct worker_stats *out)
{
	memset(out, 0, sizeof(*out));
	FILE *in = fopen(obs_path, "r");
	if (!in)
		return -1;
	char *seen = calloc((size_t)n, 1);
	if (!seen) {
		fclose(in);
		return -1;
	}
	char line[1024];
	while (fgets(line, sizeof(line), in)) {
		line[strcspn(line, "\n")] = 0;
		/* Expect prefix + prefix_digits digits. */
		size_t plen = strlen(name_prefix);
		int idx = -1;
		if (strlen(line) == plen + (size_t)prefix_digits
		    && strncmp(line, name_prefix, plen) == 0) {
			char *endp = NULL;
			long v = strtol(line + plen, &endp, 10);
			if (endp && *endp == '\0' && v >= 0 && v < n)
				idx = (int)v;
		}
		if (idx < 0) {
			out->strangers++;
			continue;
		}
		if (seen[idx])
			out->dups++;
		else
			seen[idx] = 1;
		out->total_seen++;
	}
	fclose(in);
	for (int i = 0; i < n; i++)
		if (!seen[i]) out->missing++;
	free(seen);
	return 0;
}

static void report_worker(int w, const struct worker_stats *s, int n,
			  const char *variant)
{
	if (s->dups > 0)
		complain("%s: worker %d saw %d duplicates "
			 "(concurrent cookie confusion)",
			 variant, w, s->dups);
	if (s->missing > 0)
		complain("%s: worker %d missed %d of %d entries "
			 "(cookie drift under concurrent readdir)",
			 variant, w, s->missing, n);
	if (s->strangers > 0)
		complain("%s: worker %d saw %d entries with unexpected names "
			 "(foreign cookie leakage)",
			 variant, w, s->strangers);
}

/* Case 1: portable -- readdir(3), short names ---------------------------- */

static void child_readdir_basic(const char *dir, const char *obs_path)
{
	FILE *out = fopen(obs_path, "w");
	if (!out) _exit(10);
	DIR *dp = opendir(dir);
	if (!dp) { fclose(out); _exit(11); }
	struct dirent *e;
	while ((e = readdir(dp)) != NULL) {
		if (strcmp(e->d_name, ".") == 0 ||
		    strcmp(e->d_name, "..") == 0)
			continue;
		fprintf(out, "%s\n", e->d_name);
	}
	closedir(dp);
	fclose(out);
	_exit(0);
}

static void case_concurrent_basic(void)
{
	char dir[64];
	if (make_scratch_dir(dir, sizeof(dir), 1) != 0) {
		complain("case1: mkdir: %s", strerror(errno));
		return;
	}
	const int n = Fflag ? 64 : 256;
	const int workers = Fflag ? 2 : 6;

	if (populate(dir, n) != 0) {
		complain("case1: populate: %s", strerror(errno));
		cleanup_dir(dir);
		return;
	}

	pid_t pids[16];
	char obs[16][64];
	if (workers > (int)(sizeof(pids) / sizeof(pids[0]))) {
		complain("case1: worker count exceeds local array size");
		cleanup_dir(dir);
		return;
	}

	for (int w = 0; w < workers; w++) {
		snprintf(obs[w], sizeof(obs[w]), "t_rdc.o1.%ld.%d",
			 (long)getpid(), w);
		unlink(obs[w]);
	}

	for (int w = 0; w < workers; w++) {
		pid_t pid = fork();
		if (pid < 0) {
			complain("case1: fork: %s", strerror(errno));
			/* Best-effort cleanup of already-forked children. */
			for (int k = 0; k < w; k++)
				waitpid(pids[k], NULL, 0);
			cleanup_dir(dir);
			return;
		}
		if (pid == 0)
			child_readdir_basic(dir, obs[w]);
		pids[w] = pid;
	}

	for (int w = 0; w < workers; w++) {
		int st = 0;
		waitpid(pids[w], &st, 0);
		if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
			complain("case1: worker %d exited 0x%x "
				 "(readdir path itself broke)", w, st);
		}
	}

	for (int w = 0; w < workers; w++) {
		struct worker_stats s;
		if (verify_worker(obs[w], n, "f", 4, &s) != 0) {
			complain("case1: cannot read observations for "
				 "worker %d", w);
			continue;
		}
		report_worker(w, &s, n, "case1");
		unlink(obs[w]);
	}

	cleanup_dir(dir);
}

/* Case 2: Linux-only -- tiny getdents64 buffer --------------------------- */

#if defined(__linux__)
/*
 * 128-byte user buffer is smaller than any single entry on modern
 * kernels (struct linux_dirent64 header is 19 bytes + name).  On
 * Linux the kernel reports EINVAL if the buffer is literally too
 * small for a single entry, so we use 192 which fits short names
 * but triggers many getdents64 calls.
 */
#define TINY_BUF 192

static void child_readdir_tiny(const char *dir, const char *obs_path)
{
	FILE *out = fopen(obs_path, "w");
	if (!out) _exit(10);
	int fd = open(dir, O_RDONLY | O_DIRECTORY);
	if (fd < 0) { fclose(out); _exit(11); }

	char buf[TINY_BUF];
	for (;;) {
		long n = syscall(SYS_getdents64, fd, buf, sizeof(buf));
		if (n < 0) {
			if (errno == EINTR) continue;
			fclose(out); close(fd); _exit(12);
		}
		if (n == 0) break;
		long off = 0;
		while (off < n) {
			struct linux_dirent64 {
				ino64_t        d_ino;
				off64_t        d_off;
				unsigned short d_reclen;
				unsigned char  d_type;
				char           d_name[];
			} *de = (void *)(buf + off);
			if (strcmp(de->d_name, ".") != 0 &&
			    strcmp(de->d_name, "..") != 0)
				fprintf(out, "%s\n", de->d_name);
			off += de->d_reclen;
		}
	}
	close(fd);
	fclose(out);
	_exit(0);
}

static void case_concurrent_tiny_buffer(void)
{
	char dir[64];
	if (make_scratch_dir(dir, sizeof(dir), 2) != 0) {
		complain("case2: mkdir: %s", strerror(errno));
		return;
	}
	const int n = Fflag ? 64 : 256;
	const int workers = Fflag ? 2 : 6;

	if (populate(dir, n) != 0) {
		complain("case2: populate: %s", strerror(errno));
		cleanup_dir(dir);
		return;
	}

	pid_t pids[16];
	char obs[16][64];
	for (int w = 0; w < workers; w++) {
		snprintf(obs[w], sizeof(obs[w]), "t_rdc.o2.%ld.%d",
			 (long)getpid(), w);
		unlink(obs[w]);
	}

	for (int w = 0; w < workers; w++) {
		pid_t pid = fork();
		if (pid < 0) {
			complain("case2: fork: %s", strerror(errno));
			for (int k = 0; k < w; k++)
				waitpid(pids[k], NULL, 0);
			cleanup_dir(dir);
			return;
		}
		if (pid == 0)
			child_readdir_tiny(dir, obs[w]);
		pids[w] = pid;
	}

	for (int w = 0; w < workers; w++) {
		int st = 0;
		waitpid(pids[w], &st, 0);
		if (!WIFEXITED(st) || WEXITSTATUS(st) != 0)
			complain("case2: worker %d exited 0x%x "
				 "(getdents64 tiny-buffer path broke)", w, st);
	}

	for (int w = 0; w < workers; w++) {
		struct worker_stats s;
		if (verify_worker(obs[w], n, "f", 4, &s) != 0) {
			complain("case2: cannot read observations for "
				 "worker %d", w);
			continue;
		}
		report_worker(w, &s, n, "case2");
		unlink(obs[w]);
	}

	cleanup_dir(dir);
}
#else
static void case_concurrent_tiny_buffer(void)
{
	if (!Sflag)
		printf("NOTE: %s: case2 Linux-only (getdents64 with "
		       "user-controlled buffer size) -- skipping\n",
		       myname);
}
#endif /* __linux__ */

/* Case 3: long names (portable) ----------------------------------------- */

/*
 * Populate with names whose full length is ~200 characters so each
 * server-side dirent is large and only a handful fit per READDIR
 * reply.  Encoded as a prefix + fixed-length filler + index suffix
 * so verify_worker's parser still works against the index tail.
 */
#define LONG_PREFIX "ln_"
#define LONG_FILLER_LEN 180
static int populate_long(const char *dir, int n)
{
	char filler[LONG_FILLER_LEN + 1];
	memset(filler, 'x', LONG_FILLER_LEN);
	filler[LONG_FILLER_LEN] = '\0';
	for (int i = 0; i < n; i++) {
		char p[1024];
		/* ln_<180 x's>_NNNN */
		snprintf(p, sizeof(p), "%s/%s%s_%04d",
			 dir, LONG_PREFIX, filler, i);
		int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		if (fd < 0) return -1;
		close(fd);
	}
	return 0;
}

static void child_readdir_long(const char *dir, const char *obs_path)
{
	FILE *out = fopen(obs_path, "w");
	if (!out) _exit(10);
	DIR *dp = opendir(dir);
	if (!dp) { fclose(out); _exit(11); }
	struct dirent *e;
	while ((e = readdir(dp)) != NULL) {
		if (strcmp(e->d_name, ".") == 0 ||
		    strcmp(e->d_name, "..") == 0)
			continue;
		/*
		 * Emit only the trailing _NNNN index; cheaper to verify.
		 * strrchr finds the last '_' which precedes the index.
		 */
		const char *ix = strrchr(e->d_name, '_');
		if (ix && ix[1])
			fprintf(out, "%s\n", ix + 1);
		else
			fprintf(out, "%s\n", e->d_name);
	}
	closedir(dp);
	fclose(out);
	_exit(0);
}

static void case_concurrent_long_names(void)
{
	char dir[64];
	if (make_scratch_dir(dir, sizeof(dir), 3) != 0) {
		complain("case3: mkdir: %s", strerror(errno));
		return;
	}
	const int n = Fflag ? 32 : 128;  /* fewer: each dirent is ~200 B */
	const int workers = Fflag ? 2 : 4;

	if (populate_long(dir, n) != 0) {
		if (errno == ENAMETOOLONG) {
			if (!Sflag)
				printf("NOTE: %s: case3 backing FS rejects "
				       "long names -- skipping\n", myname);
			cleanup_dir(dir);
			return;
		}
		complain("case3: populate_long: %s", strerror(errno));
		cleanup_dir(dir);
		return;
	}

	pid_t pids[16];
	char obs[16][64];
	for (int w = 0; w < workers; w++) {
		snprintf(obs[w], sizeof(obs[w]), "t_rdc.o3.%ld.%d",
			 (long)getpid(), w);
		unlink(obs[w]);
	}

	for (int w = 0; w < workers; w++) {
		pid_t pid = fork();
		if (pid < 0) {
			complain("case3: fork: %s", strerror(errno));
			for (int k = 0; k < w; k++)
				waitpid(pids[k], NULL, 0);
			cleanup_dir(dir);
			return;
		}
		if (pid == 0)
			child_readdir_long(dir, obs[w]);
		pids[w] = pid;
	}

	for (int w = 0; w < workers; w++) {
		int st = 0;
		waitpid(pids[w], &st, 0);
		if (!WIFEXITED(st) || WEXITSTATUS(st) != 0)
			complain("case3: worker %d exited 0x%x", w, st);
	}

	/*
	 * Verify expects "f####"-style names; our long-names test uses
	 * the trailing index only, so use an empty prefix and 4 digits.
	 */
	for (int w = 0; w < workers; w++) {
		struct worker_stats s;
		if (verify_worker(obs[w], n, "", 4, &s) != 0) {
			complain("case3: cannot read observations for "
				 "worker %d", w);
			continue;
		}
		report_worker(w, &s, n, "case3");
		unlink(obs[w]);
	}

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
		"concurrent readdir stress (no mutation)");
	cd_or_skip(myname, dir, Nflag);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_concurrent_basic",       case_concurrent_basic());
	RUN_CASE("case_concurrent_tiny_buffer", case_concurrent_tiny_buffer());
	RUN_CASE("case_concurrent_long_names",  case_concurrent_long_names());

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}
