/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_concurrent_writes.c -- multiple concurrent writers on the same
 * file, disjoint regions; verify no cross-contamination.
 *
 * Motivated by a FreeBSD NFS client bug (commit 39d96e08b0c4): two
 * workers submitting ~1 MiB io_uring writes on the same fd caused
 * TCP segment interleaving between the two writes' RPCs, so bytes
 * from one worker's region landed in the other's.  The fix was a
 * per-fd write gate serialising RPC emission.
 *
 * This test reproduces the scenario at the POSIX level: fork N
 * workers, each pwrite()s a 1 MiB region with a worker-unique byte
 * pattern into disjoint offsets of the same file.  After all
 * workers exit and fdatasync runs, we pread each region and verify
 * it carries its worker's pattern.  If concurrent WRITE RPCs
 * produced interleaved TCP segments on the wire, bytes from worker
 * B show up in worker A's region -- FAIL.
 *
 * The test does NOT assume any particular ordering or atomicity
 * between workers.  It only asserts that after all writes land
 * durably, each disjoint region reads back with its own pattern.
 * If the NFS client or server cannot serialise writes to the same
 * fd correctly, cross-contamination surfaces here.
 *
 * Cases:
 *
 *   1. Two workers, 1 MiB each at disjoint offsets.  Minimal
 *      reproduction of the FreeBSD scenario.
 *
 *   2. Four workers, 1 MiB each.  Higher concurrency surface.
 *
 *   3. Two workers, small (64 KiB) writes.  Same pattern below the
 *      typical wsize -- expected PASS on every implementation but
 *      catches regressions in the serialisation path itself.
 *
 *   4. Two workers, overlapping regions (explicit race).  POSIX
 *      does NOT define the outcome for concurrent overlapping
 *      writes; we report which worker "won" each byte as a NOTE
 *      and verify no byte is outside the set written by either
 *      worker.  Catches corruption even under legal races.
 *
 * Portable: POSIX.1-2008 fork / pwrite / fdatasync.
 */

#define _POSIX_C_SOURCE 200809L

#include "tests.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

int Hflag = 0;
int Sflag = 0;
int Tflag = 0;
int Fflag = 0;
int Nflag = 0;

static const char *myname = "op_concurrent_writes";

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  concurrent disjoint writes on a shared fd "
		"(FreeBSD 39d96e08 class)\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

/*
 * Worker child: pwrite a buffer full of pattern byte `tag' into
 * [off, off+len) of fd, repeatedly until the full range is covered.
 * Uses a chunk size equal to len so a single pwrite issues a single
 * WRITE RPC (or multiple if len > wsize -- the key ingredient for
 * the TCP-segment-interleave reproduction).
 */
static int worker(int fd, off_t off, size_t len, unsigned char tag)
{
	unsigned char *buf = malloc(len);
	if (!buf) return 70;
	memset(buf, tag, len);
	ssize_t w = pwrite(fd, buf, len, off);
	free(buf);
	if (w < 0) return 71;
	if ((size_t)w != len) return 72;
	return 0;
}

/*
 * Fork n workers, each writing a disjoint 1 MiB region tagged
 * with a distinct byte (0x11, 0x22, 0x33, 0x44, ...).  After all
 * workers finish, fdatasync, pread back, verify.
 */
static void run_disjoint(int n_workers, size_t len, int casenum)
{
	char a[64];
	snprintf(a, sizeof(a), "t_cw.d%d.%ld", casenum, (long)getpid());
	unlink(a);

	int fd = open(a, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("case%d: open: %s", casenum, strerror(errno));
		return;
	}
	if (ftruncate(fd, (off_t)(n_workers * len)) != 0) {
		complain("case%d: ftruncate: %s",
			 casenum, strerror(errno));
		close(fd); unlink(a); return;
	}

	pid_t *pids = calloc((size_t)n_workers, sizeof(pid_t));
	if (!pids) {
		complain("case%d: calloc", casenum);
		close(fd); unlink(a); return;
	}

	for (int i = 0; i < n_workers; i++) {
		pid_t pid = fork();
		if (pid < 0) {
			complain("case%d: fork[%d]: %s",
				 casenum, i, strerror(errno));
			pids[i] = -1;
			continue;
		}
		if (pid == 0) {
			unsigned char tag = (unsigned char)(0x11 * (i + 1));
			int rc = worker(fd, (off_t)(i * len), len, tag);
			_exit(rc);
		}
		pids[i] = pid;
	}

	int worker_fail = 0;
	for (int i = 0; i < n_workers; i++) {
		if (pids[i] < 0) { worker_fail++; continue; }
		int status = 0;
		waitpid(pids[i], &status, 0);
		if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
			complain("case%d: worker %d exited 0x%x",
				 casenum, i, status);
			worker_fail++;
		}
	}
	free(pids);

	if (worker_fail) {
		close(fd); unlink(a); return;
	}

	if (fdatasync(fd) != 0 && !Sflag)
		printf("NOTE: %s: case%d fdatasync: %s\n",
		       myname, casenum, strerror(errno));

	/* Verify each region has its tag. */
	unsigned char *chunk = malloc(len);
	if (!chunk) {
		complain("case%d: verify malloc", casenum);
		close(fd); unlink(a); return;
	}
	int bad = 0;
	for (int i = 0; i < n_workers; i++) {
		unsigned char tag = (unsigned char)(0x11 * (i + 1));
		ssize_t r = pread(fd, chunk, len, (off_t)(i * len));
		if (r != (ssize_t)len) {
			complain("case%d: pread region %d %zd / %zu: %s",
				 casenum, i, r, len, strerror(errno));
			bad++;
			continue;
		}
		for (size_t j = 0; j < len; j++) {
			if (chunk[j] != tag) {
				complain("case%d: region %d byte %zu = "
					 "0x%02x (expected 0x%02x) -- "
					 "cross-region contamination "
					 "(wire-level write interleaving?)",
					 casenum, i, j,
					 (unsigned)chunk[j], (unsigned)tag);
				bad++;
				break;
			}
		}
		if (bad >= 3) break;      /* stop once pattern is clear */
	}
	free(chunk);

	close(fd);
	unlink(a);
}

static void case_two_workers_1mib(void)
{
	run_disjoint(2, 1024 * 1024, 1);
}

static void case_four_workers_1mib(void)
{
	run_disjoint(4, 1024 * 1024, 2);
}

static void case_two_workers_small(void)
{
	run_disjoint(2, 64 * 1024, 3);
}

/*
 * Overlapping region: two workers race on the same 1 MiB range.
 * POSIX does not specify the outcome.  We only verify every byte
 * came from one of the two workers (i.e., no third value sneaked
 * in -- which would indicate bit-level corruption).
 */
static void case_overlapping_race(void)
{
	char a[64];
	snprintf(a, sizeof(a), "t_cw.ov.%ld", (long)getpid());
	unlink(a);
	int fd = open(a, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("case4: open: %s", strerror(errno));
		return;
	}
	const size_t len = 1024 * 1024;
	if (ftruncate(fd, (off_t)len) != 0) {
		complain("case4: ftruncate: %s", strerror(errno));
		close(fd); unlink(a); return;
	}

	pid_t p1 = fork();
	if (p1 < 0) {
		complain("case4: fork p1: %s", strerror(errno));
		close(fd); unlink(a); return;
	}
	if (p1 == 0) _exit(worker(fd, 0, len, 0xAA));

	pid_t p2 = fork();
	if (p2 < 0) {
		complain("case4: fork p2: %s", strerror(errno));
		close(fd); unlink(a); return;
	}
	if (p2 == 0) _exit(worker(fd, 0, len, 0xBB));

	int s1 = 0, s2 = 0;
	waitpid(p1, &s1, 0);
	waitpid(p2, &s2, 0);
	if (!WIFEXITED(s1) || WEXITSTATUS(s1) != 0 ||
	    !WIFEXITED(s2) || WEXITSTATUS(s2) != 0) {
		complain("case4: worker exit 0x%x / 0x%x", s1, s2);
		close(fd); unlink(a); return;
	}

	if (fdatasync(fd) != 0 && !Sflag)
		printf("NOTE: %s: case4 fdatasync: %s\n",
		       myname, strerror(errno));

	unsigned char *buf = malloc(len);
	if (!buf) { complain("case4: malloc"); close(fd); unlink(a); return; }
	if (pread(fd, buf, len, 0) != (ssize_t)len) {
		complain("case4: pread: %s", strerror(errno));
		free(buf); close(fd); unlink(a); return;
	}

	size_t n_aa = 0, n_bb = 0, n_other = 0;
	for (size_t i = 0; i < len; i++) {
		if (buf[i] == 0xAA) n_aa++;
		else if (buf[i] == 0xBB) n_bb++;
		else n_other++;
	}
	free(buf);

	if (n_other > 0)
		complain("case4: %zu bytes are neither 0xAA nor 0xBB -- "
			 "bit-level corruption during concurrent overlapping "
			 "writes", n_other);
	if (!Sflag)
		printf("NOTE: %s: case4 race outcome: "
		       "%zu bytes 0xAA, %zu bytes 0xBB, %zu other "
		       "(any split or all-one-worker is POSIX-legal)\n",
		       myname, n_aa, n_bb, n_other);

	close(fd);
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
		"concurrent disjoint writes on a shared fd "
		"(FreeBSD 39d96e08 class)");
	cd_or_skip(myname, dir, Nflag);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_two_workers_1mib", case_two_workers_1mib());
	RUN_CASE("case_four_workers_1mib", case_four_workers_1mib());
	RUN_CASE("case_two_workers_small", case_two_workers_small());
	RUN_CASE("case_overlapping_race", case_overlapping_race());

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}
