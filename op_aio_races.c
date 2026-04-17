/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_aio_races.c -- concurrent write-vs-truncate races on the same
 * file.
 *
 * Derived from xfstests generic/114 (async I/O sub-block write while
 * a concurrent truncate moves EOF).  xfstests uses libaio/fsx; we use
 * a forked pwriter racing against ftruncate in the parent, because
 * POSIX aio on Linux glibc pulls in librt with platform-specific link
 * conventions and we want this test to stay in the base Makefile's
 * single-.c-file rule with no extra libraries beyond subr.o.
 *
 * The invariant under test is orthogonal to the I/O primitive: after
 * a concurrent pwrite-of-N-bytes-at-0 and ftruncate(fd,0), the file
 * state on the server must be legal.  Legal states are:
 *
 *   (A) pwrite lost the race: file is 0 bytes.
 *   (B) pwrite won the race: file is N bytes and byte-for-byte the
 *       pattern pwrite wrote.
 *
 * Any other outcome is a bug:
 *
 *   (X) file has non-zero size but content differs from the pattern
 *       (torn write, interleaved truncate zero-fill, mis-ordered RPC
 *       emission), or
 *   (Y) file size is larger than N (write extended beyond its own
 *       request), or
 *   (Z) pwrite or ftruncate returned an error we weren't expecting.
 *
 * Cases:
 *
 *   1. Small sub-block write (512 B) vs truncate-to-zero.  Runs a
 *      modest number of rounds so a rare race isn't swallowed by a
 *      single-round happy path.
 *
 *   2. Write-past-EOF extend (4 KiB at offset 4 KiB) vs
 *      truncate-to-zero.  Same legal/illegal state taxonomy;
 *      specifically catches servers that accept the write-extending
 *      ALLOCATE while the file is being shrunk to zero.
 *
 * Both cases use fork; the child pwrites, the parent ftruncates.
 * The winner varies per round.  The test's job is ONLY to reject
 * states (X), (Y), (Z) -- it does NOT assume a particular winner.
 *
 * Portable: POSIX.1-2008 fork / pwrite / ftruncate.  No libaio, no
 * librt, no io_uring.
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

static const char *myname = "op_aio_races";

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  concurrent pwrite-vs-ftruncate races (generic/114 shape)\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

/*
 * Run one round.  write_off/write_len describe the child's pwrite;
 * seed is the pattern it lays down.  Returns 0 if the post-round
 * state is one of the legal outcomes (A or B); non-zero on any
 * illegal state.  Complaints are emitted directly; the return value
 * exists so the caller can report round-level pass/fail if desired.
 */
static int run_race_round(const char *fname, off_t write_off,
			  size_t write_len, unsigned seed, int round)
{
	if (truncate(fname, 0) != 0) {
		complain("round %d: reset truncate: %s", round,
			 strerror(errno));
		return 1;
	}

	unsigned char *pattern = malloc(write_len);
	if (!pattern) {
		complain("round %d: malloc", round);
		return 1;
	}
	fill_pattern(pattern, write_len, seed);

	pid_t pid = fork();
	if (pid < 0) {
		complain("round %d: fork: %s", round, strerror(errno));
		free(pattern);
		return 1;
	}
	if (pid == 0) {
		/*
		 * Child: open, pwrite, exit.  We do NOT complain() here
		 * (output is captured by the TAP harness in the parent);
		 * exit status tells the parent whether the pwrite saw a
		 * surprising error.  EBADF / ENOENT / EINTR are all
		 * expected under race conditions and not failures.
		 */
		int fd = open(fname, O_WRONLY);
		if (fd < 0) {
			free(pattern);
			_exit(errno == ENOENT ? 0 : 2);
		}
		ssize_t n = pwrite(fd, pattern, write_len, write_off);
		close(fd);
		free(pattern);
		if (n == (ssize_t)write_len)
			_exit(0);	/* pwrite won, full write */
		if (n < 0) {
			if (errno == EBADF || errno == EINTR)
				_exit(0);
			_exit(3);
		}
		/* Partial write to a regular file is surprising. */
		_exit(4);
	}

	/*
	 * Parent: issue the truncate roughly in parallel.  On NFS over
	 * a fast loopback mount this usually completes before the
	 * child's pwrite RPC returns; on slower paths the winner
	 * varies.  Either outcome is legal.
	 */
	int tfd = open(fname, O_WRONLY);
	if (tfd < 0) {
		complain("round %d: parent open: %s", round, strerror(errno));
		waitpid(pid, NULL, 0);
		free(pattern);
		return 1;
	}
	if (ftruncate(tfd, 0) != 0) {
		complain("round %d: ftruncate: %s", round, strerror(errno));
		close(tfd);
		waitpid(pid, NULL, 0);
		free(pattern);
		return 1;
	}
	close(tfd);

	int status = 0;
	if (waitpid(pid, &status, 0) < 0) {
		complain("round %d: waitpid: %s", round, strerror(errno));
		free(pattern);
		return 1;
	}
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		complain("round %d: child exited unexpectedly "
			 "(status=0x%x) -- treat as invalid race round",
			 round, status);
		free(pattern);
		return 1;
	}

	/* Inspect final state. */
	struct stat st;
	if (stat(fname, &st) != 0) {
		complain("round %d: stat: %s", round, strerror(errno));
		free(pattern);
		return 1;
	}

	off_t expected_written = write_off + (off_t)write_len;
	if (st.st_size == 0) {
		/* State (A): truncate won. */
		free(pattern);
		return 0;
	}
	if (st.st_size == expected_written) {
		/* State (B): pwrite won.  Verify bytes match pattern. */
		int fd = open(fname, O_RDONLY);
		if (fd < 0) {
			complain("round %d: verify open: %s", round,
				 strerror(errno));
			free(pattern);
			return 1;
		}
		unsigned char *rb = malloc(write_len);
		if (!rb) {
			complain("round %d: verify malloc", round);
			close(fd);
			free(pattern);
			return 1;
		}
		int rc = 0;
		if (pread_all(fd, rb, write_len, write_off,
			      "round: verify") == 0) {
			if (memcmp(rb, pattern, write_len) != 0) {
				complain("round %d: pwrite won but content "
					 "differs from pattern (torn or "
					 "interleaved with truncate)",
					 round);
				rc = 1;
			}
			/* If write_off > 0, bytes [0..write_off) must be
			 * zero-filled (hole from the truncate-then-extend
			 * path). */
			if (write_off > 0 && rc == 0) {
				unsigned char *head = malloc(write_off);
				if (head && pread_all(fd, head,
						      (size_t)write_off, 0,
						      "round: verify head")
				    == 0) {
					if (!all_zero(head, (size_t)write_off))
						complain("round %d: head "
							 "[0..%lld) not zero "
							 "after write-extend",
							 round,
							 (long long)write_off);
				}
				free(head);
			}
		}
		free(rb);
		close(fd);
		free(pattern);
		return rc;
	}

	/* State (X) or (Y): illegal. */
	complain("round %d: illegal size %lld (expected 0 or %lld) -- "
		 "torn write / partial truncate",
		 round, (long long)st.st_size, (long long)expected_written);
	free(pattern);
	return 1;
}

static void case_sub_block_vs_truncate(void)
{
	char f[64];
	snprintf(f, sizeof(f), "t_ar.sb.%ld", (long)getpid());
	unlink(f);

	int fd = open(f, O_WRONLY | O_CREAT, 0644);
	if (fd < 0) {
		complain("case1: create: %s", strerror(errno));
		return;
	}
	close(fd);

	const int rounds = Fflag ? 2 : 10;
	for (int i = 0; i < rounds; i++) {
		if (run_race_round(f, 0, 512,
				   (unsigned)(0x5B5B + i), i) != 0)
			break;
	}
	unlink(f);
}

static void case_extend_vs_truncate(void)
{
	char f[64];
	snprintf(f, sizeof(f), "t_ar.ex.%ld", (long)getpid());
	unlink(f);

	int fd = open(f, O_WRONLY | O_CREAT, 0644);
	if (fd < 0) {
		complain("case2: create: %s", strerror(errno));
		return;
	}
	close(fd);

	const int rounds = Fflag ? 2 : 10;
	for (int i = 0; i < rounds; i++) {
		if (run_race_round(f, 4096, 4096,
				   (unsigned)(0xEE00 + i), i) != 0)
			break;
	}
	unlink(f);
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

	prelude(myname, "pwrite vs ftruncate race (xfstests generic/114 shape)");
	cd_or_skip(myname, dir, Nflag);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_sub_block_vs_truncate", case_sub_block_vs_truncate());
	RUN_CASE("case_extend_vs_truncate", case_extend_vs_truncate());

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}
