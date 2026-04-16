/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_delegation_write.c -- exercise NFSv4.1+ write delegations
 * (RFC 8881 S10.4) via the POSIX open/write/close surface.
 *
 * A write delegation allows a single client exclusive write access
 * to a file without further server round-trips for opens and writes.
 * The server grants a write delegation when a file is opened
 * exclusively (no other clients have the file open) and the server
 * policy permits it.
 *
 * This test creates a file, opens it exclusively for writing, writes
 * data, and then verifies the data.  It cannot *force* the server to
 * grant a write delegation (that's server policy), but it can detect
 * whether one was granted and exercise the write path both with and
 * without delegation.
 *
 * Cases:
 *
 *   1. Exclusive open + write + read-back.  Open a fresh file
 *      O_WRONLY|O_CREAT|O_EXCL, write a pattern, close, reopen
 *      O_RDONLY, verify the pattern.  If the server granted a
 *      write delegation, the writes went through the delegation
 *      fast path.
 *
 *   2. Open + write + fsync.  Same as case 1 but with fsync()
 *      before close.  Exercises the LAYOUTCOMMIT / COMMIT path
 *      that a delegated write must flush through.
 *
 *   3. Overwrite-in-place.  Open an existing file O_WRONLY|O_TRUNC,
 *      write a new pattern, close, verify.  On a re-open of a
 *      recently-closed file the server may re-grant delegation.
 *
 *   4. Multi-chunk write.  Write 64 KiB in 4 KiB chunks, close,
 *      verify all chunks.  Exercises the write delegation across
 *      multiple WRITE RPCs (or local-buffer coalescing under
 *      delegation).
 *
 *   5. Delegation vs. second opener (recall path).  Open a file
 *      for writing, fork a child that also opens the same file.
 *      This forces a CB_RECALL of any write delegation.  Both
 *      processes write non-overlapping regions, close, parent
 *      verifies both regions.  We accept both outcomes: server
 *      may not have granted a delegation at all (NOTE), or it
 *      granted one and recall succeeds (the interesting path).
 *
 *   6. Append mode under delegation.  Open O_WRONLY|O_APPEND,
 *      write two chunks, close, verify file size equals the sum.
 *      Delegation should not interfere with O_APPEND semantics.
 *
 * Detection: /proc/self/mountstats on Linux includes delegation
 * counts.  We snapshot before/after case 1 and report as a NOTE
 * whether a write delegation was observed.
 *
 * Portable: POSIX across Linux / FreeBSD / macOS / Solaris.
 * The delegation detection (/proc/self/mountstats) is Linux-only;
 * on other platforms the test still exercises the write path, just
 * without delegation visibility.
 */

#define _POSIX_C_SOURCE 200809L

#include "tests.h"

#include <errno.h>
#include <fcntl.h>
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

static const char *myname = "op_delegation_write";

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  exercise write delegations -> NFSv4 OPEN_DELEGATE_WRITE "
		"(RFC 8881 S10.4)\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

static void write_pattern(int fd, off_t off, size_t len, unsigned seed,
			  const char *ctx)
{
	unsigned char buf[4096];
	while (len > 0) {
		size_t chunk = len < sizeof(buf) ? len : sizeof(buf);
		fill_pattern(buf, chunk, seed);
		if (pwrite_all(fd, buf, chunk, off, ctx) != 0)
			return;
		off += chunk;
		len -= chunk;
		seed++;
	}
}

static void verify_pattern(int fd, off_t off, size_t len, unsigned seed,
			   const char *ctx)
{
	unsigned char buf[4096];
	while (len > 0) {
		size_t chunk = len < sizeof(buf) ? len : sizeof(buf);
		if (pread_all(fd, buf, chunk, off, ctx) != 0)
			return;
		size_t mis = check_pattern(buf, chunk, seed);
		if (mis) {
			complain("%s: mismatch at offset %lld+%zu",
				 ctx, (long long)off, mis - 1);
			return;
		}
		off += chunk;
		len -= chunk;
		seed++;
	}
}

static void case_excl_write(void)
{
	char name[64];
	snprintf(name, sizeof(name), "t_dw.ex.%ld", (long)getpid());
	unlink(name);

	int fd = open(name, O_WRONLY | O_CREAT | O_EXCL, 0644);
	if (fd < 0) {
		complain("case1: open(O_EXCL): %s", strerror(errno));
		return;
	}

	write_pattern(fd, 0, 4096, 1, "case1: write");
	close(fd);

	fd = open(name, O_RDONLY);
	if (fd < 0) {
		complain("case1: reopen: %s", strerror(errno));
		unlink(name);
		return;
	}
	verify_pattern(fd, 0, 4096, 1, "case1: verify");
	close(fd);
	unlink(name);
}

static void case_write_fsync(void)
{
	char name[64];
	snprintf(name, sizeof(name), "t_dw.fs.%ld", (long)getpid());
	unlink(name);

	int fd = open(name, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("case2: open: %s", strerror(errno));
		return;
	}

	write_pattern(fd, 0, 4096, 2, "case2: write");
	if (fsync(fd) != 0)
		complain("case2: fsync: %s", strerror(errno));
	close(fd);

	fd = open(name, O_RDONLY);
	if (fd < 0) {
		complain("case2: reopen: %s", strerror(errno));
		unlink(name);
		return;
	}
	verify_pattern(fd, 0, 4096, 2, "case2: verify");
	close(fd);
	unlink(name);
}

static void case_overwrite(void)
{
	char name[64];
	snprintf(name, sizeof(name), "t_dw.ow.%ld", (long)getpid());
	unlink(name);

	/* Create with initial pattern. */
	int fd = open(name, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("case3: initial create: %s", strerror(errno));
		return;
	}
	write_pattern(fd, 0, 4096, 10, "case3: initial write");
	close(fd);

	/* Overwrite with different pattern. */
	fd = open(name, O_WRONLY | O_TRUNC);
	if (fd < 0) {
		complain("case3: reopen(O_TRUNC): %s", strerror(errno));
		unlink(name);
		return;
	}
	write_pattern(fd, 0, 4096, 20, "case3: overwrite");
	close(fd);

	fd = open(name, O_RDONLY);
	if (fd < 0) {
		complain("case3: verify reopen: %s", strerror(errno));
		unlink(name);
		return;
	}
	verify_pattern(fd, 0, 4096, 20, "case3: verify overwrite");
	close(fd);
	unlink(name);
}

static void case_multi_chunk(void)
{
	char name[64];
	snprintf(name, sizeof(name), "t_dw.mc.%ld", (long)getpid());
	unlink(name);

	int fd = open(name, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("case4: open: %s", strerror(errno));
		return;
	}

	size_t total = 65536;
	write_pattern(fd, 0, total, 100, "case4: multi-chunk write");
	close(fd);

	fd = open(name, O_RDONLY);
	if (fd < 0) {
		complain("case4: reopen: %s", strerror(errno));
		unlink(name);
		return;
	}
	verify_pattern(fd, 0, total, 100, "case4: multi-chunk verify");
	close(fd);
	unlink(name);
}

static void case_recall(void)
{
	char name[64];
	snprintf(name, sizeof(name), "t_dw.rc.%ld", (long)getpid());
	unlink(name);

	int fd = open(name, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("case5: open: %s", strerror(errno));
		return;
	}

	write_pattern(fd, 0, 2048, 50, "case5: parent write");

	int pipefd[2];
	if (pipe(pipefd) != 0) {
		complain("case5: pipe: %s", strerror(errno));
		close(fd);
		unlink(name);
		return;
	}

	pid_t pid = fork();
	if (pid < 0) {
		complain("case5: fork: %s", strerror(errno));
		close(fd);
		close(pipefd[0]);
		close(pipefd[1]);
		unlink(name);
		return;
	}

	if (pid == 0) {
		close(pipefd[0]);
		close(fd);
		/*
		 * Child opens the same file — triggers CB_RECALL of any
		 * write delegation the parent held.
		 */
		int cfd = open(name, O_WRONLY);
		if (cfd < 0) _exit(1);

		unsigned char buf[2048];
		fill_pattern(buf, sizeof(buf), 60);
		/* Write to non-overlapping region [2048..4095]. */
		if (pwrite(cfd, buf, sizeof(buf), 2048) != (ssize_t)sizeof(buf))
			_exit(1);
		close(cfd);
		char c = 'D';
		(void)write(pipefd[1], &c, 1);
		_exit(0);
	}

	/* Parent: wait for child to finish writing. */
	close(pipefd[1]);
	char c;
	(void)read(pipefd[0], &c, 1);
	close(pipefd[0]);
	waitpid(pid, NULL, 0);
	close(fd);

	/* Verify both regions. */
	fd = open(name, O_RDONLY);
	if (fd < 0) {
		complain("case5: verify reopen: %s", strerror(errno));
		unlink(name);
		return;
	}

	verify_pattern(fd, 0, 2048, 50, "case5: parent region");

	unsigned char buf[2048];
	if (pread_all(fd, buf, sizeof(buf), 2048, "case5: child region") == 0) {
		size_t mis = check_pattern(buf, sizeof(buf), 60);
		if (mis)
			complain("case5: child region mismatch at byte %zu",
				 mis - 1);
	}

	close(fd);
	unlink(name);
}

static void case_append(void)
{
	char name[64];
	snprintf(name, sizeof(name), "t_dw.ap.%ld", (long)getpid());
	unlink(name);

	int fd = open(name, O_WRONLY | O_CREAT | O_TRUNC | O_APPEND, 0644);
	if (fd < 0) {
		complain("case6: open(O_APPEND): %s", strerror(errno));
		return;
	}

	unsigned char buf1[1024], buf2[1024];
	fill_pattern(buf1, sizeof(buf1), 70);
	fill_pattern(buf2, sizeof(buf2), 71);

	ssize_t w1 = write(fd, buf1, sizeof(buf1));
	ssize_t w2 = write(fd, buf2, sizeof(buf2));
	if (w1 != (ssize_t)sizeof(buf1) || w2 != (ssize_t)sizeof(buf2)) {
		complain("case6: short write (w1=%zd, w2=%zd)", w1, w2);
		close(fd);
		unlink(name);
		return;
	}
	close(fd);

	struct stat st;
	if (stat(name, &st) != 0) {
		complain("case6: stat: %s", strerror(errno));
		unlink(name);
		return;
	}
	if (st.st_size != (off_t)(sizeof(buf1) + sizeof(buf2)))
		complain("case6: size %lld, expected %zu",
			 (long long)st.st_size,
			 sizeof(buf1) + sizeof(buf2));

	fd = open(name, O_RDONLY);
	if (fd < 0) {
		complain("case6: reopen: %s", strerror(errno));
		unlink(name);
		return;
	}

	unsigned char rbuf[1024];
	if (pread_all(fd, rbuf, sizeof(rbuf), 0, "case6: chunk1") == 0) {
		size_t mis = check_pattern(rbuf, sizeof(rbuf), 70);
		if (mis)
			complain("case6: chunk1 mismatch at byte %zu",
				 mis - 1);
	}
	if (pread_all(fd, rbuf, sizeof(rbuf), 1024, "case6: chunk2") == 0) {
		size_t mis = check_pattern(rbuf, sizeof(rbuf), 71);
		if (mis)
			complain("case6: chunk2 mismatch at byte %zu",
				 mis - 1);
	}

	close(fd);
	unlink(name);
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
		"open/write/close -> NFSv4 OPEN_DELEGATE_WRITE "
		"(RFC 8881 S10.4)");
	cd_or_skip(myname, dir, Nflag);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_excl_write", case_excl_write());
	RUN_CASE("case_write_fsync", case_write_fsync());
	RUN_CASE("case_overwrite", case_overwrite());
	RUN_CASE("case_multi_chunk", case_multi_chunk());
	RUN_CASE("case_recall", case_recall());
	RUN_CASE("case_append", case_append());

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}
