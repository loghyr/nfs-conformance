/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_read_write.c -- exercise the basic read(2) / write(2) /
 * pread(2) / pwrite(2) contract over NFS.
 *
 * Every other test in this suite builds on the assumption that the
 * mount can store and retrieve bytes correctly.  This test verifies
 * that assumption directly: write N bytes, read them back, and check
 * what came out.  It is the foundation, and worth a dedicated binary
 * so a regression in basic I/O surfaces here rather than as chaos
 * across forty other tests.
 *
 * Cases:
 *
 *   1. Same-fd round-trip.  Write a short buffer, lseek to 0, read
 *      it back via the same fd, compare.
 *
 *   2. Close-reopen round-trip.  Write, close, reopen, read.  This
 *      forces any client-side write buffer to commit and a fresh fd
 *      to pick up the data via a new OPEN.
 *
 *   3. pwrite / pread at arbitrary offsets (non-sequential I/O).
 *      pwrite at offsets 1024, 64, 8192 in that order; pread each
 *      back in a different order; verify.
 *
 *   4. Sparse write past EOF auto-extends.  lseek to 4096, write
 *      a pattern, pread the [0, 4096) hole -- must be zeros; pread
 *      the written pattern -- must match.  File size must equal
 *      write-end.
 *
 *   5. Read at exactly EOF returns 0.  POSIX: a read issued when
 *      the offset equals the file size returns 0 bytes, not an
 *      error and not a short count.
 *
 *   6. Read past EOF returns 0.  Same, with offset strictly beyond
 *      file size.  MUST NOT return EINVAL or EIO.
 *
 *   7. Sequential writes accumulate.  write(fd, "aa", 2); write(fd,
 *      "bb", 2); the fd offset advances and the file now reads
 *      "aabb".
 *
 *   8. Short read at tail.  Write 10 bytes; read 100 from offset 0.
 *      Expect return value 10, not -1, not 100.
 *
 *   9. Zero-length read/write are no-ops that return 0.  Catches
 *      servers that erroneously return EINVAL on len=0.
 *
 * Portable: POSIX across every platform we target.
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

static const char *myname = "op_read_write";

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  basic read/write contract over NFS\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

static int create_scratch(char *out, size_t sz, int casenum)
{
	snprintf(out, sz, "t_rw.%d.%ld", casenum, (long)getpid());
	unlink(out);
	int fd = open(out, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) return -1;
	return fd;
}

static void case_same_fd_round_trip(void)
{
	char a[64];
	int fd = create_scratch(a, sizeof(a), 1);
	if (fd < 0) {
		complain("case1: create: %s", strerror(errno));
		return;
	}

	const char msg[] = "the quick brown fox";
	ssize_t w = write(fd, msg, sizeof(msg));
	if (w != (ssize_t)sizeof(msg)) {
		complain("case1: write %zd / %zu: %s",
			 w, sizeof(msg), strerror(errno));
		close(fd); unlink(a); return;
	}
	if (lseek(fd, 0, SEEK_SET) != 0) {
		complain("case1: lseek 0: %s", strerror(errno));
		close(fd); unlink(a); return;
	}
	char buf[sizeof(msg)] = {0};
	ssize_t r = read(fd, buf, sizeof(buf));
	close(fd);
	if (r != (ssize_t)sizeof(msg))
		complain("case1: read %zd / %zu", r, sizeof(msg));
	else if (memcmp(buf, msg, sizeof(msg)) != 0)
		complain("case1: data mismatch ('%s' vs '%s')", buf, msg);

	unlink(a);
}

static void case_close_reopen_round_trip(void)
{
	char a[64];
	int fd = create_scratch(a, sizeof(a), 2);
	if (fd < 0) {
		complain("case2: create: %s", strerror(errno));
		return;
	}
	const char msg[] = "close-reopen-check";
	if (write(fd, msg, sizeof(msg)) != (ssize_t)sizeof(msg)) {
		complain("case2: write: %s", strerror(errno));
		close(fd); unlink(a); return;
	}
	close(fd);

	int rfd = open(a, O_RDONLY);
	if (rfd < 0) {
		complain("case2: reopen: %s", strerror(errno));
		unlink(a); return;
	}
	char buf[sizeof(msg)] = {0};
	ssize_t r = read(rfd, buf, sizeof(buf));
	close(rfd);
	if (r != (ssize_t)sizeof(msg))
		complain("case2: read %zd / %zu", r, sizeof(msg));
	else if (memcmp(buf, msg, sizeof(msg)) != 0)
		complain("case2: data mismatch after close-reopen");

	unlink(a);
}

static void case_pwrite_pread_offsets(void)
{
	char a[64];
	int fd = create_scratch(a, sizeof(a), 3);
	if (fd < 0) {
		complain("case3: create: %s", strerror(errno));
		return;
	}

	struct { off_t off; const char *pat; size_t len; } writes[] = {
		{ 1024, "AAAA", 4 },
		{   64, "BBBB", 4 },
		{ 8192, "CCCC", 4 },
	};
	for (size_t i = 0; i < 3; i++) {
		if (pwrite(fd, writes[i].pat, writes[i].len, writes[i].off)
		    != (ssize_t)writes[i].len) {
			complain("case3: pwrite[%zu]@%lld: %s",
				 i, (long long)writes[i].off,
				 strerror(errno));
			close(fd); unlink(a); return;
		}
	}

	/* Read back in reverse offset order. */
	struct { off_t off; const char *expected; size_t len; } reads[] = {
		{ 8192, "CCCC", 4 },
		{ 1024, "AAAA", 4 },
		{   64, "BBBB", 4 },
	};
	char buf[8] = {0};
	for (size_t i = 0; i < 3; i++) {
		memset(buf, 0, sizeof(buf));
		ssize_t r = pread(fd, buf, reads[i].len, reads[i].off);
		if (r != (ssize_t)reads[i].len)
			complain("case3: pread[%zu]@%lld returned %zd",
				 i, (long long)reads[i].off, r);
		else if (memcmp(buf, reads[i].expected, reads[i].len) != 0)
			complain("case3: pread[%zu]@%lld got '%.*s' "
				 "(expected '%s')",
				 i, (long long)reads[i].off,
				 (int)reads[i].len, buf,
				 reads[i].expected);
	}

	close(fd);
	unlink(a);
}

static void case_sparse_write_past_eof(void)
{
	char a[64];
	int fd = create_scratch(a, sizeof(a), 4);
	if (fd < 0) {
		complain("case4: create: %s", strerror(errno));
		return;
	}

	const char pat[] = "PATTERN!";
	if (lseek(fd, 4096, SEEK_SET) != 4096) {
		complain("case4: lseek: %s", strerror(errno));
		close(fd); unlink(a); return;
	}
	if (write(fd, pat, sizeof(pat)) != (ssize_t)sizeof(pat)) {
		complain("case4: write: %s", strerror(errno));
		close(fd); unlink(a); return;
	}

	struct stat st;
	if (fstat(fd, &st) != 0) {
		complain("case4: fstat: %s", strerror(errno));
		close(fd); unlink(a); return;
	}
	if (st.st_size != (off_t)(4096 + sizeof(pat)))
		complain("case4: size %lld, expected %zu",
			 (long long)st.st_size, 4096 + sizeof(pat));

	/* Hole region [0, 4096) must read zero. */
	char hole[128];
	memset(hole, 0xFF, sizeof(hole));
	if (pread(fd, hole, sizeof(hole), 0) != (ssize_t)sizeof(hole)) {
		complain("case4: pread hole: %s", strerror(errno));
	} else {
		for (size_t i = 0; i < sizeof(hole); i++) {
			if (hole[i] != 0) {
				complain("case4: hole byte %zu = 0x%02x "
					 "(expected 0)", i,
					 (unsigned char)hole[i]);
				break;
			}
		}
	}

	/* Pattern region must match. */
	char check[sizeof(pat)] = {0};
	if (pread(fd, check, sizeof(check), 4096) != (ssize_t)sizeof(check))
		complain("case4: pread pattern: %s", strerror(errno));
	else if (memcmp(check, pat, sizeof(pat)) != 0)
		complain("case4: pattern mismatch at offset 4096");

	close(fd);
	unlink(a);
}

static void case_read_at_eof(void)
{
	char a[64];
	int fd = create_scratch(a, sizeof(a), 5);
	if (fd < 0) {
		complain("case5: create: %s", strerror(errno));
		return;
	}
	if (write(fd, "hi", 2) != 2) {
		complain("case5: write: %s", strerror(errno));
		close(fd); unlink(a); return;
	}

	char buf[4];
	errno = 0;
	ssize_t r = pread(fd, buf, sizeof(buf), 2);     /* offset == size */
	if (r < 0)
		complain("case5: pread at EOF failed: %s",
			 strerror(errno));
	else if (r != 0)
		complain("case5: pread at EOF returned %zd "
			 "(expected 0)", r);

	close(fd);
	unlink(a);
}

static void case_read_past_eof(void)
{
	char a[64];
	int fd = create_scratch(a, sizeof(a), 6);
	if (fd < 0) {
		complain("case6: create: %s", strerror(errno));
		return;
	}
	if (write(fd, "hi", 2) != 2) {
		complain("case6: write: %s", strerror(errno));
		close(fd); unlink(a); return;
	}

	char buf[4];
	errno = 0;
	ssize_t r = pread(fd, buf, sizeof(buf), 1000);  /* well past EOF */
	if (r < 0)
		complain("case6: pread past EOF failed: %s "
			 "(POSIX: return 0, not an error)",
			 strerror(errno));
	else if (r != 0)
		complain("case6: pread past EOF returned %zd", r);

	close(fd);
	unlink(a);
}

static void case_sequential_writes_accumulate(void)
{
	char a[64];
	int fd = create_scratch(a, sizeof(a), 7);
	if (fd < 0) {
		complain("case7: create: %s", strerror(errno));
		return;
	}
	if (write(fd, "aa", 2) != 2 || write(fd, "bb", 2) != 2) {
		complain("case7: write: %s", strerror(errno));
		close(fd); unlink(a); return;
	}
	off_t pos = lseek(fd, 0, SEEK_CUR);
	if (pos != 4)
		complain("case7: offset %lld, expected 4",
			 (long long)pos);

	char buf[5] = {0};
	if (pread(fd, buf, 4, 0) != 4)
		complain("case7: pread: %s", strerror(errno));
	else if (memcmp(buf, "aabb", 4) != 0)
		complain("case7: got '%s', expected 'aabb'", buf);

	close(fd);
	unlink(a);
}

static void case_short_read_tail(void)
{
	char a[64];
	int fd = create_scratch(a, sizeof(a), 8);
	if (fd < 0) {
		complain("case8: create: %s", strerror(errno));
		return;
	}
	if (write(fd, "0123456789", 10) != 10) {
		complain("case8: write: %s", strerror(errno));
		close(fd); unlink(a); return;
	}

	char buf[100];
	memset(buf, 0xFF, sizeof(buf));
	ssize_t r = pread(fd, buf, sizeof(buf), 0);
	if (r != 10)
		complain("case8: short read returned %zd (expected 10)",
			 r);
	else if (memcmp(buf, "0123456789", 10) != 0)
		complain("case8: data mismatch");

	close(fd);
	unlink(a);
}

static void case_zero_length(void)
{
	char a[64];
	int fd = create_scratch(a, sizeof(a), 9);
	if (fd < 0) {
		complain("case9: create: %s", strerror(errno));
		return;
	}
	if (write(fd, "x", 1) != 1) {
		complain("case9: setup write: %s", strerror(errno));
		close(fd); unlink(a); return;
	}

	errno = 0;
	ssize_t w0 = write(fd, "", 0);
	if (w0 < 0)
		complain("case9: write(len=0) returned error %s",
			 strerror(errno));
	else if (w0 != 0)
		complain("case9: write(len=0) returned %zd (expected 0)",
			 w0);

	char buf[1];
	errno = 0;
	ssize_t r0 = pread(fd, buf, 0, 0);
	if (r0 < 0)
		complain("case9: pread(len=0) returned error %s",
			 strerror(errno));
	else if (r0 != 0)
		complain("case9: pread(len=0) returned %zd (expected 0)",
			 r0);

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

	prelude(myname, "basic read/write/pread/pwrite contract");
	cd_or_skip(myname, dir, Nflag);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_same_fd_round_trip", case_same_fd_round_trip());
	RUN_CASE("case_close_reopen_round_trip",
		 case_close_reopen_round_trip());
	RUN_CASE("case_pwrite_pread_offsets",
		 case_pwrite_pread_offsets());
	RUN_CASE("case_sparse_write_past_eof",
		 case_sparse_write_past_eof());
	RUN_CASE("case_read_at_eof", case_read_at_eof());
	RUN_CASE("case_read_past_eof", case_read_past_eof());
	RUN_CASE("case_sequential_writes_accumulate",
		 case_sequential_writes_accumulate());
	RUN_CASE("case_short_read_tail", case_short_read_tail());
	RUN_CASE("case_zero_length", case_zero_length());

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}
