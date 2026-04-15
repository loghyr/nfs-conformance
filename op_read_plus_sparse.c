/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_read_plus_sparse.c -- exercise the NFSv4.2 READ_PLUS op
 * (RFC 7862 S15) over sparse files.
 *
 * READ_PLUS lets the server return a reply that distinguishes data
 * extents from holes instead of streaming zeros for every sparse
 * byte.  The Linux NFS client uses READ_PLUS transparently under
 * read(2) when the kernel and server both support it; from user
 * space the only observable requirement is "reads over holes return
 * zeros, reads over data return the data, and reads across a hole
 * boundary produce a seamless buffer."
 *
 * Cases:
 *
 *   1. Punch-in-the-middle: pwrite a 4 KiB pattern at offset 0,
 *      pwrite another 4 KiB pattern at offset 16 KiB, read the
 *      12 KiB hole in between.  The read must return zeros.
 *
 *   2. Large hole: create a 1 MiB file with no writes (via ftruncate)
 *      and read it in 64 KiB chunks.  Every byte must be zero.
 *      Exercises the READ_PLUS path for a file that is entirely a
 *      single hole extent.
 *
 *   3. Cross-boundary read: pwrite a pattern at offset 8 KiB..12 KiB,
 *      then read 16 KiB from offset 4 KiB.  The result must be
 *      [zeros | pattern | zeros], i.e. the server must stitch hole
 *      + data + hole extents back into a contiguous buffer.
 *
 *   4. Aligned-hole-only: read exactly a 64 KiB hole at offset 0 of
 *      an ftruncate'd file.  Ensures that the server returns a pure
 *      hole extent without requiring a preceding data extent.
 *
 *   5. Tail hole: pwrite a 4 KiB pattern at offset 0, ftruncate to
 *      64 KiB, read the 60 KiB tail.  Exercises a reply that is
 *      data-then-hole (the tail-hole case is a common server bug).
 *
 * Portable: POSIX pread / ftruncate.  No dependence on any userspace
 * READ_PLUS API -- Linux NFS client chooses READ_PLUS when available
 * and the test only observes the POSIX-visible outcome.
 */

#define _POSIX_C_SOURCE 200809L

#include "tests.h"

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

static const char *myname = "op_read_plus_sparse";

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  exercise sparse reads -> NFSv4.2 READ_PLUS (RFC 7862 S15)\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

/* case 1 ---------------------------------------------------------------- */

static void case_punch_middle(void)
{
	char f[64];
	snprintf(f, sizeof(f), "t_rp.pm.%ld", (long)getpid());
	unlink(f);

	int fd = open(f, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("case1: open: %s", strerror(errno));
		return;
	}

	unsigned char head[4096];
	unsigned char tail[4096];
	fill_pattern(head, sizeof(head), 11);
	fill_pattern(tail, sizeof(tail), 22);

	if (pwrite_all(fd, head, sizeof(head), 0,
		       "case1: pwrite head") != 0) {
		close(fd); unlink(f); return;
	}
	if (pwrite_all(fd, tail, sizeof(tail), 16384,
		       "case1: pwrite tail") != 0) {
		close(fd); unlink(f); return;
	}

	/* Read the 12 KiB hole between offsets 4096 and 16384. */
	unsigned char hole[12288];
	if (pread_all(fd, hole, sizeof(hole), 4096,
		      "case1: pread hole") != 0) {
		close(fd); unlink(f); return;
	}
	if (!all_zero(hole, sizeof(hole)))
		complain("case1: hole region not all zero "
			 "(READ_PLUS did not materialise hole as zeros)");

	close(fd);
	unlink(f);
}

/* case 2 ---------------------------------------------------------------- */

static void case_giant_hole(void)
{
	char f[64];
	snprintf(f, sizeof(f), "t_rp.gh.%ld", (long)getpid());
	unlink(f);

	int fd = open(f, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("case2: open: %s", strerror(errno));
		return;
	}

	if (ftruncate(fd, 1024 * 1024) != 0) {
		complain("case2: ftruncate(1 MiB): %s", strerror(errno));
		close(fd); unlink(f); return;
	}

	unsigned char chunk[65536];
	for (int i = 0; i < 16; i++) {
		if (pread_all(fd, chunk, sizeof(chunk),
			      (off_t)i * (off_t)sizeof(chunk),
			      "case2: pread 64K chunk") != 0) {
			close(fd); unlink(f); return;
		}
		if (!all_zero(chunk, sizeof(chunk))) {
			complain("case2: 64 KiB chunk %d not zero "
				 "(READ_PLUS over pure hole returned nonzero)",
				 i);
			break;
		}
	}

	close(fd);
	unlink(f);
}

/* case 3 ---------------------------------------------------------------- */

static void case_cross_boundary(void)
{
	char f[64];
	snprintf(f, sizeof(f), "t_rp.cb.%ld", (long)getpid());
	unlink(f);

	int fd = open(f, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("case3: open: %s", strerror(errno));
		return;
	}
	if (ftruncate(fd, 16384) != 0) {
		complain("case3: ftruncate: %s", strerror(errno));
		close(fd); unlink(f); return;
	}
	unsigned char mid[4096];
	fill_pattern(mid, sizeof(mid), 33);
	if (pwrite_all(fd, mid, sizeof(mid), 8192,
		       "case3: pwrite middle") != 0) {
		close(fd); unlink(f); return;
	}

	unsigned char rbuf[16384];
	if (pread_all(fd, rbuf, sizeof(rbuf), 0,
		      "case3: pread full") != 0) {
		close(fd); unlink(f); return;
	}

	/* [0..8192) must be zero. */
	if (!all_zero(rbuf, 8192))
		complain("case3: leading hole not zero "
			 "(READ_PLUS stitched hole incorrectly)");
	/* [8192..12288) must match pattern. */
	if (memcmp(rbuf + 8192, mid, 4096) != 0)
		complain("case3: data extent mismatch "
			 "(READ_PLUS lost data across hole boundary)");
	/* [12288..16384) must be zero. */
	if (!all_zero(rbuf + 12288, 4096))
		complain("case3: trailing hole not zero "
			 "(READ_PLUS did not restitch trailing hole)");

	close(fd);
	unlink(f);
}

/* case 4 ---------------------------------------------------------------- */

static void case_pure_hole(void)
{
	char f[64];
	snprintf(f, sizeof(f), "t_rp.ph.%ld", (long)getpid());
	unlink(f);

	int fd = open(f, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("case4: open: %s", strerror(errno));
		return;
	}
	if (ftruncate(fd, 65536) != 0) {
		complain("case4: ftruncate: %s", strerror(errno));
		close(fd); unlink(f); return;
	}

	unsigned char rbuf[65536];
	if (pread_all(fd, rbuf, sizeof(rbuf), 0,
		      "case4: pread pure hole") != 0) {
		close(fd); unlink(f); return;
	}
	if (!all_zero(rbuf, sizeof(rbuf)))
		complain("case4: pure-hole read nonzero "
			 "(server fabricated data bytes for an unwritten file)");

	close(fd);
	unlink(f);
}

/* case 5 ---------------------------------------------------------------- */

static void case_tail_hole(void)
{
	char f[64];
	snprintf(f, sizeof(f), "t_rp.th.%ld", (long)getpid());
	unlink(f);

	int fd = open(f, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("case5: open: %s", strerror(errno));
		return;
	}
	unsigned char head[4096];
	fill_pattern(head, sizeof(head), 55);
	if (pwrite_all(fd, head, sizeof(head), 0,
		       "case5: pwrite head") != 0) {
		close(fd); unlink(f); return;
	}
	if (ftruncate(fd, 65536) != 0) {
		complain("case5: ftruncate: %s", strerror(errno));
		close(fd); unlink(f); return;
	}

	/* Read the 60 KiB tail starting at offset 4 KiB. */
	const size_t tail_len = 65536 - 4096;
	unsigned char *tail = malloc(tail_len);
	if (!tail) {
		complain("case5: malloc tail");
		close(fd); unlink(f); return;
	}
	if (pread_all(fd, tail, tail_len, 4096,
		      "case5: pread tail") != 0) {
		free(tail); close(fd); unlink(f); return;
	}
	if (!all_zero(tail, tail_len))
		complain("case5: tail hole nonzero "
			 "(READ_PLUS mis-stitched data-then-hole reply)");

	free(tail);
	close(fd);
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

	prelude(myname,
		"sparse reads -> NFSv4.2 READ_PLUS (RFC 7862 S15)");
	cd_or_skip(myname, dir, Nflag);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	case_punch_middle();
	case_giant_hole();
	case_cross_boundary();
	case_pure_hole();
	case_tail_hole();

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}
