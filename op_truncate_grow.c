/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_truncate_grow.c -- exercise NFSv4 SETATTR(size) that grows a
 * file, which must create a sparse hole (RFC 7530 S5.8.1.5).
 *
 * ftruncate(fd, new_size) with new_size > current_size must:
 *   - extend the file to new_size;
 *   - fill the gap with zeros (observable as either a hole, an
 *     explicit zero region, or both -- all are valid on-wire);
 *   - not allocate data blocks for the gap (desirable but not
 *     mandatory; we don't test st_blocks).
 *
 * Cases:
 *
 *   1. truncate-grow from empty: ftruncate(fd, 4 KiB) on a 0-byte
 *      file.  stat reports size=4096; read returns 4 KiB of zeros.
 *      (POSIX.1-1990 XSI ftruncate() S5.6.7: "the extended area
 *      shall appear as if it were zero-filled")
 *
 *   2. truncate-grow with prefix data: pwrite 1 KiB, ftruncate to
 *      4 KiB.  First 1 KiB is the pattern; remaining 3 KiB is zero.
 *      (POSIX.1-1990 XSI ftruncate() S5.6.7: zero-fill on extend)
 *
 *   3. truncate-grow past an existing tail: pwrite 1 KiB, ftruncate
 *      to 64 KiB, then SEEK_HOLE from offset 1024 should land inside
 *      the created hole (either immediately or at a block boundary).
 *      Exercises that the server reports the extended region as
 *      sparse via SEEK_HOLE, complementing op_seek.
 *      (POSIX.1-1990 XSI ftruncate() S5.6.7 zero-fill; SEEK_HOLE
 *      is Linux / FreeBSD / macOS 10.15+ only)
 *
 *   4. truncate-grow-then-read beyond size: ftruncate to 4 KiB, read
 *      8 KiB; read should return exactly 4 KiB (EOF), not block or
 *      error.
 *      (POSIX.1-1990 read() S6.4.1: EOF when offset >= file size)
 *
 *   5. truncate-grow over an existing fd with pending writes: pwrite
 *      1 KiB, ftruncate to 4 KiB, pwrite another 512 bytes inside
 *      the hole (at offset 2048).  fstat reports 4 KiB; the hole
 *      between offsets 1024 and 2048 should still read as zeros.
 *      (POSIX.1-1990 XSI ftruncate() S5.6.7: zero-fill semantics)
 *
 * Portable: POSIX.1-1990 XSI ftruncate() S5.6.7 (zero-fill on
 * extend) across Linux / FreeBSD / macOS / Solaris.  SEEK_HOLE in
 * case 3 is Linux / FreeBSD / macOS 10.15+ only.
 */

#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE

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

static const char *myname = "op_truncate_grow";

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  exercise ftruncate grow -> NFSv4 SETATTR(size) with hole\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

/* case 1 ---------------------------------------------------------------- */

static void case_grow_from_empty(void)
{
	char f[64];
	snprintf(f, sizeof(f), "t_tg.em.%ld", (long)getpid());
	unlink(f);

	int fd = open(f, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("case1: open: %s", strerror(errno));
		return;
	}

	if (ftruncate(fd, 4096) != 0) {
		complain("case1: ftruncate(4096): %s", strerror(errno));
		close(fd); unlink(f); return;
	}

	struct stat st;
	if (fstat(fd, &st) != 0) {
		complain("case1: fstat: %s", strerror(errno));
		close(fd); unlink(f); return;
	}
	if (st.st_size != 4096)
		complain("case1: size %lld != 4096 after ftruncate-grow",
			 (long long)st.st_size);

	unsigned char rbuf[4096];
	if (pread_all(fd, rbuf, sizeof(rbuf), 0,
		      "case1: pread over grown region") != 0) {
		close(fd); unlink(f); return;
	}
	if (!all_zero(rbuf, sizeof(rbuf)))
		complain("case1: grown region not all zero "
			 "(SETATTR size did not produce a zero-filled hole)");

	close(fd);
	unlink(f);
}

/* case 2 ---------------------------------------------------------------- */

static void case_grow_with_prefix(void)
{
	char f[64];
	snprintf(f, sizeof(f), "t_tg.pf.%ld", (long)getpid());
	unlink(f);

	int fd = open(f, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("case2: open: %s", strerror(errno));
		return;
	}

	unsigned char prefix[1024];
	fill_pattern(prefix, sizeof(prefix), 12);
	if (pwrite_all(fd, prefix, sizeof(prefix), 0,
		       "case2: pwrite prefix") != 0) {
		close(fd); unlink(f); return;
	}

	if (ftruncate(fd, 4096) != 0) {
		complain("case2: ftruncate(4096): %s", strerror(errno));
		close(fd); unlink(f); return;
	}

	struct stat st;
	if (fstat(fd, &st) != 0) {
		complain("case2: fstat: %s", strerror(errno));
		close(fd); unlink(f); return;
	}
	if (st.st_size != 4096)
		complain("case2: size %lld != 4096", (long long)st.st_size);

	unsigned char readback[4096];
	if (pread_all(fd, readback, sizeof(readback), 0,
		      "case2: pread after grow") != 0) {
		close(fd); unlink(f); return;
	}

	/* Prefix must match the pattern. */
	size_t off = check_pattern(readback, sizeof(prefix), 12);
	if (off != 0)
		complain("case2: prefix corrupted by grow at byte %zu",
			 off - 1);

	/* Tail from [1024 .. 4096) must be zero. */
	if (!all_zero(readback + 1024, sizeof(readback) - 1024))
		complain("case2: grown tail not all zero "
			 "(SETATTR size did not zero-fill past EOF)");

	close(fd);
	unlink(f);
}

/* case 3 ---------------------------------------------------------------- */

static void case_grow_and_seek_hole(void)
{
	char f[64];
	snprintf(f, sizeof(f), "t_tg.sh.%ld", (long)getpid());
	unlink(f);

	int fd = open(f, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("case3: open: %s", strerror(errno));
		return;
	}

	unsigned char head[1024];
	fill_pattern(head, sizeof(head), 3);
	if (pwrite_all(fd, head, sizeof(head), 0,
		       "case3: pwrite head") != 0) {
		close(fd); unlink(f); return;
	}

	if (ftruncate(fd, 65536) != 0) {
		complain("case3: ftruncate(64K): %s", strerror(errno));
		close(fd); unlink(f); return;
	}

#ifdef SEEK_HOLE
	off_t hole = lseek(fd, 1024, SEEK_HOLE);
	if (hole < 0) {
		/*
		 * SEEK_HOLE is allowed to fail with ENXIO or EINVAL if the
		 * backing filesystem does not implement it.  Skip the hole
		 * check with a NOTE but keep the size assertion below.
		 */
		if (!Sflag)
			printf("NOTE: %s: case3 SEEK_HOLE unsupported "
			       "(%s); skipping sparse check\n",
			       myname, strerror(errno));
	} else if (hole < 1024 || hole > 65536) {
		complain("case3: SEEK_HOLE returned %lld "
			 "(expected between 1024 and EOF=65536)",
			 (long long)hole);
	}
#else
	if (!Sflag)
		printf("NOTE: %s: case3 SEEK_HOLE not defined; "
		       "skipping sparse check\n",
		       myname);
#endif

	struct stat st;
	if (fstat(fd, &st) != 0)
		complain("case3: fstat: %s", strerror(errno));
	else if (st.st_size != 65536)
		complain("case3: size %lld != 65536",
			 (long long)st.st_size);

	close(fd);
	unlink(f);
}

/* case 4 ---------------------------------------------------------------- */

static void case_read_past_eof(void)
{
	char f[64];
	snprintf(f, sizeof(f), "t_tg.pe.%ld", (long)getpid());
	unlink(f);

	int fd = open(f, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("case4: open: %s", strerror(errno));
		return;
	}
	if (ftruncate(fd, 4096) != 0) {
		complain("case4: ftruncate(4096): %s", strerror(errno));
		close(fd); unlink(f); return;
	}

	unsigned char rbuf[8192];
	ssize_t n = pread(fd, rbuf, sizeof(rbuf), 0);
	if (n < 0)
		complain("case4: pread 8 KiB on 4 KiB file: %s",
			 strerror(errno));
	else if (n != 4096)
		complain("case4: pread returned %zd (expected 4096)", n);

	close(fd);
	unlink(f);
}

/* case 5 ---------------------------------------------------------------- */

static void case_grow_write_into_hole(void)
{
	char f[64];
	snprintf(f, sizeof(f), "t_tg.hw.%ld", (long)getpid());
	unlink(f);

	int fd = open(f, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("case5: open: %s", strerror(errno));
		return;
	}

	unsigned char head[1024];
	fill_pattern(head, sizeof(head), 5);
	if (pwrite_all(fd, head, sizeof(head), 0,
		       "case5: pwrite head") != 0) {
		close(fd); unlink(f); return;
	}
	if (ftruncate(fd, 4096) != 0) {
		complain("case5: ftruncate(4096): %s", strerror(errno));
		close(fd); unlink(f); return;
	}
	unsigned char mid[512];
	fill_pattern(mid, sizeof(mid), 55);
	if (pwrite_all(fd, mid, sizeof(mid), 2048,
		       "case5: pwrite mid") != 0) {
		close(fd); unlink(f); return;
	}

	struct stat st;
	if (fstat(fd, &st) != 0)
		complain("case5: fstat: %s", strerror(errno));
	else if (st.st_size != 4096)
		complain("case5: size %lld != 4096 after mid write",
			 (long long)st.st_size);

	/* Gap between offset 1024 and 2048 must still be zero. */
	unsigned char gap[1024];
	if (pread_all(fd, gap, sizeof(gap), 1024,
		      "case5: pread gap") != 0) {
		close(fd); unlink(f); return;
	}
	if (!all_zero(gap, sizeof(gap)))
		complain("case5: grown-hole gap not zero after mid write");

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
		"ftruncate grow -> NFSv4 SETATTR(size) hole (RFC 7530 S5.8.1.5)");
	cd_or_skip(myname, dir, Nflag);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_grow_from_empty", case_grow_from_empty());
	RUN_CASE("case_grow_with_prefix", case_grow_with_prefix());
	RUN_CASE("case_grow_and_seek_hole", case_grow_and_seek_hole());
	RUN_CASE("case_read_past_eof", case_read_past_eof());
	RUN_CASE("case_grow_write_into_hole", case_grow_write_into_hole());

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}
