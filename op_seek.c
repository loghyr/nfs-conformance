/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_seek.c -- exercise SEEK_HOLE / SEEK_DATA (NFSv4.2 SEEK,
 * RFC 7862 S6) and verify reads across holes return zeros
 * (indirectly exercising READ_PLUS, RFC 7862 S8).
 *
 * Builds a sparse file with three data islands and holes between
 * them; walks with lseek(SEEK_HOLE/SEEK_DATA); reads through each
 * hole.
 *
 * RFC 7862 S11.21 note: for SEEK past EOF some server
 * implementations return sr_eof=TRUE + position=file size rather
 * than ENXIO.  Linux client returns ENXIO from lseek in that case,
 * but to stay portable we accept either "returned ENXIO" or
 * "returned offset == file size".
 *
 * SKIP on systems without SEEK_HOLE/SEEK_DATA defined (older macOS,
 * older BSDs).
 */

#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700
#define _GNU_SOURCE /* Linux: SEEK_HOLE/DATA live in <unistd.h> */

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

static const char *myname = "op_seek";

#if !defined(SEEK_HOLE) || !defined(SEEK_DATA)
int main(void)
{
	skip("%s: SEEK_HOLE / SEEK_DATA macros not defined on this platform",
	     myname);
	return TEST_SKIP;
}
#else

#define FILE_LEN  (16 * 1024 * 1024)
#define ISLAND_LEN (64 * 1024)

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  exercise SEEK_HOLE/SEEK_DATA -> NFSv4.2 SEEK + READ_PLUS\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

/*
 * island_at -- offset of the i-th (0..2) data island.  Three islands
 * spaced FILE_LEN/4 apart so they're at roughly 1/8, 3/8, 5/8 of the
 * file with holes between and after.
 */
static off_t island_at(int i)
{
	off_t quarter = FILE_LEN / 4;
	return (off_t)(i * quarter + quarter / 2);
}

static int build_sparse_file(int fd)
{
	if (ftruncate(fd, FILE_LEN) != 0) {
		complain("ftruncate(%d): %s", FILE_LEN, strerror(errno));
		return -1;
	}
	unsigned char *buf = malloc(ISLAND_LEN);
	if (!buf) {
		complain("malloc");
		return -1;
	}
	for (int i = 0; i < 3; i++) {
		fill_pattern(buf, ISLAND_LEN, 0xA5A5A5A5u + (unsigned)i);
		char ctx[32];
		snprintf(ctx, sizeof(ctx), "island %d", i);
		if (pwrite_all(fd, buf, ISLAND_LEN, island_at(i), ctx) < 0) {
			free(buf);
			return -1;
		}
	}
	free(buf);
	if (fdatasync(fd) != 0 && !Sflag)
		printf("NOTE: %s: fdatasync (non-fatal): %s\n",
		       myname, strerror(errno));
	return 0;
}

static void verify_seek_hole_data(int fd)
{
	/* Case 1a: SEEK_DATA at offset 0 lands at or before island 0. */
	off_t pos = lseek(fd, 0, SEEK_DATA);
	if (pos < 0)
		complain("SEEK_DATA at 0: %s", strerror(errno));
	else if (pos > island_at(0))
		complain("SEEK_DATA at 0 overshot: %lld > island0 %lld",
			 (long long)pos, (long long)island_at(0));

	/* Case 1b: SEEK_HOLE from the end of island 0 finds a hole
	 * at or after the end of the island. */
	off_t isl0_end = island_at(0) + ISLAND_LEN;
	off_t hole = lseek(fd, island_at(0), SEEK_HOLE);
	if (hole < 0)
		complain("SEEK_HOLE at island0: %s", strerror(errno));
	else if (hole < isl0_end)
		complain("SEEK_HOLE at island0 reports premature hole "
			 "(%lld < %lld)",
			 (long long)hole, (long long)isl0_end);

	/*
	 * Case 1c: SEEK_DATA past EOF.  POSIX-ish convention is
	 * return -1/ENXIO; NFSv4.2 servers that set sr_eof=TRUE can
	 * legally return offset == file size (Linux client surfaces
	 * this as a successful lseek to that offset).  Accept either.
	 */
	struct stat st;
	if (fstat(fd, &st) != 0) {
		complain("fstat for past-EOF check: %s", strerror(errno));
		return;
	}
	errno = 0;
	off_t past = lseek(fd, st.st_size + 1, SEEK_DATA);
	if (past == -1 && errno == ENXIO) {
		/* Linux / ext4 / most NFS clients */
	} else if (past == st.st_size) {
		/* Per sr_eof semantics; accept */
	} else {
		complain("SEEK_DATA past EOF: expected -1/ENXIO or "
			 "%lld, got %lld/%s",
			 (long long)st.st_size, (long long)past,
			 past == -1 ? strerror(errno) : "no-error");
	}

	/* Case 1d: SEEK_HOLE in last island finds the virtual hole at EOF. */
	off_t last_hole = lseek(fd, island_at(2), SEEK_HOLE);
	if (last_hole < 0)
		complain("SEEK_HOLE in last island: %s", strerror(errno));
	else if (last_hole < island_at(2) + ISLAND_LEN)
		complain("SEEK_HOLE in last island premature "
			 "(%lld < %lld)",
			 (long long)last_hole,
			 (long long)(island_at(2) + ISLAND_LEN));
}

static void verify_hole_reads_zero(int fd)
{
	unsigned char *buf = malloc(ISLAND_LEN);
	if (!buf) {
		complain("malloc");
		return;
	}

	for (int i = 0; i < 2; i++) {
		off_t hole_start = island_at(i) + ISLAND_LEN;
		char ctx[32];
		snprintf(ctx, sizeof(ctx), "hole %d", i);
		if (pread_all(fd, buf, ISLAND_LEN, hole_start, ctx) < 0)
			continue;
		if (!all_zero(buf, ISLAND_LEN))
			complain("hole %d not all zero", i);
	}

	off_t last_start = island_at(2) + ISLAND_LEN;
	off_t sample = (FILE_LEN - last_start < ISLAND_LEN)
			       ? (FILE_LEN - last_start)
			       : ISLAND_LEN;
	if (sample > 0) {
		if (pread_all(fd, buf, (size_t)sample, last_start,
			      "post-last hole") == 0) {
			if (!all_zero(buf, (size_t)sample))
				complain("post-last-island hole not all zero");
		}
	}
	free(buf);
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
		"lseek(SEEK_HOLE/SEEK_DATA) + sparse read -> SEEK + READ_PLUS");
	cd_or_skip(myname, dir, Nflag);

	char name[64];
	int fd = scratch_open("t12", name, sizeof(name));

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	if (build_sparse_file(fd) == 0) {
		verify_seek_hole_data(fd);
		verify_hole_reads_zero(fd);
	}

	close(fd);
	unlink(name);

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}

#endif /* SEEK_HOLE / SEEK_DATA */
