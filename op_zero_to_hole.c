/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_zero_to_hole.c -- does the server convert explicit zero writes
 * into server-side holes?
 *
 * POSIX allows, but does not require, a filesystem to detect that a
 * block of all-zero bytes was written and represent it as a hole
 * rather than an allocated zero-filled block.  Different NFS server
 * backends choose differently:
 *
 *   - ZFS with compress=zle/lz4, btrfs with nodatacow off, WAFL
 *     under some configurations, NetApp FlexVol with space-guarantee
 *     none: YES, they detect and punch.
 *   - ext4, xfs (default), raw block devices: NO, they allocate and
 *     write zeros.
 *
 * Both behaviours are conformant.  The test observes and reports
 * the server's choice without asserting either outcome.
 *
 * What we observe:
 *
 *   - SEEK_DATA / SEEK_HOLE after the write tells us how the server
 *     represents the written region.
 *   - Data read-back must ALWAYS return zeros regardless of the
 *     server's choice (this is the correctness axis and IS
 *     asserted).
 *
 * Every test fdatasyncs before observation so the server-side state
 * is what we are measuring, not the client page cache.
 *
 * Cases:
 *
 *   1. Single all-zero block.  Create an empty file, pwrite 4 KiB
 *      of zeros at offset 0, fdatasync.  SEEK_HOLE from 0 reports
 *      either (server kept as data) or a hole at 0 (server punched).
 *      Data read-back must be zeros.
 *
 *   2. All-zero block at offset 4 KiB + all-zero block at offset
 *      12 KiB with a real hole (no writes) between and after.
 *      Count the hole/data extents the server reports:
 *        - 0 extents: entire file is one hole (server punched both)
 *        - 1 data, rest holes: servers vary in coalescing
 *        - 2 data extents, 3 holes: server kept both zero writes
 *          as data (ext4 / xfs behaviour)
 *      Report the extent layout as a NOTE so you can see exactly
 *      what the server did.
 *      Data read-back at any offset must return zeros.
 *
 *   3. Mixed: real data at block 0, zeros at block 1, real data at
 *      block 2.  Does the middle zero write become a hole between
 *      two data extents?  Report the layout.
 *
 *   4. Zero write over existing data: pwrite nonzero pattern, then
 *      pwrite zeros of the same length at the same offset, fdatasync.
 *      Does the server punch the previously-allocated block?  Real-
 *      world relevance: `dd if=/dev/zero of=... conv=sparse`.  Report.
 *
 * Portable: POSIX.1-2008 SEEK_HOLE / SEEK_DATA.  Skips if those
 * macros are not defined.
 */

#define _POSIX_C_SOURCE 200809L
#ifndef __FreeBSD__
#define _XOPEN_SOURCE 700
#endif
#define _GNU_SOURCE

#include "tests.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
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

static const char *myname = "op_zero_to_hole";

#if !defined(SEEK_HOLE) || !defined(SEEK_DATA)
int main(void)
{
	skip("%s: SEEK_HOLE / SEEK_DATA not defined on this platform",
	     myname);
	return TEST_SKIP;
}
#else

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  observe whether server converts zero writes to holes\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

#define BLK 4096u

/*
 * describe_extents -- walk the file with SEEK_DATA / SEEK_HOLE and
 * emit a NOTE describing the extent layout as the server presents
 * it (per POSIX/NFSv4.2 SEEK semantics).  Returns the number of
 * distinct DATA extents seen; 0 means the file has no server-side
 * data extents (all implicit hole).
 */
static int describe_extents(int fd, off_t size, const char *label)
{
	off_t pos = 0;
	int n_data = 0, n_hole = 0;
	if (!Sflag)
		printf("NOTE: %s: %s extent layout (size=%lld):\n",
		       myname, label, (long long)size);
	while (pos < size) {
		off_t data = lseek(fd, pos, SEEK_DATA);
		if (data == -1) {
			if (errno == ENXIO) {
				/* No further data; rest is hole. */
				if (!Sflag && pos < size)
					printf("  [hole  %lld..%lld)\n",
					       (long long)pos,
					       (long long)size);
				n_hole++;
				break;
			}
			if (!Sflag)
				printf("  (SEEK_DATA at %lld: %s)\n",
				       (long long)pos, strerror(errno));
			return -1;
		}
		if (data > pos) {
			if (!Sflag)
				printf("  [hole  %lld..%lld)\n",
				       (long long)pos, (long long)data);
			n_hole++;
		}
		off_t hole = lseek(fd, data, SEEK_HOLE);
		if (hole == -1 || hole > size) hole = size;
		if (!Sflag)
			printf("  [data  %lld..%lld)\n",
			       (long long)data, (long long)hole);
		n_data++;
		pos = hole;
	}
	if (!Sflag)
		printf("  summary: %d data extent(s), %d hole extent(s)\n",
		       n_data, n_hole);
	return n_data;
}

static int verify_all_zero(int fd, off_t size, const char *label)
{
	unsigned char *buf = malloc((size_t)size);
	if (!buf) {
		complain("%s: malloc %lld", label, (long long)size);
		return -1;
	}
	ssize_t r = pread(fd, buf, (size_t)size, 0);
	if (r != size) {
		complain("%s: pread %zd / %lld: %s",
			 label, r, (long long)size, strerror(errno));
		free(buf);
		return -1;
	}
	for (off_t i = 0; i < size; i++) {
		if (buf[i] != 0) {
			complain("%s: byte %lld = 0x%02x (expected 0)",
				 label, (long long)i,
				 (unsigned)buf[i]);
			free(buf);
			return -1;
		}
	}
	free(buf);
	return 0;
}

static void case_single_zero_block(void)
{
	char f[64];
	snprintf(f, sizeof(f), "t_zh.s.%ld", (long)getpid());
	unlink(f);

	int fd = open(f, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) { complain("case1: open: %s", strerror(errno)); return; }

	unsigned char zeros[BLK] = {0};
	if (pwrite(fd, zeros, BLK, 0) != (ssize_t)BLK) {
		complain("case1: pwrite zeros: %s", strerror(errno));
		close(fd); unlink(f); return;
	}
	if (fdatasync(fd) != 0 && !Sflag)
		printf("NOTE: %s: case1 fdatasync: %s\n",
		       myname, strerror(errno));

	describe_extents(fd, BLK, "case1 single-zero-block");
	verify_all_zero(fd, BLK, "case1");

	close(fd);
	unlink(f);
}

static void case_blocks_2_and_4(void)
{
	char f[64];
	snprintf(f, sizeof(f), "t_zh.24.%ld", (long)getpid());
	unlink(f);

	int fd = open(f, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) { complain("case2: open: %s", strerror(errno)); return; }

	/* Extend the file to 6 blocks via ftruncate (all hole), then
	 * pwrite zeros into blocks 1 and 3 (zero-indexed).  Blocks
	 * 0, 2, 4, 5 are "real" holes; blocks 1, 3 are explicitly-
	 * written zero data.  Whether the server treats them as
	 * hole, coalesces, or keeps them as data is what we observe. */
	if (ftruncate(fd, (off_t)(BLK * 6)) != 0) {
		complain("case2: ftruncate: %s", strerror(errno));
		close(fd); unlink(f); return;
	}

	unsigned char zeros[BLK] = {0};
	if (pwrite(fd, zeros, BLK, BLK * 1) != (ssize_t)BLK ||
	    pwrite(fd, zeros, BLK, BLK * 3) != (ssize_t)BLK) {
		complain("case2: pwrite: %s", strerror(errno));
		close(fd); unlink(f); return;
	}
	if (fdatasync(fd) != 0 && !Sflag)
		printf("NOTE: %s: case2 fdatasync: %s\n",
		       myname, strerror(errno));

	describe_extents(fd, BLK * 6, "case2 zeros-at-blocks-1-and-3");
	verify_all_zero(fd, BLK * 6, "case2");

	close(fd);
	unlink(f);
}

static void case_data_zero_data(void)
{
	char f[64];
	snprintf(f, sizeof(f), "t_zh.dzd.%ld", (long)getpid());
	unlink(f);

	int fd = open(f, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) { complain("case3: open: %s", strerror(errno)); return; }

	unsigned char data[BLK];
	for (size_t i = 0; i < BLK; i++) data[i] = (unsigned char)(0xA5);
	unsigned char zeros[BLK] = {0};

	if (pwrite(fd, data,  BLK, 0)        != (ssize_t)BLK ||
	    pwrite(fd, zeros, BLK, BLK)      != (ssize_t)BLK ||
	    pwrite(fd, data,  BLK, BLK * 2)  != (ssize_t)BLK) {
		complain("case3: pwrite: %s", strerror(errno));
		close(fd); unlink(f); return;
	}
	if (fdatasync(fd) != 0 && !Sflag)
		printf("NOTE: %s: case3 fdatasync: %s\n",
		       myname, strerror(errno));

	describe_extents(fd, BLK * 3,
			 "case3 data-zeros-data (middle block zeros)");

	/* Data regions must read back as our pattern; middle must be
	 * zero regardless of server choice. */
	unsigned char got[BLK];
	if (pread(fd, got, BLK, 0) != (ssize_t)BLK
	    || memcmp(got, data, BLK) != 0)
		complain("case3: leading data corrupted");
	if (pread(fd, got, BLK, BLK) != (ssize_t)BLK)
		complain("case3: middle read: %s", strerror(errno));
	else
		for (size_t i = 0; i < BLK; i++)
			if (got[i] != 0) {
				complain("case3: middle byte %zu = 0x%02x "
					 "(expected 0)", i,
					 (unsigned)got[i]);
				break;
			}
	if (pread(fd, got, BLK, BLK * 2) != (ssize_t)BLK
	    || memcmp(got, data, BLK) != 0)
		complain("case3: trailing data corrupted");

	close(fd);
	unlink(f);
}

static void case_zero_overwrites_data(void)
{
	char f[64];
	snprintf(f, sizeof(f), "t_zh.ow.%ld", (long)getpid());
	unlink(f);

	int fd = open(f, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) { complain("case4: open: %s", strerror(errno)); return; }

	unsigned char data[BLK];
	for (size_t i = 0; i < BLK; i++) data[i] = (unsigned char)(0x5A);
	if (pwrite(fd, data, BLK, 0) != (ssize_t)BLK) {
		complain("case4: initial pwrite: %s", strerror(errno));
		close(fd); unlink(f); return;
	}
	if (fdatasync(fd) != 0 && !Sflag)
		printf("NOTE: %s: case4 fdatasync (post-data): %s\n",
		       myname, strerror(errno));

	if (!Sflag)
		printf("NOTE: %s: case4 -- extent layout AFTER data write:\n",
		       myname);
	describe_extents(fd, BLK, "case4 pre-overwrite");

	unsigned char zeros[BLK] = {0};
	if (pwrite(fd, zeros, BLK, 0) != (ssize_t)BLK) {
		complain("case4: overwrite pwrite: %s", strerror(errno));
		close(fd); unlink(f); return;
	}
	if (fdatasync(fd) != 0 && !Sflag)
		printf("NOTE: %s: case4 fdatasync (post-zero): %s\n",
		       myname, strerror(errno));

	if (!Sflag)
		printf("NOTE: %s: case4 -- extent layout AFTER zero overwrite:\n",
		       myname);
	describe_extents(fd, BLK, "case4 post-overwrite");

	verify_all_zero(fd, BLK, "case4 post-overwrite read-back");

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
		"server-side hole punching for explicit zero writes");
	cd_or_skip(myname, dir, Nflag);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_single_zero_block", case_single_zero_block());
	RUN_CASE("case_blocks_2_and_4", case_blocks_2_and_4());
	RUN_CASE("case_data_zero_data", case_data_zero_data());
	RUN_CASE("case_zero_overwrites_data",
		 case_zero_overwrites_data());

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}

#endif /* SEEK_HOLE / SEEK_DATA */
