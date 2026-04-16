/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_mmap_msync.c -- exercise mmap + msync coherence on NFS.
 *
 * NFS FAQ: "munmap() doesn't flush dirty pages to NFS; applications
 * must call msync(MS_SYNC) explicitly."  This is the most common
 * source of data loss for mmap-based applications on NFS.
 *
 * Cases:
 *
 *   1. mmap write + msync + read-back.  mmap a file MAP_SHARED,
 *      memcpy a pattern, msync(MS_SYNC), munmap, reopen+pread,
 *      verify pattern.
 *
 *   2. mmap read after pwrite.  pwrite a pattern, mmap MAP_SHARED
 *      read-only, verify the mmap view sees the written data.
 *
 *   3. msync(MS_ASYNC) + close.  Write via mmap, msync(MS_ASYNC),
 *      munmap, close, reopen, verify.  MS_ASYNC does not guarantee
 *      flush — but close on NFS should flush dirty pages.
 *
 *   4. Partial page write.  mmap, write 13 bytes at a non-page-
 *      aligned offset within the page, msync, verify only those
 *      bytes changed.
 *
 *   5. mmap MAP_PRIVATE.  Write via MAP_PRIVATE, msync, verify
 *      the file is NOT modified (MAP_PRIVATE creates a copy-on-
 *      write mapping).
 *
 * Portable: POSIX across Linux / FreeBSD / macOS / Solaris.
 * All cases skip gracefully if mmap is unsupported (e.g., some
 * NFS server configurations disable it).
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "tests.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

int Hflag = 0;
int Sflag = 0;
int Tflag = 0;
int Fflag = 0;
int Nflag = 0;

static const char *myname = "op_mmap_msync";
static long page_size;

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  exercise mmap + msync coherence on NFS\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

static void case_write_msync_read(void)
{
	char name[64];
	int fd = scratch_open("t_mm.wr", name, sizeof(name));

	size_t sz = (size_t)page_size;
	if (ftruncate(fd, (off_t)sz) != 0) {
		complain("case1: ftruncate: %s", strerror(errno));
		close(fd); unlink(name); return;
	}

	void *map = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED) {
		if (errno == ENODEV || errno == EACCES) {
			if (!Sflag)
				printf("NOTE: %s: case1 mmap not supported "
				       "on this mount\n", myname);
			close(fd); unlink(name); return;
		}
		complain("case1: mmap: %s", strerror(errno));
		close(fd); unlink(name); return;
	}

	unsigned char pattern[256];
	fill_pattern(pattern, sizeof(pattern), 1);
	memcpy(map, pattern, sizeof(pattern));

	if (msync(map, sz, MS_SYNC) != 0)
		complain("case1: msync(MS_SYNC): %s", strerror(errno));

	munmap(map, sz);
	close(fd);

	fd = open(name, O_RDONLY);
	if (fd < 0) { complain("case1: reopen: %s", strerror(errno)); unlink(name); return; }

	unsigned char rbuf[256];
	if (pread_all(fd, rbuf, sizeof(rbuf), 0, "case1: pread") == 0) {
		size_t mis = check_pattern(rbuf, sizeof(rbuf), 1);
		if (mis)
			complain("case1: mmap+msync data mismatch at byte %zu "
				 "(msync did not flush to server)", mis - 1);
	}

	close(fd);
	unlink(name);
}

static void case_read_after_pwrite(void)
{
	char name[64];
	int fd = scratch_open("t_mm.rp", name, sizeof(name));

	size_t sz = (size_t)page_size;
	unsigned char wbuf[256];
	fill_pattern(wbuf, sizeof(wbuf), 2);
	if (pwrite_all(fd, wbuf, sizeof(wbuf), 0, "case2: pwrite") != 0) {
		close(fd); unlink(name); return;
	}

	if (ftruncate(fd, (off_t)sz) != 0) {
		complain("case2: ftruncate: %s", strerror(errno));
		close(fd); unlink(name); return;
	}

	void *map = mmap(NULL, sz, PROT_READ, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED) {
		if (errno == ENODEV || errno == EACCES) {
			if (!Sflag)
				printf("NOTE: %s: case2 mmap not supported\n",
				       myname);
			close(fd); unlink(name); return;
		}
		complain("case2: mmap: %s", strerror(errno));
		close(fd); unlink(name); return;
	}

	size_t mis = check_pattern((unsigned char *)map, sizeof(wbuf), 2);
	if (mis)
		complain("case2: mmap read does not see pwrite data at "
			 "byte %zu", mis - 1);

	munmap(map, sz);
	close(fd);
	unlink(name);
}

static void case_async_close(void)
{
	char name[64];
	int fd = scratch_open("t_mm.ac", name, sizeof(name));

	size_t sz = (size_t)page_size;
	if (ftruncate(fd, (off_t)sz) != 0) {
		complain("case3: ftruncate: %s", strerror(errno));
		close(fd); unlink(name); return;
	}

	void *map = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED) {
		if (errno == ENODEV || errno == EACCES) {
			if (!Sflag)
				printf("NOTE: %s: case3 mmap not supported\n",
				       myname);
			close(fd); unlink(name); return;
		}
		complain("case3: mmap: %s", strerror(errno));
		close(fd); unlink(name); return;
	}

	unsigned char pattern[128];
	fill_pattern(pattern, sizeof(pattern), 3);
	memcpy(map, pattern, sizeof(pattern));

	msync(map, sz, MS_ASYNC);
	munmap(map, sz);
	close(fd);

	fd = open(name, O_RDONLY);
	if (fd < 0) { complain("case3: reopen: %s", strerror(errno)); unlink(name); return; }

	unsigned char rbuf[128];
	if (pread_all(fd, rbuf, sizeof(rbuf), 0, "case3: pread") == 0) {
		size_t mis = check_pattern(rbuf, sizeof(rbuf), 3);
		if (mis)
			complain("case3: MS_ASYNC+close data mismatch at "
				 "byte %zu (close did not flush dirty pages "
				 "to NFS server)", mis - 1);
	}

	close(fd);
	unlink(name);
}

static void case_partial_page(void)
{
	char name[64];
	int fd = scratch_open("t_mm.pp", name, sizeof(name));

	size_t sz = (size_t)page_size;
	unsigned char zeros[256];
	memset(zeros, 0, sizeof(zeros));
	if (pwrite_all(fd, zeros, sz < sizeof(zeros) ? sz : sizeof(zeros),
		       0, "case4: zero") != 0) {
		close(fd); unlink(name); return;
	}
	if (ftruncate(fd, (off_t)sz) != 0) {
		complain("case4: ftruncate: %s", strerror(errno));
		close(fd); unlink(name); return;
	}

	void *map = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED) {
		if (errno == ENODEV || errno == EACCES) {
			if (!Sflag)
				printf("NOTE: %s: case4 mmap not supported\n",
				       myname);
			close(fd); unlink(name); return;
		}
		complain("case4: mmap: %s", strerror(errno));
		close(fd); unlink(name); return;
	}

	unsigned char patch[13];
	fill_pattern(patch, sizeof(patch), 4);
	off_t off = 17;
	memcpy((unsigned char *)map + off, patch, sizeof(patch));

	if (msync(map, sz, MS_SYNC) != 0)
		complain("case4: msync: %s", strerror(errno));
	munmap(map, sz);
	close(fd);

	fd = open(name, O_RDONLY);
	if (fd < 0) { complain("case4: reopen: %s", strerror(errno)); unlink(name); return; }

	unsigned char rbuf[13];
	if (pread_all(fd, rbuf, sizeof(rbuf), off, "case4: pread patch") == 0) {
		if (memcmp(rbuf, patch, sizeof(patch)) != 0)
			complain("case4: partial page write not persisted");
	}

	/* Verify bytes before the patch are still zero. */
	unsigned char pre[17];
	if (pread_all(fd, pre, sizeof(pre), 0, "case4: pread pre") == 0) {
		if (!all_zero(pre, sizeof(pre)))
			complain("case4: bytes before patch corrupted");
	}

	close(fd);
	unlink(name);
}

static void case_map_private(void)
{
	char name[64];
	int fd = scratch_open("t_mm.mp", name, sizeof(name));

	size_t sz = (size_t)page_size;
	unsigned char orig[64];
	fill_pattern(orig, sizeof(orig), 50);
	if (pwrite_all(fd, orig, sizeof(orig), 0, "case5: write") != 0) {
		close(fd); unlink(name); return;
	}
	if (ftruncate(fd, (off_t)sz) != 0) {
		complain("case5: ftruncate: %s", strerror(errno));
		close(fd); unlink(name); return;
	}

	void *map = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (map == MAP_FAILED) {
		if (errno == ENODEV || errno == EACCES) {
			if (!Sflag)
				printf("NOTE: %s: case5 mmap not supported\n",
				       myname);
			close(fd); unlink(name); return;
		}
		complain("case5: mmap(MAP_PRIVATE): %s", strerror(errno));
		close(fd); unlink(name); return;
	}

	memset(map, 'X', sizeof(orig));
	msync(map, sz, MS_SYNC);
	munmap(map, sz);
	close(fd);

	fd = open(name, O_RDONLY);
	if (fd < 0) { complain("case5: reopen: %s", strerror(errno)); unlink(name); return; }

	unsigned char rbuf[64];
	if (pread_all(fd, rbuf, sizeof(rbuf), 0, "case5: pread") == 0) {
		size_t mis = check_pattern(rbuf, sizeof(rbuf), 50);
		if (mis)
			complain("case5: MAP_PRIVATE write leaked to file "
				 "at byte %zu (MAP_PRIVATE must be "
				 "copy-on-write)", mis - 1);
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

	page_size = sysconf(_SC_PAGESIZE);
	if (page_size <= 0) page_size = 4096;

	prelude(myname, "mmap + msync coherence on NFS");
	cd_or_skip(myname, dir, Nflag);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_write_msync_read", case_write_msync_read());
	RUN_CASE("case_read_after_pwrite", case_read_after_pwrite());
	RUN_CASE("case_async_close", case_async_close());
	RUN_CASE("case_partial_page", case_partial_page());
	RUN_CASE("case_map_private", case_map_private());

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}
