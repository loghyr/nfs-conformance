/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_io_advise.c -- exercise posix_fadvise(2), which NFSv4.2 servers
 * translate into IO_ADVISE (RFC 7862 S5).
 *
 * posix_fadvise is a hint: no observable data motion is guaranteed.
 * This test only verifies the syscall accepts every advice value and
 * returns 0 on every legal range.
 *
 * Cases:
 *   1. Each POSIX_FADV_* (NORMAL/RANDOM/SEQUENTIAL/WILLNEED/
 *      DONTNEED/NOREUSE) on a full file returns 0.
 *   2. Zero-length range returns 0 (POSIX says no-op, not error).
 *   3. Range beyond EOF returns 0.
 *   4. Invalid advice returns 0 or EINVAL (Linux returns EINVAL;
 *      some BSDs historically returned 0).
 *
 * macOS lacks posix_fadvise; stub out.
 */

#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700

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

static const char *myname = "op_io_advise";

#if defined(__APPLE__)
int main(void)
{
	skip("%s: posix_fadvise(2) not available on macOS (macOS uses "
	     "fcntl(F_RDADVISE) with different semantics)",
	     myname);
	return TEST_SKIP;
}
#else

#define FILE_LEN (1 * 1024 * 1024)

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  exercise posix_fadvise -> NFSv4.2 IO_ADVISE\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

static void one_advice(int fd, off_t off, off_t len, int advice,
		       const char *name)
{
	int rc = posix_fadvise(fd, off, len, advice);
	if (rc != 0)
		complain("posix_fadvise(%s, off=%lld, len=%lld): %s",
			 name, (long long)off, (long long)len,
			 strerror(rc));
}

/* Shared scratch fd for all cases. */
static int adv_fd = -1;

static void case_all_advices(void)
{
	struct {
		int advice;
		const char *name;
	} pool[] = {
		{ POSIX_FADV_NORMAL,     "NORMAL" },
		{ POSIX_FADV_RANDOM,     "RANDOM" },
		{ POSIX_FADV_SEQUENTIAL, "SEQUENTIAL" },
		{ POSIX_FADV_WILLNEED,   "WILLNEED" },
		{ POSIX_FADV_DONTNEED,   "DONTNEED" },
		{ POSIX_FADV_NOREUSE,    "NOREUSE" },
	};
	for (size_t i = 0; i < sizeof(pool) / sizeof(pool[0]); i++)
		one_advice(adv_fd, 0, FILE_LEN, pool[i].advice, pool[i].name);
}

static void case_zero_length_range(void)
{
	one_advice(adv_fd, 0, 0, POSIX_FADV_WILLNEED, "WILLNEED,len=0");
}

static void case_range_beyond_eof(void)
{
	one_advice(adv_fd, FILE_LEN * 2, FILE_LEN, POSIX_FADV_WILLNEED,
		   "WILLNEED,beyond-EOF");
}

static void case_invalid_advice(void)
{
	int rc = posix_fadvise(adv_fd, 0, FILE_LEN, 999 /* bogus */);
	if (rc != 0 && rc != EINVAL)
		complain("case4: invalid advice: expected 0 or EINVAL, got %s",
			 strerror(rc));
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

	prelude(myname, "posix_fadvise -> NFSv4.2 IO_ADVISE (RFC 7862 S5)");
	cd_or_skip(myname, dir, Nflag);

	char name[64];
	adv_fd = scratch_open("t11", name, sizeof(name));
	if (ftruncate(adv_fd, FILE_LEN) != 0)
		bail("ftruncate: %s", strerror(errno));

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_all_advices",       case_all_advices());
	RUN_CASE("case_zero_length_range", case_zero_length_range());
	RUN_CASE("case_range_beyond_eof",  case_range_beyond_eof());
	RUN_CASE("case_invalid_advice",    case_invalid_advice());

	close(adv_fd);
	unlink(name);

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}

#endif /* __APPLE__ */
