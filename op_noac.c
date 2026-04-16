/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_noac.c -- exercise attribute-cache-disabled semantics (mount -o noac).
 *
 * When the NFS client is mounted with -o noac, it must not cache file
 * attributes.  Every stat() should fetch fresh attributes from the
 * server.  This is the strongest consistency mode short of -o lookupcache=none.
 *
 * This test auto-detects the noac mount option via /proc/self/mountinfo.
 * If noac is not present, the test skips (unless -f forces it).
 *
 * Cases:
 *
 *   1. Stat sees write immediately.  Write 1234 bytes, stat, verify
 *      size == 1234 without closing.  Under noac, the client must
 *      not return a cached zero-size.
 *
 *   2. Stat sees chmod immediately.  fchmod to 0600, stat by name
 *      without closing.  Under noac, mode must be 0600.
 *
 *   3. Stat sees ftruncate immediately.  Write 4096 bytes, ftruncate
 *      to 100, stat by name.  Under noac, size must be 100.
 *
 *   4. Rapid stat consistency.  Write in a loop (10 iterations),
 *      stat after each write.  Under noac, every stat must see the
 *      cumulative size.
 *
 * Portable: Linux (mount option detection).  Test logic is POSIX.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

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

static const char *myname = "op_noac";

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  exercise noac mount option (no attribute caching)\n"
		"  -h help  -s silent  -t timing  -f force (skip mount check)\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

static void case_write_stat_size(void)
{
	char name[64];
	snprintf(name, sizeof(name), "t_noac.ws.%ld", (long)getpid());
	unlink(name);

	int fd = open(name, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) { complain("case1: open: %s", strerror(errno)); return; }

	char buf[1234];
	memset(buf, 'W', sizeof(buf));
	ssize_t w = write(fd, buf, sizeof(buf));
	if (w != (ssize_t)sizeof(buf)) {
		complain("case1: write: %s", w < 0 ? strerror(errno) : "short");
		close(fd); unlink(name); return;
	}

	struct stat st;
	if (stat(name, &st) != 0) {
		complain("case1: stat: %s", strerror(errno));
		close(fd); unlink(name); return;
	}

	if (st.st_size != (off_t)sizeof(buf))
		complain("case1: stat size %lld, expected %zu (attribute "
			 "cache returned stale size despite noac)",
			 (long long)st.st_size, sizeof(buf));

	close(fd);
	unlink(name);
}

static void case_chmod_stat(void)
{
	char name[64];
	snprintf(name, sizeof(name), "t_noac.cm.%ld", (long)getpid());
	unlink(name);

	int fd = open(name, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) { complain("case2: open: %s", strerror(errno)); return; }

	if (fchmod(fd, 0600) != 0) {
		complain("case2: fchmod: %s", strerror(errno));
		close(fd); unlink(name); return;
	}

	struct stat st;
	if (stat(name, &st) != 0) {
		complain("case2: stat: %s", strerror(errno));
		close(fd); unlink(name); return;
	}

	if ((st.st_mode & 07777) != 0600)
		complain("case2: mode 0%o, expected 0600 (stale cached mode "
			 "despite noac)", st.st_mode & 07777);

	close(fd);
	unlink(name);
}

static void case_ftruncate_stat(void)
{
	char name[64];
	snprintf(name, sizeof(name), "t_noac.ft.%ld", (long)getpid());
	unlink(name);

	int fd = open(name, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) { complain("case3: open: %s", strerror(errno)); return; }

	char buf[4096];
	memset(buf, 'T', sizeof(buf));
	(void)write(fd, buf, sizeof(buf));

	if (ftruncate(fd, 100) != 0) {
		complain("case3: ftruncate: %s", strerror(errno));
		close(fd); unlink(name); return;
	}

	struct stat st;
	if (stat(name, &st) != 0) {
		complain("case3: stat: %s", strerror(errno));
		close(fd); unlink(name); return;
	}

	if (st.st_size != 100)
		complain("case3: size %lld, expected 100 (stale size "
			 "after ftruncate despite noac)",
			 (long long)st.st_size);

	close(fd);
	unlink(name);
}

static void case_rapid_stat(void)
{
	char name[64];
	snprintf(name, sizeof(name), "t_noac.rs.%ld", (long)getpid());
	unlink(name);

	int fd = open(name, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) { complain("case4: open: %s", strerror(errno)); return; }

	char buf[100];
	memset(buf, 'R', sizeof(buf));

	for (int i = 1; i <= 10; i++) {
		ssize_t w = write(fd, buf, sizeof(buf));
		if (w != (ssize_t)sizeof(buf)) {
			complain("case4: write %d: %s", i,
				 w < 0 ? strerror(errno) : "short");
			break;
		}

		struct stat st;
		if (stat(name, &st) != 0) {
			complain("case4: stat %d: %s", i, strerror(errno));
			break;
		}

		off_t expected = (off_t)i * sizeof(buf);
		if (st.st_size != expected) {
			complain("case4: iteration %d: size %lld, expected "
				 "%lld (attribute cache stale despite noac)",
				 i, (long long)st.st_size,
				 (long long)expected);
			break;
		}
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

	prelude(myname, "noac mount option (no attribute caching)");
	cd_or_skip(myname, dir, Nflag);

	if (!Fflag) {
		int rc = mount_has_option("noac");
		if (rc == 0)
			skip("%s: mount does not have noac; mount with "
			     "-o noac to run this test (or -f to force)",
			     myname);
		if (rc == -1 && !Sflag)
			printf("NOTE: %s: cannot detect mount options on "
			       "this platform; running anyway\n", myname);
	}

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_write_stat_size", case_write_stat_size());
	RUN_CASE("case_chmod_stat", case_chmod_stat());
	RUN_CASE("case_ftruncate_stat", case_ftruncate_stat());
	RUN_CASE("case_rapid_stat", case_rapid_stat());

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}
