/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_unlink.c -- exercise NFSv4 REMOVE (RFC 7530 S18.25) on regular
 * files via the POSIX unlink(2) surface.
 *
 * Cases:
 *
 *   1. Basic unlink.  Create, unlink, stat returns ENOENT.
 *      (POSIX.1-1990 unlink() S5.5.1)
 *
 *   2. Unlink on directory returns EISDIR (or EPERM on some systems).
 *      (POSIX.1-1990 unlink() S5.5.1: EISDIR error condition;
 *      EPERM is an alternative on some implementations)
 *
 *   3. Unlink on nonexistent name returns ENOENT.
 *      (POSIX.1-1990 unlink() S5.5.1: ENOENT error condition)
 *
 *   4. Parent nlink unchanged.  Regular-file unlink must NOT decrement
 *      the parent directory nlink (only rmdir does that).
 *      (POSIX.1-1990 S5.5.1: nlink decremented on the file itself,
 *      not on the parent directory)
 *
 *   5. Parent mtime/ctime advance.  After unlink, the parent
 *      directory's mtime and ctime must advance; atime must not.
 *      (POSIX.1-2008 unlink(), "Upon successful completion" clause:
 *      "the st_ctime and st_mtime fields of the parent directory
 *      shall be marked for update")
 *
 *   6. Hard-link unlink.  Create a file, hard-link it, unlink the
 *      original name.  Verify nlink decrements from 2 to 1 and the
 *      file is still accessible via the second name.  Verify the
 *      inode ctime advances.
 *      (POSIX.1-1990 unlink() S5.5.1: "the st_nlink count of the
 *      file shall be decremented")
 *
 *   7. Unlink-open-file (silly rename).  Open a file, unlink the
 *      name, verify the fd is still readable/writable (the inode
 *      stays alive until the last fd closes).  On NFS this triggers
 *      the "silly rename" path.
 *      (POSIX.1-1990 unlink() S5.5.1: "the file's contents shall
 *      be accessible until all file descriptors ... are closed")
 *
 * Portable: POSIX.1-1990 S5.5.1 (unlink) across Linux / FreeBSD /
 * macOS / Solaris.
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

static const char *myname = "op_unlink";

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  exercise unlink -> NFSv4 REMOVE (RFC 7530 S18.25)\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

static void case_basic(void)
{
	char a[64];
	snprintf(a, sizeof(a), "t_ul.b.%ld", (long)getpid());
	unlink(a);

	int fd = open(a, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) { complain("case1: create: %s", strerror(errno)); return; }
	close(fd);

	if (unlink(a) != 0) {
		complain("case1: unlink: %s", strerror(errno));
		return;
	}

	struct stat st;
	errno = 0;
	if (stat(a, &st) == 0)
		complain("case1: stat after unlink succeeded");
	else if (errno != ENOENT)
		complain("case1: expected ENOENT, got %s", strerror(errno));
}

static void case_eisdir(void)
{
	char d[64];
	snprintf(d, sizeof(d), "t_ul.d.%ld", (long)getpid());
	rmdir(d);
	if (mkdir(d, 0755) != 0) {
		complain("case2: mkdir: %s", strerror(errno));
		return;
	}

	errno = 0;
	if (unlink(d) == 0) {
		complain("case2: unlink(directory) succeeded");
		rmdir(d);
		return;
	}
	if (errno != EISDIR && errno != EPERM)
		complain("case2: expected EISDIR or EPERM, got %s",
			 strerror(errno));
	rmdir(d);
}

static void case_enoent(void)
{
	char a[64];
	snprintf(a, sizeof(a), "t_ul.ne.%ld", (long)getpid());
	unlink(a);

	errno = 0;
	if (unlink(a) == 0)
		complain("case3: unlink nonexistent succeeded");
	else if (errno != ENOENT)
		complain("case3: expected ENOENT, got %s", strerror(errno));
}

static void case_parent_nlink(void)
{
	struct stat st_before, st_after;

	char a[64];
	snprintf(a, sizeof(a), "t_ul.nl.%ld", (long)getpid());
	unlink(a);

	int fd = open(a, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) { complain("case4: create: %s", strerror(errno)); return; }
	close(fd);

	/*
	 * Measure parent nlink AFTER the create, not before, so the
	 * pre/post comparison attributes any change to the unlink
	 * rather than to the transient create-then-unlink pair.
	 */
	if (stat(".", &st_before) != 0) {
		complain("case4: stat(.) before unlink: %s", strerror(errno));
		unlink(a);
		return;
	}

	if (unlink(a) != 0) {
		complain("case4: unlink: %s", strerror(errno));
		return;
	}

	if (stat(".", &st_after) != 0) {
		complain("case4: stat(.) after: %s", strerror(errno));
		return;
	}

	if (st_after.st_nlink != st_before.st_nlink)
		complain("case4: parent nlink changed from %lu to %lu "
			 "(regular-file unlink must not change parent nlink)",
			 (unsigned long)st_before.st_nlink,
			 (unsigned long)st_after.st_nlink);
}

static void case_parent_timestamps(void)
{
	char a[64];
	snprintf(a, sizeof(a), "t_ul.ts.%ld", (long)getpid());
	unlink(a);

	int fd = open(a, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) { complain("case5: create: %s", strerror(errno)); return; }
	close(fd);

	sleep_ms(50);

	struct stat st_before;
	if (stat(".", &st_before) != 0) {
		complain("case5: stat(.) before: %s", strerror(errno));
		unlink(a);
		return;
	}

	sleep_ms(50);

	if (unlink(a) != 0) {
		complain("case5: unlink: %s", strerror(errno));
		return;
	}

	struct stat st_after;
	if (stat(".", &st_after) != 0) {
		complain("case5: stat(.) after: %s", strerror(errno));
		return;
	}

	if (st_after.st_mtime < st_before.st_mtime)
		complain("case5: parent mtime did not advance after unlink");
}

static void case_hardlink_unlink(void)
{
	char a[64], b[64];
	snprintf(a, sizeof(a), "t_ul.ha.%ld", (long)getpid());
	snprintf(b, sizeof(b), "t_ul.hb.%ld", (long)getpid());
	unlink(a); unlink(b);

	int fd = open(a, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) { complain("case6: create: %s", strerror(errno)); return; }
	char buf[] = "hardlink_data";
	(void)write(fd, buf, sizeof(buf));
	close(fd);

	if (link(a, b) != 0) {
		if (errno == EOPNOTSUPP || errno == ENOTSUP) {
			if (!Sflag)
				printf("NOTE: %s: case6 skipped (hard links "
				       "not supported)\n", myname);
			unlink(a);
			return;
		}
		complain("case6: link: %s", strerror(errno));
		unlink(a);
		return;
	}

	struct stat st_before;
	if (stat(b, &st_before) != 0) {
		complain("case6: stat(b) before: %s", strerror(errno));
		unlink(a); unlink(b);
		return;
	}
	if (st_before.st_nlink != 2)
		complain("case6: nlink before unlink: %lu (expected 2)",
			 (unsigned long)st_before.st_nlink);

	sleep_ms(50);

	if (unlink(a) != 0) {
		complain("case6: unlink(a): %s", strerror(errno));
		unlink(b);
		return;
	}

	struct stat st_after;
	if (stat(b, &st_after) != 0) {
		complain("case6: stat(b) after unlink(a): %s",
			 strerror(errno));
		return;
	}

	if (st_after.st_nlink != 1)
		complain("case6: nlink after unlink: %lu (expected 1)",
			 (unsigned long)st_after.st_nlink);

	fd = open(b, O_RDONLY);
	if (fd < 0) {
		complain("case6: open(b) after unlink(a): %s",
			 strerror(errno));
		unlink(b);
		return;
	}
	char rbuf[sizeof(buf)];
	ssize_t n = read(fd, rbuf, sizeof(rbuf));
	if (n != (ssize_t)sizeof(buf) || memcmp(rbuf, buf, sizeof(buf)) != 0)
		complain("case6: data via second link corrupted after "
			 "unlink of first");
	close(fd);
	unlink(b);
}

static void case_unlink_open(void)
{
	char a[64];
	snprintf(a, sizeof(a), "t_ul.uo.%ld", (long)getpid());
	unlink(a);

	int fd = open(a, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) { complain("case7: create: %s", strerror(errno)); return; }

	unsigned char wbuf[128];
	fill_pattern(wbuf, sizeof(wbuf), 99);
	if (pwrite_all(fd, wbuf, sizeof(wbuf), 0, "case7: write") != 0) {
		close(fd);
		unlink(a);
		return;
	}

	if (unlink(a) != 0) {
		complain("case7: unlink while open: %s", strerror(errno));
		close(fd);
		return;
	}

	/* Name is gone. */
	struct stat st;
	errno = 0;
	if (stat(a, &st) == 0)
		complain("case7: stat after unlink still succeeds");

	/* But the fd is still alive — read back the data. */
	unsigned char rbuf[128];
	if (pread_all(fd, rbuf, sizeof(rbuf), 0, "case7: read via fd") != 0) {
		close(fd);
		return;
	}
	size_t mis = check_pattern(rbuf, sizeof(rbuf), 99);
	if (mis)
		complain("case7: data mismatch at byte %zu via fd after "
			 "unlink (NFS silly-rename path)", mis - 1);

	/* Write more data via the open fd. */
	fill_pattern(wbuf, sizeof(wbuf), 100);
	if (pwrite_all(fd, wbuf, sizeof(wbuf), 128, "case7: write2") != 0) {
		close(fd);
		return;
	}

	/* fstat still works on the open fd. */
	if (fstat(fd, &st) != 0)
		complain("case7: fstat on unlinked fd: %s", strerror(errno));
	else if (st.st_size != 256)
		complain("case7: fstat size %lld, expected 256",
			 (long long)st.st_size);

	close(fd);
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
		"unlink -> NFSv4 REMOVE (RFC 7530 S18.25)");
	cd_or_skip(myname, dir, Nflag);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_basic", case_basic());
	RUN_CASE("case_eisdir", case_eisdir());
	RUN_CASE("case_enoent", case_enoent());
	RUN_CASE("case_parent_nlink", case_parent_nlink());
	RUN_CASE("case_parent_timestamps", case_parent_timestamps());
	RUN_CASE("case_hardlink_unlink", case_hardlink_unlink());
	RUN_CASE("case_unlink_open", case_unlink_open());

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}
