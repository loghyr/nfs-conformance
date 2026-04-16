/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_open_downgrade.c -- exercise NFSv4 OPEN_DOWNGRADE (RFC 7530
 * S18.18) via the POSIX open/dup/close surface.
 *
 * OPEN_DOWNGRADE reduces the access/deny mode on an open file.
 * The Linux NFS client issues it when the last fd with a particular
 * access mode is closed while other fds to the same file remain
 * open with a narrower mode.
 *
 * Cases:
 *
 *   1. Open RW, dup, close original.  Open O_RDWR, dup() the fd,
 *      close the original fd.  The dup'd fd must still be readable
 *      and writable.  (No downgrade occurs — both fds share the
 *      same open file description.)
 *
 *   2. Open RW + open RO, close RW.  Open the same file O_RDWR and
 *      O_RDONLY.  Close the O_RDWR fd.  The O_RDONLY fd must still
 *      be readable.  Triggers OPEN_DOWNGRADE (access reduced from
 *      READ|WRITE to READ).
 *
 *   3. Open RW + open WO, close WO.  Open O_RDWR and O_WRONLY.
 *      Close O_WRONLY.  The O_RDWR fd must still be readable and
 *      writable.  (No effective downgrade — O_RDWR still covers
 *      both.)
 *
 *   4. Open RO, write attempt.  Open O_RDONLY, attempt write — must
 *      fail with EBADF.  Baseline: the server does not grant write
 *      access when only O_RDONLY is open.
 *
 *   5. Open RW, close, reopen RO.  Open O_RDWR, write, close.
 *      Reopen O_RDONLY, attempt write — must fail with EBADF.
 *      The close released the OPEN state entirely; the reopen
 *      with O_RDONLY should get READ-only access.
 *
 *   6. Multiple readers.  Open O_RDONLY three times, close one,
 *      verify the other two still read successfully.  Each close
 *      decrements the open-share count; the server should not
 *      revoke access until all fds are closed.
 *
 * Portable: POSIX across Linux / FreeBSD / macOS / Solaris.
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

static const char *myname = "op_open_downgrade";

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  exercise open/close combinations -> NFSv4 OPEN_DOWNGRADE "
		"(RFC 7530 S18.18)\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

static int make_file(const char *tag, char *out, size_t outsz)
{
	snprintf(out, outsz, "t_od.%s.%ld", tag, (long)getpid());
	unlink(out);
	int fd = open(out, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("%s: open(%s): %s", tag, out, strerror(errno));
		return -1;
	}
	unsigned char buf[256];
	fill_pattern(buf, sizeof(buf), 42);
	if (pwrite_all(fd, buf, sizeof(buf), 0, tag) != 0) {
		close(fd);
		unlink(out);
		return -1;
	}
	close(fd);
	return 0;
}

static void case_dup_close_original(void)
{
	char name[64];
	if (make_file("dc", name, sizeof(name)) != 0) return;

	int fd = open(name, O_RDWR);
	if (fd < 0) {
		complain("case1: open(RW): %s", strerror(errno));
		unlink(name);
		return;
	}

	int fd2 = dup(fd);
	if (fd2 < 0) {
		complain("case1: dup: %s", strerror(errno));
		close(fd);
		unlink(name);
		return;
	}
	close(fd);

	unsigned char buf[64];
	if (pread_all(fd2, buf, sizeof(buf), 0, "case1: read via dup") != 0)
		goto out;
	size_t mis = check_pattern(buf, sizeof(buf), 42);
	if (mis)
		complain("case1: data mismatch at byte %zu via dup'd fd",
			 mis - 1);

	memset(buf, 'W', sizeof(buf));
	if (write(fd2, buf, sizeof(buf)) < 0)
		complain("case1: write via dup'd fd: %s", strerror(errno));

out:
	close(fd2);
	unlink(name);
}

static void case_rw_plus_ro_close_rw(void)
{
	char name[64];
	if (make_file("rr", name, sizeof(name)) != 0) return;

	int rw = open(name, O_RDWR);
	int ro = open(name, O_RDONLY);
	if (rw < 0 || ro < 0) {
		complain("case2: open: %s", strerror(errno));
		if (rw >= 0) close(rw);
		if (ro >= 0) close(ro);
		unlink(name);
		return;
	}

	close(rw);

	unsigned char buf[64];
	if (pread_all(ro, buf, sizeof(buf), 0, "case2: read after RW close") != 0)
		goto out;
	size_t mis = check_pattern(buf, sizeof(buf), 42);
	if (mis)
		complain("case2: data mismatch at byte %zu after RW fd "
			 "closed", mis - 1);

out:
	close(ro);
	unlink(name);
}

static void case_rw_plus_wo_close_wo(void)
{
	char name[64];
	if (make_file("rw", name, sizeof(name)) != 0) return;

	int rw = open(name, O_RDWR);
	int wo = open(name, O_WRONLY);
	if (rw < 0 || wo < 0) {
		complain("case3: open: %s", strerror(errno));
		if (rw >= 0) close(rw);
		if (wo >= 0) close(wo);
		unlink(name);
		return;
	}

	close(wo);

	unsigned char buf[64];
	if (pread_all(rw, buf, sizeof(buf), 0, "case3: read RW after WO close") != 0)
		goto out;
	size_t mis = check_pattern(buf, sizeof(buf), 42);
	if (mis)
		complain("case3: data mismatch at byte %zu", mis - 1);

	memset(buf, 'X', sizeof(buf));
	if (write(rw, buf, sizeof(buf)) < 0)
		complain("case3: write RW after WO close: %s",
			 strerror(errno));

out:
	close(rw);
	unlink(name);
}

static void case_ro_write_rejected(void)
{
	char name[64];
	if (make_file("wr", name, sizeof(name)) != 0) return;

	int ro = open(name, O_RDONLY);
	if (ro < 0) {
		complain("case4: open(RO): %s", strerror(errno));
		unlink(name);
		return;
	}

	char buf[4] = "bad";
	errno = 0;
	ssize_t w = write(ro, buf, sizeof(buf));
	if (w >= 0)
		complain("case4: write on O_RDONLY fd succeeded (%zd bytes)",
			 w);
	else if (errno != EBADF)
		complain("case4: expected EBADF, got %s", strerror(errno));

	close(ro);
	unlink(name);
}

static void case_close_reopen_ro(void)
{
	char name[64];
	if (make_file("cr", name, sizeof(name)) != 0) return;

	int fd = open(name, O_RDWR);
	if (fd < 0) {
		complain("case5: open(RW): %s", strerror(errno));
		unlink(name);
		return;
	}
	char buf[16] = "hello";
	(void)write(fd, buf, sizeof(buf));
	close(fd);

	int ro = open(name, O_RDONLY);
	if (ro < 0) {
		complain("case5: reopen(RO): %s", strerror(errno));
		unlink(name);
		return;
	}

	errno = 0;
	ssize_t w = write(ro, buf, sizeof(buf));
	if (w >= 0)
		complain("case5: write on RO-reopened fd succeeded");
	else if (errno != EBADF)
		complain("case5: expected EBADF, got %s", strerror(errno));

	close(ro);
	unlink(name);
}

static void case_multiple_readers(void)
{
	char name[64];
	if (make_file("mr", name, sizeof(name)) != 0) return;

	int fd1 = open(name, O_RDONLY);
	int fd2 = open(name, O_RDONLY);
	int fd3 = open(name, O_RDONLY);
	if (fd1 < 0 || fd2 < 0 || fd3 < 0) {
		complain("case6: open: %s", strerror(errno));
		if (fd1 >= 0) close(fd1);
		if (fd2 >= 0) close(fd2);
		if (fd3 >= 0) close(fd3);
		unlink(name);
		return;
	}

	close(fd1);

	unsigned char buf[64];
	if (pread_all(fd2, buf, sizeof(buf), 0, "case6: read fd2") == 0) {
		size_t mis = check_pattern(buf, sizeof(buf), 42);
		if (mis)
			complain("case6: fd2 mismatch at byte %zu", mis - 1);
	}
	if (pread_all(fd3, buf, sizeof(buf), 0, "case6: read fd3") == 0) {
		size_t mis = check_pattern(buf, sizeof(buf), 42);
		if (mis)
			complain("case6: fd3 mismatch at byte %zu", mis - 1);
	}

	close(fd2);
	close(fd3);
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
		"open/close combinations -> NFSv4 OPEN_DOWNGRADE "
		"(RFC 7530 S18.18)");
	cd_or_skip(myname, dir, Nflag);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_dup_close_original", case_dup_close_original());
	RUN_CASE("case_rw_plus_ro_close_rw", case_rw_plus_ro_close_rw());
	RUN_CASE("case_rw_plus_wo_close_wo", case_rw_plus_wo_close_wo());
	RUN_CASE("case_ro_write_rejected", case_ro_write_rejected());
	RUN_CASE("case_close_reopen_ro", case_close_reopen_ro());
	RUN_CASE("case_multiple_readers", case_multiple_readers());

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}
