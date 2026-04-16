/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_close_to_open.c -- exercise NFS close-to-open cache consistency.
 *
 * Close-to-open (CTO) is the NFS consistency guarantee: when a
 * process closes a file, all modified data and metadata are flushed
 * to the server.  When another process (or the same process) opens
 * the file, the client fetches fresh attributes from the server and
 * invalidates any cached data whose change_attr/mtime has advanced.
 *
 * CTO is NOT strict coherence — concurrent readers and writers on
 * separate clients may see stale data.  But within a single client,
 * close-then-open must see the latest state.
 *
 * Cases:
 *
 *   1. Write + close + reopen + read (same process).  Write a
 *      pattern, close, reopen O_RDONLY, verify the data.
 *
 *   2. Write + close + stat (size).  Write N bytes, close.  stat()
 *      must return the new size immediately — no stale cached size.
 *
 *   3. Overwrite + close + reopen.  Write pattern A, close.  Reopen,
 *      write pattern B, close.  Reopen, verify pattern B.
 *
 *   4. Fork: child writes, parent reads after child exit.  Fork,
 *      child opens O_WRONLY, writes, closes, exits.  Parent waits
 *      for child, opens O_RDONLY, reads — must see child's data.
 *      This is the CTO contract between processes.
 *
 *   5. Metadata CTO: chmod + close + stat.  Open, chmod to 0600,
 *      close.  stat() must see 0600, not a cached mode.
 *
 *   6. Truncate + close + stat.  Open, ftruncate to 0, close.
 *      stat() must see size 0 immediately.
 *
 * Portable: POSIX across Linux / FreeBSD / macOS / Solaris.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "tests.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

int Hflag = 0;
int Sflag = 0;
int Tflag = 0;
int Fflag = 0;
int Nflag = 0;

static const char *myname = "op_close_to_open";

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  exercise NFS close-to-open cache consistency\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

static void case_write_close_read(void)
{
	char name[64];
	snprintf(name, sizeof(name), "t_cto.wcr.%ld", (long)getpid());
	unlink(name);

	int fd = open(name, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) { complain("case1: create: %s", strerror(errno)); return; }

	unsigned char wbuf[512];
	fill_pattern(wbuf, sizeof(wbuf), 1);
	if (pwrite_all(fd, wbuf, sizeof(wbuf), 0, "case1: write") != 0) {
		close(fd); unlink(name); return;
	}
	close(fd);

	fd = open(name, O_RDONLY);
	if (fd < 0) { complain("case1: reopen: %s", strerror(errno)); unlink(name); return; }

	unsigned char rbuf[512];
	if (pread_all(fd, rbuf, sizeof(rbuf), 0, "case1: read") == 0) {
		size_t mis = check_pattern(rbuf, sizeof(rbuf), 1);
		if (mis)
			complain("case1: CTO violation at byte %zu "
				 "(read after close did not see written data)",
				 mis - 1);
	}
	close(fd);
	unlink(name);
}

static void case_close_stat_size(void)
{
	char name[64];
	snprintf(name, sizeof(name), "t_cto.css.%ld", (long)getpid());
	unlink(name);

	int fd = open(name, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) { complain("case2: create: %s", strerror(errno)); return; }

	char buf[1234];
	memset(buf, 'S', sizeof(buf));
	ssize_t w = write(fd, buf, sizeof(buf));
	if (w != (ssize_t)sizeof(buf)) {
		complain("case2: write: %s", w < 0 ? strerror(errno) : "short");
		close(fd); unlink(name); return;
	}
	close(fd);

	struct stat st;
	if (stat(name, &st) != 0) {
		complain("case2: stat: %s", strerror(errno));
		unlink(name); return;
	}
	if (st.st_size != (off_t)sizeof(buf))
		complain("case2: stat size %lld after close, expected %zu "
			 "(stale cached size)", (long long)st.st_size,
			 sizeof(buf));
	unlink(name);
}

static void case_overwrite(void)
{
	char name[64];
	snprintf(name, sizeof(name), "t_cto.ow.%ld", (long)getpid());
	unlink(name);

	/* Write pattern A. */
	int fd = open(name, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) { complain("case3: create: %s", strerror(errno)); return; }
	unsigned char a[256];
	fill_pattern(a, sizeof(a), 10);
	pwrite_all(fd, a, sizeof(a), 0, "case3: write A");
	close(fd);

	/* Overwrite with pattern B. */
	fd = open(name, O_WRONLY | O_TRUNC);
	if (fd < 0) { complain("case3: reopen: %s", strerror(errno)); unlink(name); return; }
	unsigned char b[256];
	fill_pattern(b, sizeof(b), 20);
	pwrite_all(fd, b, sizeof(b), 0, "case3: write B");
	close(fd);

	/* Read back — must see B, not A. */
	fd = open(name, O_RDONLY);
	if (fd < 0) { complain("case3: read open: %s", strerror(errno)); unlink(name); return; }
	unsigned char rbuf[256];
	if (pread_all(fd, rbuf, sizeof(rbuf), 0, "case3: read") == 0) {
		size_t mis = check_pattern(rbuf, sizeof(rbuf), 20);
		if (mis)
			complain("case3: CTO violation at byte %zu "
				 "(read sees pattern A, not B)", mis - 1);
	}
	close(fd);
	unlink(name);
}

static void case_fork_child_writes(void)
{
	char name[64];
	snprintf(name, sizeof(name), "t_cto.fc.%ld", (long)getpid());
	unlink(name);

	/* Create empty file. */
	int fd = open(name, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) { complain("case4: create: %s", strerror(errno)); return; }
	close(fd);

	pid_t pid = fork();
	if (pid < 0) {
		complain("case4: fork: %s", strerror(errno));
		unlink(name); return;
	}

	if (pid == 0) {
		int cfd = open(name, O_WRONLY);
		if (cfd < 0) _exit(1);
		unsigned char wbuf[256];
		fill_pattern(wbuf, sizeof(wbuf), 30);
		if (pwrite(cfd, wbuf, sizeof(wbuf), 0) != (ssize_t)sizeof(wbuf))
			_exit(1);
		close(cfd);
		_exit(0);
	}

	int status;
	waitpid(pid, &status, 0);
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		complain("case4: child failed");
		unlink(name); return;
	}

	fd = open(name, O_RDONLY);
	if (fd < 0) {
		complain("case4: parent open: %s", strerror(errno));
		unlink(name); return;
	}

	unsigned char rbuf[256];
	if (pread_all(fd, rbuf, sizeof(rbuf), 0, "case4: parent read") == 0) {
		size_t mis = check_pattern(rbuf, sizeof(rbuf), 30);
		if (mis)
			complain("case4: CTO violation at byte %zu "
				 "(parent did not see child's data after "
				 "child close + parent open)", mis - 1);
	}
	close(fd);
	unlink(name);
}

static void case_chmod_close_stat(void)
{
	char name[64];
	snprintf(name, sizeof(name), "t_cto.cm.%ld", (long)getpid());
	unlink(name);

	int fd = open(name, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) { complain("case5: create: %s", strerror(errno)); return; }

	if (fchmod(fd, 0600) != 0) {
		complain("case5: fchmod: %s", strerror(errno));
		close(fd); unlink(name); return;
	}
	close(fd);

	struct stat st;
	if (stat(name, &st) != 0) {
		complain("case5: stat: %s", strerror(errno));
		unlink(name); return;
	}
	if ((st.st_mode & 07777) != 0600)
		complain("case5: mode 0%o after close, expected 0600 "
			 "(stale cached mode)", st.st_mode & 07777);
	unlink(name);
}

static void case_truncate_close_stat(void)
{
	char name[64];
	snprintf(name, sizeof(name), "t_cto.tr.%ld", (long)getpid());
	unlink(name);

	int fd = open(name, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) { complain("case6: create: %s", strerror(errno)); return; }
	char buf[512];
	memset(buf, 'T', sizeof(buf));
	(void)write(fd, buf, sizeof(buf));
	close(fd);

	fd = open(name, O_WRONLY);
	if (fd < 0) { complain("case6: reopen: %s", strerror(errno)); unlink(name); return; }
	if (ftruncate(fd, 0) != 0) {
		complain("case6: ftruncate: %s", strerror(errno));
		close(fd); unlink(name); return;
	}
	close(fd);

	struct stat st;
	if (stat(name, &st) != 0) {
		complain("case6: stat: %s", strerror(errno));
		unlink(name); return;
	}
	if (st.st_size != 0)
		complain("case6: size %lld after truncate+close, expected 0 "
			 "(stale cached size)", (long long)st.st_size);
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

	prelude(myname, "NFS close-to-open cache consistency");
	cd_or_skip(myname, dir, Nflag);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_write_close_read", case_write_close_read());
	RUN_CASE("case_close_stat_size", case_close_stat_size());
	RUN_CASE("case_overwrite", case_overwrite());
	RUN_CASE("case_fork_child_writes", case_fork_child_writes());
	RUN_CASE("case_chmod_close_stat", case_chmod_close_stat());
	RUN_CASE("case_truncate_close_stat", case_truncate_close_stat());

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}
