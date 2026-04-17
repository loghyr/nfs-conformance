/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_fd_sharing.c -- exercise fd duplication and inheritance
 * semantics over NFS (ported from cthon04 basic/test4).
 *
 * Two fds can refer to the same "open file description" (dup,
 * dup2, fork) or to INDEPENDENT descriptions (two open() calls on
 * the same path).  The first shares offset and flags; the second
 * does not.  On NFS the distinction is visible in cache coherence
 * and lock ownership.
 *
 * Cases:
 *
 *   1. dup(): two fds share offset.  Write on fd1 advances offset
 *      visible via lseek(fd2, 0, SEEK_CUR).
 *
 *   2. dup2() over existing fd: the target fd is closed first,
 *      then becomes a copy of the source.  Pre-existing data in
 *      the target-fd's file is unaffected.
 *
 *   3. fcntl(F_DUPFD): new fd >= specified lower bound; shares
 *      open file description.
 *
 *   4. Two independent open() calls have independent offsets.
 *
 *   5. fork: child inherits open fds and shares their offsets
 *      with the parent.  Parent write advances child's lseek.
 *
 *   6. O_CLOEXEC: fd with FD_CLOEXEC set is NOT inherited across
 *      execve(); it IS inherited across fork().
 *
 *   7. fcntl(F_DUPFD_CLOEXEC): duplicated fd inherits flags
 *      independently — specifically, FD_CLOEXEC is set on the
 *      new fd regardless of the source fd's setting.
 *
 * Portable: POSIX.  F_DUPFD_CLOEXEC is POSIX.1-2008.
 */

#define _POSIX_C_SOURCE 200809L

#include "tests.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
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

static const char *myname = "op_fd_sharing";

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  fd duplication and inheritance over NFS\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

static int create_scratch(char *path, size_t sz, int casenum)
{
	snprintf(path, sz, "t_fs.%d.%ld", casenum, (long)getpid());
	unlink(path);
	int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) return -1;
	return fd;
}

static void case_dup_shared_offset(void)
{
	char a[64];
	int fd1 = create_scratch(a, sizeof(a), 1);
	if (fd1 < 0) {
		complain("case1: create: %s", strerror(errno));
		return;
	}
	int fd2 = dup(fd1);
	if (fd2 < 0) {
		complain("case1: dup: %s", strerror(errno));
		close(fd1); unlink(a); return;
	}
	if (write(fd1, "abc", 3) != 3) {
		complain("case1: write: %s", strerror(errno));
		close(fd1); close(fd2); unlink(a); return;
	}
	off_t off = lseek(fd2, 0, SEEK_CUR);
	if (off != 3)
		complain("case1: dup'd fd offset = %lld, expected 3 "
			 "(offset sharing broken)", (long long)off);
	close(fd1);
	close(fd2);
	unlink(a);
}

static void case_dup2_closes_target(void)
{
	char a[64], b[64];
	int fd1 = create_scratch(a, sizeof(a), 2);
	if (fd1 < 0) {
		complain("case2: create a: %s", strerror(errno));
		return;
	}
	snprintf(b, sizeof(b), "t_fs.2b.%ld", (long)getpid());
	unlink(b);
	int fd2 = open(b, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd2 < 0) {
		complain("case2: create b: %s", strerror(errno));
		close(fd1); unlink(a); return;
	}
	if (write(fd2, "XY", 2) != 2) {
		complain("case2: write b: %s", strerror(errno));
		goto out;
	}
	/* dup2 fd1 over fd2: b's fd is closed, and fd2 now refers to a. */
	if (dup2(fd1, fd2) != fd2) {
		complain("case2: dup2: %s", strerror(errno));
		goto out;
	}
	if (write(fd2, "abc", 3) != 3) {
		complain("case2: write via dup'd fd2: %s", strerror(errno));
		goto out;
	}
	/* b should still have "XY" on disk. */
	int rfd = open(b, O_RDONLY);
	if (rfd >= 0) {
		char buf[4] = {0};
		ssize_t r = read(rfd, buf, sizeof(buf));
		close(rfd);
		if (r != 2 || strncmp(buf, "XY", 2) != 0)
			complain("case2: b contents disturbed by dup2 "
				 "('%.*s')", (int)r, buf);
	} else {
		complain("case2: reopen b: %s", strerror(errno));
	}
	/* a should have "abc" via fd2's writes. */
	int rfd2 = open(a, O_RDONLY);
	if (rfd2 >= 0) {
		char buf[4] = {0};
		ssize_t r = read(rfd2, buf, sizeof(buf));
		close(rfd2);
		if (r != 3 || strncmp(buf, "abc", 3) != 0)
			complain("case2: a contents after dup2+write: '%.*s'",
				 (int)r, buf);
	}

out:
	close(fd1);
	/* fd2 may already be closed by dup2, or may be the dup. */
	close(fd2);
	unlink(a);
	unlink(b);
}

static void case_fcntl_dupfd(void)
{
	char a[64];
	int fd1 = create_scratch(a, sizeof(a), 3);
	if (fd1 < 0) {
		complain("case3: create: %s", strerror(errno));
		return;
	}
	int fd2 = fcntl(fd1, F_DUPFD, 100);
	if (fd2 < 0) {
		complain("case3: F_DUPFD: %s", strerror(errno));
		close(fd1); unlink(a); return;
	}
	if (fd2 < 100)
		complain("case3: F_DUPFD returned %d, expected >=100", fd2);

	if (write(fd1, "hello", 5) != 5) {
		complain("case3: write: %s", strerror(errno));
		close(fd1); close(fd2); unlink(a); return;
	}
	off_t off = lseek(fd2, 0, SEEK_CUR);
	if (off != 5)
		complain("case3: F_DUPFD did not share offset (got %lld)",
			 (long long)off);

	close(fd1);
	close(fd2);
	unlink(a);
}

static void case_independent_opens(void)
{
	char a[64];
	snprintf(a, sizeof(a), "t_fs.io.%ld", (long)getpid());
	unlink(a);

	int fd1 = open(a, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd1 < 0) {
		complain("case4: create: %s", strerror(errno));
		return;
	}
	if (write(fd1, "1234567890", 10) != 10) {
		complain("case4: write: %s", strerror(errno));
		close(fd1); unlink(a); return;
	}
	int fd2 = open(a, O_RDWR);
	if (fd2 < 0) {
		complain("case4: second open: %s", strerror(errno));
		close(fd1); unlink(a); return;
	}
	off_t off1 = lseek(fd1, 0, SEEK_CUR);
	off_t off2 = lseek(fd2, 0, SEEK_CUR);
	if (off1 != 10)
		complain("case4: fd1 offset %lld, expected 10",
			 (long long)off1);
	if (off2 != 0)
		complain("case4: fd2 offset %lld, expected 0 (independent "
			 "open should have its own offset)",
			 (long long)off2);
	close(fd1);
	close(fd2);
	unlink(a);
}

static void case_fork_shared_offset(void)
{
	char a[64];
	int fd = create_scratch(a, sizeof(a), 5);
	if (fd < 0) {
		complain("case5: create: %s", strerror(errno));
		return;
	}

	/* Child writes 3 bytes via inherited fd; parent's offset
	 * must advance because the open file description is shared. */
	pid_t pid = fork();
	if (pid < 0) {
		complain("case5: fork: %s", strerror(errno));
		close(fd); unlink(a); return;
	}
	if (pid == 0) {
		if (write(fd, "abc", 3) != 3) _exit(70);
		_exit(0);
	}
	int status = 0;
	waitpid(pid, &status, 0);
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		complain("case5: child exit 0x%x", status);
		close(fd); unlink(a); return;
	}
	off_t off = lseek(fd, 0, SEEK_CUR);
	if (off != 3)
		complain("case5: parent offset %lld after child write, "
			 "expected 3 (fork offset sharing broken)",
			 (long long)off);

	close(fd);
	unlink(a);
}

static void case_cloexec_fork_inherit(void)
{
	char a[64];
	snprintf(a, sizeof(a), "t_fs.ce.%ld", (long)getpid());
	unlink(a);
	int fd = open(a, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (fd < 0) {
		complain("case6: open O_CLOEXEC: %s", strerror(errno));
		unlink(a); return;
	}
	int flags = fcntl(fd, F_GETFD);
	if (flags < 0 || !(flags & FD_CLOEXEC))
		complain("case6: FD_CLOEXEC not set after O_CLOEXEC open "
			 "(got flags 0x%x)", flags);

	/* Fork: child should still have fd open (CLOEXEC only fires
	 * at execve). */
	pid_t pid = fork();
	if (pid < 0) {
		complain("case6: fork: %s", strerror(errno));
		close(fd); unlink(a); return;
	}
	if (pid == 0) {
		if (write(fd, "x", 1) == 1)
			_exit(0);
		_exit(70);
	}
	int status = 0;
	waitpid(pid, &status, 0);
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		complain("case6: O_CLOEXEC fd not inherited across fork "
			 "(child exit 0x%x) — CLOEXEC is exec-only",
			 status);

	close(fd);
	unlink(a);
}

static void case_fcntl_dupfd_cloexec(void)
{
	char a[64];
	int fd = create_scratch(a, sizeof(a), 7);
	if (fd < 0) {
		complain("case7: create: %s", strerror(errno));
		return;
	}
	/* Source fd has no CLOEXEC. */
	int flags = fcntl(fd, F_GETFD);
	if (flags & FD_CLOEXEC)
		complain("case7: source fd has unexpected FD_CLOEXEC");

	int dupfd = fcntl(fd, F_DUPFD_CLOEXEC, 0);
	if (dupfd < 0) {
		if (errno == EINVAL && !Sflag) {
			printf("NOTE: %s: case7 F_DUPFD_CLOEXEC not "
			       "supported on this platform\n", myname);
			close(fd); unlink(a); return;
		}
		complain("case7: F_DUPFD_CLOEXEC: %s", strerror(errno));
		close(fd); unlink(a); return;
	}
	int dupflags = fcntl(dupfd, F_GETFD);
	if (dupflags < 0 || !(dupflags & FD_CLOEXEC))
		complain("case7: F_DUPFD_CLOEXEC did not set FD_CLOEXEC "
			 "on the new fd (flags 0x%x)", dupflags);
	/* Source fd's FD_CLOEXEC must NOT have been changed. */
	int src_after = fcntl(fd, F_GETFD);
	if (src_after & FD_CLOEXEC)
		complain("case7: F_DUPFD_CLOEXEC modified source fd's "
			 "flags (0x%x)", src_after);

	close(fd);
	close(dupfd);
	unlink(a);
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
		"fd duplication and inheritance over NFS");
	cd_or_skip(myname, dir, Nflag);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_dup_shared_offset", case_dup_shared_offset());
	RUN_CASE("case_dup2_closes_target",
		 case_dup2_closes_target());
	RUN_CASE("case_fcntl_dupfd", case_fcntl_dupfd());
	RUN_CASE("case_independent_opens", case_independent_opens());
	RUN_CASE("case_fork_shared_offset",
		 case_fork_shared_offset());
	RUN_CASE("case_cloexec_fork_inherit",
		 case_cloexec_fork_inherit());
	RUN_CASE("case_fcntl_dupfd_cloexec",
		 case_fcntl_dupfd_cloexec());

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}
