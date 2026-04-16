/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_at_variants.c -- exercise the POSIX.1-2008 *at() syscall family
 * with real directory fds (not AT_FDCWD) to verify NFS servers handle
 * dirfd-relative operations correctly.
 *
 * The *at() syscalls were introduced to eliminate TOCTOU races
 * inherent in chdir + operation sequences.  On NFS, each *at() call
 * with a real dirfd translates to a compound that includes the
 * directory's filehandle — the server must resolve the name relative
 * to that handle, not the process's cwd.
 *
 * Cases:
 *
 *   1. openat(dirfd, name).  Open a real directory fd, create a file
 *      via openat, verify it exists via fstatat.
 *
 *   2. mkdirat(dirfd, name).  Create a subdirectory via mkdirat
 *      with a real dirfd.  Verify via fstatat.
 *
 *   3. mknodat(dirfd, name, S_IFIFO).  Create a FIFO via mknodat.
 *      Verify S_ISFIFO via fstatat.
 *
 *   4. fchmodat(dirfd, name, mode).  Create a file, fchmodat to
 *      0600, verify mode via fstatat.
 *
 *   5. fchownat(dirfd, name, uid, gid).  No-op chown via fchownat
 *      with real dirfd.  Verify uid/gid unchanged.
 *
 *   6. renameat(olddirfd, old, newdirfd, new).  Create file in
 *      dir A, rename to dir B using two directory fds.  Verify
 *      the file moved.
 *
 *   7. unlinkat(dirfd, name, 0).  Create and unlink a file via
 *      unlinkat with real dirfd.  Verify gone.
 *
 *   8. unlinkat(dirfd, name, AT_REMOVEDIR).  mkdir then remove
 *      via unlinkat with AT_REMOVEDIR flag.
 *
 * Portable: POSIX.1-2008 across Linux / FreeBSD / macOS / Solaris.
 */

#define _GNU_SOURCE
#define _DARWIN_C_SOURCE

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

static const char *myname = "op_at_variants";

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  exercise *at() syscalls with real dirfds "
		"(POSIX.1-2008)\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

static int make_subdir(const char *tag, char *out, size_t outsz)
{
	snprintf(out, outsz, "t_at.%s.%ld", tag, (long)getpid());
	rmdir(out);
	if (mkdir(out, 0755) != 0) {
		complain("%s: mkdir(%s): %s", tag, out, strerror(errno));
		return -1;
	}
	return 0;
}

static void case_openat(void)
{
	char sub[64];
	if (make_subdir("oa", sub, sizeof(sub)) != 0) return;

	int dirfd = open(sub, O_RDONLY | O_DIRECTORY);
	if (dirfd < 0) {
		complain("case1: open dir: %s", strerror(errno));
		rmdir(sub);
		return;
	}

	int fd = openat(dirfd, "file", O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("case1: openat: %s", strerror(errno));
		close(dirfd);
		rmdir(sub);
		return;
	}
	close(fd);

	struct stat st;
	if (fstatat(dirfd, "file", &st, 0) != 0)
		complain("case1: fstatat after openat: %s", strerror(errno));
	else if (!S_ISREG(st.st_mode))
		complain("case1: fstatat mode not regular file");

	unlinkat(dirfd, "file", 0);
	close(dirfd);
	rmdir(sub);
}

static void case_mkdirat(void)
{
	char sub[64];
	if (make_subdir("md", sub, sizeof(sub)) != 0) return;

	int dirfd = open(sub, O_RDONLY | O_DIRECTORY);
	if (dirfd < 0) {
		complain("case2: open dir: %s", strerror(errno));
		rmdir(sub);
		return;
	}

	if (mkdirat(dirfd, "child", 0755) != 0) {
		complain("case2: mkdirat: %s", strerror(errno));
		close(dirfd);
		rmdir(sub);
		return;
	}

	struct stat st;
	if (fstatat(dirfd, "child", &st, 0) != 0)
		complain("case2: fstatat: %s", strerror(errno));
	else if (!S_ISDIR(st.st_mode))
		complain("case2: mkdirat result not S_IFDIR");

	unlinkat(dirfd, "child", AT_REMOVEDIR);
	close(dirfd);
	rmdir(sub);
}

static void case_mknodat(void)
{
	char sub[64];
	if (make_subdir("mk", sub, sizeof(sub)) != 0) return;

	int dirfd = open(sub, O_RDONLY | O_DIRECTORY);
	if (dirfd < 0) {
		complain("case3: open dir: %s", strerror(errno));
		rmdir(sub);
		return;
	}

	if (mknodat(dirfd, "fifo", S_IFIFO | 0644, 0) != 0) {
		if (errno == EOPNOTSUPP || errno == ENOTSUP) {
			if (!Sflag)
				printf("NOTE: %s: case3 mknodat(FIFO) not "
				       "supported\n", myname);
			close(dirfd);
			rmdir(sub);
			return;
		}
		complain("case3: mknodat: %s", strerror(errno));
		close(dirfd);
		rmdir(sub);
		return;
	}

	struct stat st;
	if (fstatat(dirfd, "fifo", &st, 0) != 0)
		complain("case3: fstatat: %s", strerror(errno));
	else if (!S_ISFIFO(st.st_mode))
		complain("case3: mknodat result not S_IFIFO");

	unlinkat(dirfd, "fifo", 0);
	close(dirfd);
	rmdir(sub);
}

static void case_fchmodat(void)
{
	char sub[64];
	if (make_subdir("cm", sub, sizeof(sub)) != 0) return;

	int dirfd = open(sub, O_RDONLY | O_DIRECTORY);
	if (dirfd < 0) {
		complain("case4: open dir: %s", strerror(errno));
		rmdir(sub);
		return;
	}

	int fd = openat(dirfd, "f", O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) { complain("case4: create: %s", strerror(errno)); close(dirfd); rmdir(sub); return; }
	close(fd);

	if (fchmodat(dirfd, "f", 0600, 0) != 0) {
		complain("case4: fchmodat: %s", strerror(errno));
		goto out;
	}

	struct stat st;
	if (fstatat(dirfd, "f", &st, 0) != 0) {
		complain("case4: fstatat: %s", strerror(errno));
		goto out;
	}
	if ((st.st_mode & 07777) != 0600)
		complain("case4: mode 0%o, expected 0600",
			 st.st_mode & 07777);
out:
	unlinkat(dirfd, "f", 0);
	close(dirfd);
	rmdir(sub);
}

static void case_fchownat(void)
{
	char sub[64];
	if (make_subdir("co", sub, sizeof(sub)) != 0) return;

	int dirfd = open(sub, O_RDONLY | O_DIRECTORY);
	if (dirfd < 0) {
		complain("case5: open dir: %s", strerror(errno));
		rmdir(sub);
		return;
	}

	int fd = openat(dirfd, "f", O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) { complain("case5: create: %s", strerror(errno)); close(dirfd); rmdir(sub); return; }
	close(fd);

	uid_t myuid = getuid();
	gid_t mygid = getgid();
	if (fchownat(dirfd, "f", myuid, mygid, 0) != 0) {
		complain("case5: fchownat: %s", strerror(errno));
		goto out;
	}

	struct stat st;
	if (fstatat(dirfd, "f", &st, 0) != 0) {
		complain("case5: fstatat: %s", strerror(errno));
		goto out;
	}
	if (st.st_uid != myuid)
		complain("case5: uid %u, expected %u",
			 (unsigned)st.st_uid, (unsigned)myuid);
out:
	unlinkat(dirfd, "f", 0);
	close(dirfd);
	rmdir(sub);
}

static void case_renameat_cross(void)
{
	char a[64], b[64];
	if (make_subdir("ra", a, sizeof(a)) != 0) return;
	if (make_subdir("rb", b, sizeof(b)) != 0) { rmdir(a); return; }

	int dfa = open(a, O_RDONLY | O_DIRECTORY);
	int dfb = open(b, O_RDONLY | O_DIRECTORY);
	if (dfa < 0 || dfb < 0) {
		complain("case6: open dirs: %s", strerror(errno));
		if (dfa >= 0) close(dfa);
		if (dfb >= 0) close(dfb);
		rmdir(a); rmdir(b);
		return;
	}

	int fd = openat(dfa, "src", O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) { complain("case6: create: %s", strerror(errno)); goto out; }
	close(fd);

	if (renameat(dfa, "src", dfb, "dst") != 0) {
		complain("case6: renameat(dirA/src, dirB/dst): %s",
			 strerror(errno));
		unlinkat(dfa, "src", 0);
		goto out;
	}

	struct stat st;
	errno = 0;
	if (fstatat(dfa, "src", &st, 0) == 0)
		complain("case6: src still exists in dir A after renameat");
	if (fstatat(dfb, "dst", &st, 0) != 0)
		complain("case6: dst not found in dir B after renameat: %s",
			 strerror(errno));

	unlinkat(dfb, "dst", 0);
out:
	close(dfa);
	close(dfb);
	rmdir(a);
	rmdir(b);
}

static void case_unlinkat_file(void)
{
	char sub[64];
	if (make_subdir("uf", sub, sizeof(sub)) != 0) return;

	int dirfd = open(sub, O_RDONLY | O_DIRECTORY);
	if (dirfd < 0) {
		complain("case7: open dir: %s", strerror(errno));
		rmdir(sub);
		return;
	}

	int fd = openat(dirfd, "f", O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) { complain("case7: create: %s", strerror(errno)); close(dirfd); rmdir(sub); return; }
	close(fd);

	if (unlinkat(dirfd, "f", 0) != 0)
		complain("case7: unlinkat: %s", strerror(errno));

	struct stat st;
	errno = 0;
	if (fstatat(dirfd, "f", &st, 0) == 0)
		complain("case7: file still exists after unlinkat");

	close(dirfd);
	rmdir(sub);
}

static void case_unlinkat_removedir(void)
{
	char sub[64];
	if (make_subdir("ur", sub, sizeof(sub)) != 0) return;

	int dirfd = open(sub, O_RDONLY | O_DIRECTORY);
	if (dirfd < 0) {
		complain("case8: open dir: %s", strerror(errno));
		rmdir(sub);
		return;
	}

	if (mkdirat(dirfd, "child", 0755) != 0) {
		complain("case8: mkdirat: %s", strerror(errno));
		close(dirfd);
		rmdir(sub);
		return;
	}

	if (unlinkat(dirfd, "child", AT_REMOVEDIR) != 0)
		complain("case8: unlinkat(AT_REMOVEDIR): %s",
			 strerror(errno));

	struct stat st;
	errno = 0;
	if (fstatat(dirfd, "child", &st, 0) == 0)
		complain("case8: dir still exists after unlinkat(AT_REMOVEDIR)");

	close(dirfd);
	rmdir(sub);
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
		"*at() syscalls with real dirfds (POSIX.1-2008)");
	cd_or_skip(myname, dir, Nflag);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_openat", case_openat());
	RUN_CASE("case_mkdirat", case_mkdirat());
	RUN_CASE("case_mknodat", case_mknodat());
	RUN_CASE("case_fchmodat", case_fchmodat());
	RUN_CASE("case_fchownat", case_fchownat());
	RUN_CASE("case_renameat_cross", case_renameat_cross());
	RUN_CASE("case_unlinkat_file", case_unlinkat_file());
	RUN_CASE("case_unlinkat_removedir", case_unlinkat_removedir());

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}
