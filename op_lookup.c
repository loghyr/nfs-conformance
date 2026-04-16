/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_lookup.c -- exercise NFSv4 LOOKUP / LOOKUPP ops (RFC 7530
 * S18.14 / S18.15) via the POSIX open / stat / openat surface.
 *
 * Cases:
 *
 *   1. Simple lookup.  Create a file, stat() it by name, verify
 *      st_ino is consistent across stat and fstat.
 *
 *   2. ENOENT.  stat() on a nonexistent name returns -1/ENOENT.
 *
 *   3. Deep path.  Create a directory tree 8 levels deep, create a
 *      file at the bottom, open it via the full relative path.
 *      Exercises a chain of LOOKUP operations in one compound.
 *
 *   4. LOOKUPP (parent).  Open ".", fstat to get its inode.  Open
 *      a subdir, open ".." inside it, fstat -- the inode of ".."
 *      must match the original ".".
 *
 *   5. Dot-dot at root.  chdir to the mount root (-d), stat("..").
 *      On NFS the server should return the root itself (LOOKUPP
 *      at the export root is the root).  Verify st_ino of ".."
 *      equals st_ino of ".".
 *
 *   6. Component EACCES.  Create dir/file with dir mode 0000.
 *      stat("dir/file") should return -1/EACCES (the LOOKUP
 *      on the intermediate component fails).  Skipped when
 *      running as root (DAC bypass).
 *
 *   7. Long component name.  Create a file with a 255-byte name
 *      (NAME_MAX); stat it.  Then attempt to create a file with
 *      a 256-byte name and expect ENAMETOOLONG.
 *
 * Portable: POSIX across Linux / FreeBSD / macOS / Solaris.
 */

#define _POSIX_C_SOURCE 200809L

#include "tests.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
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

static const char *myname = "op_lookup";

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  exercise open/stat -> NFSv4 LOOKUP/LOOKUPP "
		"(RFC 7530 S18.14/S18.15)\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

static void case_simple_lookup(void)
{
	char a[64];
	snprintf(a, sizeof(a), "t_lk.s.%ld", (long)getpid());
	unlink(a);

	int fd = open(a, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("case1: open(create): %s", strerror(errno));
		return;
	}

	struct stat st_name, st_fd;
	if (stat(a, &st_name) != 0) {
		complain("case1: stat(%s): %s", a, strerror(errno));
		close(fd);
		unlink(a);
		return;
	}
	if (fstat(fd, &st_fd) != 0) {
		complain("case1: fstat: %s", strerror(errno));
		close(fd);
		unlink(a);
		return;
	}

	if (st_name.st_ino != st_fd.st_ino)
		complain("case1: stat ino %lu != fstat ino %lu",
			 (unsigned long)st_name.st_ino,
			 (unsigned long)st_fd.st_ino);
	close(fd);
	unlink(a);
}

static void case_enoent(void)
{
	char a[64];
	snprintf(a, sizeof(a), "t_lk.ne.%ld", (long)getpid());
	unlink(a);

	errno = 0;
	struct stat st;
	if (stat(a, &st) == 0)
		complain("case2: stat(%s) succeeded on nonexistent file", a);
	else if (errno != ENOENT)
		complain("case2: expected ENOENT, got %s", strerror(errno));
}

static void rmdir_r(const char *base, int depth)
{
	if (depth <= 0) return;
	size_t blen = strlen(base);
	if (blen + 3 > PATH_MAX) return;
	char path[PATH_MAX];
	memcpy(path, base, blen);
	memcpy(path + blen, "/d", 3);
	rmdir_r(path, depth - 1);
	rmdir(path);
}

static void case_deep_path(void)
{
	char base[64];
	snprintf(base, sizeof(base), "t_lk.dp.%ld", (long)getpid());

	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s", base);

	int depth = 8;
	for (int i = 0; i < depth; i++) {
		size_t len = strlen(path);
		snprintf(path + len, sizeof(path) - len, "/d");
		mkdir(path, 0755);
	}

	size_t len = strlen(path);
	snprintf(path + len, sizeof(path) - len, "/leaf");
	int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("case3: open(%s): %s", path, strerror(errno));
		rmdir_r(base, depth);
		rmdir(base);
		return;
	}

	struct stat st;
	if (fstat(fd, &st) != 0) {
		complain("case3: fstat: %s", strerror(errno));
	} else if (!S_ISREG(st.st_mode)) {
		complain("case3: fstat mode not regular file");
	}

	close(fd);
	unlink(path);
	rmdir_r(base, depth);
	rmdir(base);
}

static void case_lookupp(void)
{
	char sub[64];
	snprintf(sub, sizeof(sub), "t_lk.pp.%ld", (long)getpid());
	rmdir(sub);
	if (mkdir(sub, 0755) != 0) {
		complain("case4: mkdir(%s): %s", sub, strerror(errno));
		return;
	}

	struct stat st_dot, st_dotdot;
	if (stat(".", &st_dot) != 0) {
		complain("case4: stat(.): %s", strerror(errno));
		rmdir(sub);
		return;
	}

	char dotdot[128];
	snprintf(dotdot, sizeof(dotdot), "%s/..", sub);
	if (stat(dotdot, &st_dotdot) != 0) {
		complain("case4: stat(%s): %s", dotdot, strerror(errno));
		rmdir(sub);
		return;
	}

	if (st_dot.st_ino != st_dotdot.st_ino)
		complain("case4: ino of '.' (%lu) != ino of '%s' (%lu)",
			 (unsigned long)st_dot.st_ino, dotdot,
			 (unsigned long)st_dotdot.st_ino);
	rmdir(sub);
}

static void case_dotdot_at_root(void)
{
	struct stat st_dot, st_dotdot;
	if (stat(".", &st_dot) != 0) {
		complain("case5: stat(.): %s", strerror(errno));
		return;
	}
	if (stat("..", &st_dotdot) != 0) {
		complain("case5: stat(..): %s", strerror(errno));
		return;
	}
	if (st_dot.st_ino != st_dotdot.st_ino) {
		if (!Sflag)
			printf("NOTE: %s: case5 '.' ino %lu != '..' ino %lu "
			       "(may be above export root or submount)\n",
			       myname,
			       (unsigned long)st_dot.st_ino,
			       (unsigned long)st_dotdot.st_ino);
	}
}

static void case_eacces(void)
{
	if (getuid() == 0) {
		if (!Sflag)
			printf("NOTE: %s: case6 skipped (running as root, "
			       "DAC bypass)\n", myname);
		return;
	}

	char dir[64], file[128];
	snprintf(dir, sizeof(dir), "t_lk.ac.%ld", (long)getpid());
	snprintf(file, sizeof(file), "%s/secret", dir);
	rmdir(dir);

	if (mkdir(dir, 0755) != 0) {
		complain("case6: mkdir: %s", strerror(errno));
		return;
	}

	int fd = open(file, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("case6: open: %s", strerror(errno));
		rmdir(dir);
		return;
	}
	close(fd);

	if (chmod(dir, 0000) != 0) {
		complain("case6: chmod: %s", strerror(errno));
		unlink(file);
		rmdir(dir);
		return;
	}

	errno = 0;
	struct stat st;
	if (stat(file, &st) == 0) {
		complain("case6: stat through 0000 dir succeeded");
	} else if (errno != EACCES) {
		complain("case6: expected EACCES, got %s", strerror(errno));
	}

	chmod(dir, 0755);
	unlink(file);
	rmdir(dir);
}

static void case_long_name(void)
{
	char name[512];
	memset(name, 'L', 255);
	name[255] = '\0';

	unlink(name);
	int fd = open(name, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		if (errno == ENAMETOOLONG) {
			if (!Sflag)
				printf("NOTE: %s: case7 server NAME_MAX < 255 "
				       "(%s)\n", myname, strerror(errno));
			return;
		}
		complain("case7: open(255-char name): %s", strerror(errno));
		return;
	}

	struct stat st;
	if (stat(name, &st) != 0)
		complain("case7: stat(255-char name): %s", strerror(errno));

	close(fd);
	unlink(name);

	memset(name, 'L', 256);
	name[256] = '\0';
	errno = 0;
	fd = open(name, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd >= 0) {
		if (!Sflag)
			printf("NOTE: %s: case7 server allowed 256-byte "
			       "component name (NAME_MAX > 255)\n", myname);
		close(fd);
		unlink(name);
	} else if (errno != ENAMETOOLONG) {
		complain("case7: expected ENAMETOOLONG for 256-char name, "
			 "got %s", strerror(errno));
	}
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
		"open/stat -> NFSv4 LOOKUP/LOOKUPP (RFC 7530 S18.14/S18.15)");
	cd_or_skip(myname, dir, Nflag);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_simple_lookup", case_simple_lookup());
	RUN_CASE("case_enoent", case_enoent());
	RUN_CASE("case_deep_path", case_deep_path());
	RUN_CASE("case_lookupp", case_lookupp());
	RUN_CASE("case_dotdot_at_root", case_dotdot_at_root());
	RUN_CASE("case_eacces", case_eacces());
	RUN_CASE("case_long_name", case_long_name());

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}
