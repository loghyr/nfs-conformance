/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_errno_rename.c -- exercise rename(2) error paths.
 *
 * POSIX.1-2008 specifies a long list of errno returns for rename().
 * This test covers the high-value ones that NFS servers frequently
 * get wrong; pjdfstest's rename/ directory is the reference.
 *
 * Cases:
 *
 *   1. rename(".", new)  and rename("..", new): must fail.  POSIX
 *      leaves the specific errno implementation-defined among
 *      EINVAL and EBUSY; we accept either.
 *
 *   2. rename(old, ".") and rename(old, ".."): same.
 *
 *   3. rename(dir, existing_file): the target must be a directory
 *      too.  Expect ENOTDIR.
 *
 *   4. rename(file, existing_dir): the source must also be a
 *      directory.  Expect EISDIR.
 *
 *   5. rename(A, B) where B is a non-empty directory: must fail
 *      with ENOTEMPTY (POSIX) or EEXIST (some older Unixes).
 *
 *   6. rename(parent, parent/child): moving a directory into one
 *      of its descendants is invalid.  Expect EINVAL.
 *
 *   7. rename(missing, new): ENOENT.
 *
 *   8. rename(old, /nonexistent_dir/new): missing path prefix on
 *      the target.  Expect ENOENT.
 *
 * Portable: POSIX.1-2008 across Linux / FreeBSD / macOS / Solaris.
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

static const char *myname = "op_errno_rename";

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  exercise rename(2) error paths\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

static int touch(const char *path)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) return -1;
	close(fd);
	return 0;
}

/* Report "expected one of these errnos" -- caller passes a
 * NULL-terminated list and we check rc == -1 plus errno is listed. */
static int check_fail_with(int rc, const int *allowed, int n_allowed,
			   const char *label)
{
	if (rc == 0) {
		complain("%s: unexpectedly succeeded", label);
		return 0;
	}
	for (int i = 0; i < n_allowed; i++)
		if (errno == allowed[i])
			return 1;
	complain("%s: got %s (%d); expected one of the allowed errnos",
		 label, strerror(errno), errno);
	return 0;
}

static void case_rename_from_dot(void)
{
	char new[64];
	snprintf(new, sizeof(new), "t_er.fd.%ld", (long)getpid());
	unlink(new);
	rmdir(new);

	errno = 0;
	int allowed[] = { EINVAL, EBUSY };
	check_fail_with(rename(".", new), allowed, 2,
			"case1: rename(\".\", new)");

	errno = 0;
	check_fail_with(rename("..", new), allowed, 2,
			"case1: rename(\"..\", new)");
}

static void case_rename_to_dot(void)
{
	char old[64];
	snprintf(old, sizeof(old), "t_er.td.%ld", (long)getpid());
	unlink(old);

	if (touch(old) != 0) {
		complain("case2: touch: %s", strerror(errno));
		return;
	}

	errno = 0;
	int allowed[] = { EINVAL, EBUSY };
	check_fail_with(rename(old, "."), allowed, 2,
			"case2: rename(old, \".\")");
	errno = 0;
	check_fail_with(rename(old, ".."), allowed, 2,
			"case2: rename(old, \"..\")");

	unlink(old);
}

static void case_rename_dir_over_file(void)
{
	char d[64], f[64];
	snprintf(d, sizeof(d), "t_er.dof.d.%ld", (long)getpid());
	snprintf(f, sizeof(f), "t_er.dof.f.%ld", (long)getpid());
	rmdir(d); unlink(f);

	if (mkdir(d, 0755) != 0) { complain("case3: mkdir: %s", strerror(errno)); return; }
	if (touch(f) != 0) { complain("case3: touch: %s", strerror(errno)); rmdir(d); return; }

	errno = 0;
	int allowed[] = { ENOTDIR };
	check_fail_with(rename(d, f), allowed, 1,
			"case3: rename(dir, file)");

	rmdir(d);
	unlink(f);
}

static void case_rename_file_over_dir(void)
{
	char d[64], f[64];
	snprintf(d, sizeof(d), "t_er.fod.d.%ld", (long)getpid());
	snprintf(f, sizeof(f), "t_er.fod.f.%ld", (long)getpid());
	rmdir(d); unlink(f);

	if (mkdir(d, 0755) != 0) { complain("case4: mkdir: %s", strerror(errno)); return; }
	if (touch(f) != 0) { complain("case4: touch: %s", strerror(errno)); rmdir(d); return; }

	errno = 0;
	int allowed[] = { EISDIR };
	check_fail_with(rename(f, d), allowed, 1,
			"case4: rename(file, dir)");

	rmdir(d);
	unlink(f);
}

static void case_rename_to_nonempty_dir(void)
{
	char sd[64], td[64], inside[128];
	snprintf(sd, sizeof(sd), "t_er.ne.s.%ld", (long)getpid());
	snprintf(td, sizeof(td), "t_er.ne.t.%ld", (long)getpid());
	snprintf(inside, sizeof(inside), "%s/f", td);
	unlink(inside); rmdir(sd); rmdir(td);

	if (mkdir(sd, 0755) != 0 || mkdir(td, 0755) != 0) {
		complain("case5: mkdir: %s", strerror(errno));
		rmdir(sd); rmdir(td);
		return;
	}
	if (touch(inside) != 0) {
		complain("case5: touch inside td: %s", strerror(errno));
		rmdir(sd); unlink(inside); rmdir(td);
		return;
	}

	errno = 0;
	int allowed[] = { ENOTEMPTY, EEXIST };
	check_fail_with(rename(sd, td), allowed, 2,
			"case5: rename(dir, non-empty dir)");

	unlink(inside);
	rmdir(sd);
	rmdir(td);
}

static void case_rename_into_child(void)
{
	char p[64], c[128];
	snprintf(p, sizeof(p), "t_er.ic.%ld", (long)getpid());
	snprintf(c, sizeof(c), "%s/child", p);
	rmdir(c); rmdir(p);

	if (mkdir(p, 0755) != 0) { complain("case6: mkdir: %s", strerror(errno)); return; }
	if (mkdir(c, 0755) != 0) {
		complain("case6: mkdir child: %s", strerror(errno));
		rmdir(p); return;
	}

	errno = 0;
	int allowed[] = { EINVAL };
	check_fail_with(rename(p, c), allowed, 1,
			"case6: rename(parent, parent/child)");

	rmdir(c);
	rmdir(p);
}

static void case_rename_missing_source(void)
{
	char a[64], b[64];
	snprintf(a, sizeof(a), "t_er.ms.a.%ld", (long)getpid());
	snprintf(b, sizeof(b), "t_er.ms.b.%ld", (long)getpid());
	unlink(a); unlink(b);

	errno = 0;
	int allowed[] = { ENOENT };
	check_fail_with(rename(a, b), allowed, 1,
			"case7: rename(missing, new)");
}

static void case_rename_missing_target_prefix(void)
{
	char a[64], b[128];
	snprintf(a, sizeof(a), "t_er.mt.%ld", (long)getpid());
	snprintf(b, sizeof(b), "t_er.mt.nonexistent.%ld/x", (long)getpid());
	unlink(a);

	if (touch(a) != 0) { complain("case8: touch: %s", strerror(errno)); return; }

	errno = 0;
	int allowed[] = { ENOENT };
	check_fail_with(rename(a, b), allowed, 1,
			"case8: rename(old, missing/new)");

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
		"rename(2) error-path coverage (pjdfstest rename/)");
	cd_or_skip(myname, dir, Nflag);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_rename_from_dot", case_rename_from_dot());
	RUN_CASE("case_rename_to_dot", case_rename_to_dot());
	RUN_CASE("case_rename_dir_over_file", case_rename_dir_over_file());
	RUN_CASE("case_rename_file_over_dir", case_rename_file_over_dir());
	RUN_CASE("case_rename_to_nonempty_dir",
		 case_rename_to_nonempty_dir());
	RUN_CASE("case_rename_into_child", case_rename_into_child());
	RUN_CASE("case_rename_missing_source",
		 case_rename_missing_source());
	RUN_CASE("case_rename_missing_target_prefix",
		 case_rename_missing_target_prefix());

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}
