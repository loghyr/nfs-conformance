/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_linkat.c -- exercise NFSv4 LINK op (RFC 7530 S18.14) via
 * link / linkat and the POSIX st_nlink invariants.
 *
 * Cases:
 *
 *   1. link(old, new) creates a hardlink; both names refer to the
 *      same inode; st_nlink goes from 1 to 2.
 *
 *   2. Contents visible via both names.  Writing through `old`
 *      changes contents read through `new`, and vice versa.  This
 *      is the defining property of a hardlink (vs reflink).
 *
 *   3. Unlink decrements nlink.  unlink(old): nlink drops to 1;
 *      file still accessible via `new`.  unlink(new): file gone.
 *
 *   4. link() target exists: EEXIST.
 *
 *   5. link() to a symlink: creates a hardlink to the symlink
 *      (POSIX behaviour; linkat with AT_SYMLINK_FOLLOW would
 *      follow it, but plain link()/linkat without the flag does
 *      not).  Verify S_IFLNK on the result.
 *
 *   6. linkat(AT_EMPTY_PATH) from an open fd (Linux-only behaviour;
 *      skipped on non-Linux).  Tests linking an already-open file.
 *
 * Portable via link(2) + linkat(2); case 6 is Linux-specific and
 * runtime-skipped elsewhere.
 */

#define _GNU_SOURCE
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

static const char *myname = "op_linkat";

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  exercise link/linkat -> NFSv4 LINK (RFC 7530 S18.14)\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

static int write_tiny(const char *path, const char *body)
{
	int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("open(%s): %s", path, strerror(errno));
		return -1;
	}
	int rc = pwrite_all(fd, body, strlen(body), 0, path);
	close(fd);
	return rc;
}

static ssize_t read_all(const char *path, char *buf, size_t cap)
{
	int fd = open(path, O_RDONLY);
	if (fd < 0) {
		complain("open(%s) for read: %s", path, strerror(errno));
		return -1;
	}
	ssize_t n = read(fd, buf, cap - 1);
	close(fd);
	if (n < 0) {
		complain("read(%s): %s", path, strerror(errno));
		return -1;
	}
	buf[n] = '\0';
	return n;
}

static void case_basic_link(void)
{
	char a[64], b[64];
	snprintf(a, sizeof(a), "t_ln.a.%ld", (long)getpid());
	snprintf(b, sizeof(b), "t_ln.b.%ld", (long)getpid());
	unlink(a); unlink(b);

	if (write_tiny(a, "hello\n") < 0) return;

	if (link(a, b) != 0) {
		complain("case1: link(%s,%s): %s", a, b, strerror(errno));
		unlink(a);
		return;
	}

	struct stat sta, stb;
	if (stat(a, &sta) != 0 || stat(b, &stb) != 0) {
		complain("case1: stat: %s", strerror(errno));
		goto out;
	}
	if (sta.st_ino != stb.st_ino || sta.st_dev != stb.st_dev)
		complain("case1: link does not share inode (a: %llu/%llu, "
			 "b: %llu/%llu)",
			 (unsigned long long)sta.st_dev,
			 (unsigned long long)sta.st_ino,
			 (unsigned long long)stb.st_dev,
			 (unsigned long long)stb.st_ino);
	if (sta.st_nlink != 2)
		complain("case1: st_nlink after link = %lu, expected 2",
			 (unsigned long)sta.st_nlink);

out:
	unlink(a);
	unlink(b);
}

static void case_shared_contents(void)
{
	char a[64], b[64];
	snprintf(a, sizeof(a), "t_ln.sa.%ld", (long)getpid());
	snprintf(b, sizeof(b), "t_ln.sb.%ld", (long)getpid());
	unlink(a); unlink(b);

	if (write_tiny(a, "one\n") < 0) return;
	if (link(a, b) != 0) {
		complain("case2: link: %s", strerror(errno));
		unlink(a);
		return;
	}

	/* Write through b, read through a. */
	if (write_tiny(b, "TWO\n") < 0) goto out;
	char buf[16];
	if (read_all(a, buf, sizeof(buf)) < 0) goto out;
	if (strcmp(buf, "TWO\n") != 0)
		complain("case2: writing via b did not affect a "
			 "(a reads '%s')",
			 buf);
out:
	unlink(a);
	unlink(b);
}

static void case_unlink_nlink(void)
{
	char a[64], b[64];
	snprintf(a, sizeof(a), "t_ln.ua.%ld", (long)getpid());
	snprintf(b, sizeof(b), "t_ln.ub.%ld", (long)getpid());
	unlink(a); unlink(b);

	if (write_tiny(a, "persistent\n") < 0) return;
	if (link(a, b) != 0) {
		complain("case3: link: %s", strerror(errno));
		unlink(a);
		return;
	}

	if (unlink(a) != 0) {
		complain("case3: unlink(a): %s", strerror(errno));
		unlink(b);
		return;
	}

	/* b still exists, nlink == 1, contents intact. */
	struct stat st;
	if (stat(b, &st) != 0) {
		complain("case3: stat(b) after unlink(a): %s",
			 strerror(errno));
		goto out;
	}
	if (st.st_nlink != 1)
		complain("case3: nlink after unlink(a) = %lu, expected 1",
			 (unsigned long)st.st_nlink);

	char buf[32];
	if (read_all(b, buf, sizeof(buf)) < 0) goto out;
	if (strcmp(buf, "persistent\n") != 0)
		complain("case3: contents changed after unlink(a): '%s'",
			 buf);

	if (unlink(b) != 0) {
		complain("case3: unlink(b): %s", strerror(errno));
		return;
	}
	if (access(b, F_OK) == 0)
		complain("case3: b still accessible after final unlink");
	return;
out:
	unlink(b);
}

static void case_link_to_existing(void)
{
	char a[64], b[64];
	snprintf(a, sizeof(a), "t_ln.ea.%ld", (long)getpid());
	snprintf(b, sizeof(b), "t_ln.eb.%ld", (long)getpid());
	unlink(a); unlink(b);

	if (write_tiny(a, "a\n") < 0) return;
	if (write_tiny(b, "b\n") < 0) { unlink(a); return; }

	errno = 0;
	int rc = link(a, b);
	if (rc == 0)
		complain("case4: link() over existing target unexpectedly "
			 "succeeded");
	else if (errno != EEXIST)
		complain("case4: expected EEXIST, got %s", strerror(errno));

	unlink(a);
	unlink(b);
}

static void case_link_to_symlink(void)
{
	char target[64], link_[64], hardlink[64];
	snprintf(target, sizeof(target), "t_ln.tg.%ld", (long)getpid());
	snprintf(link_, sizeof(link_), "t_ln.sl.%ld", (long)getpid());
	snprintf(hardlink, sizeof(hardlink), "t_ln.hl.%ld", (long)getpid());
	unlink(target); unlink(link_); unlink(hardlink);

	if (write_tiny(target, "t\n") < 0) return;
	if (symlink(target, link_) != 0) {
		complain("case5: symlink: %s", strerror(errno));
		unlink(target);
		return;
	}

	/*
	 * Plain link() on a symlink: POSIX leaves this implementation-
	 * defined (may link to the symlink OR follow it).  RFC 7530
	 * S18.14 also permits the NFS server to reject a LINK whose
	 * source is a non-regular file with NFS4ERR_NOTSUPP, which
	 * the client surfaces as EPERM (or ENOSYS / EOPNOTSUPP /
	 * ENOTSUP on other stacks).  Treat those as a spec-legal
	 * server refusal and NOTE rather than FAIL.
	 *
	 * When the call succeeds, we expect linkat without
	 * AT_SYMLINK_FOLLOW to hardlink the symlink itself -- same
	 * ino as link_.  A different ino means the server followed
	 * the link, which is non-conforming.
	 */
	if (linkat(AT_FDCWD, link_, AT_FDCWD, hardlink, 0) != 0) {
		if (errno == EPERM || errno == ENOSYS
		    || errno == EOPNOTSUPP || errno == ENOTSUP) {
			if (!Sflag)
				printf("NOTE: %s: case5 server rejected "
				       "hardlink-to-symlink with %s "
				       "(RFC 7530 S18.14 permits "
				       "NFS4ERR_NOTSUPP here)\n",
				       myname, strerror(errno));
			goto out;
		}
		complain("case5: linkat: %s", strerror(errno));
		goto out;
	}
	struct stat st_hl, st_ln;
	if (lstat(hardlink, &st_hl) != 0 || lstat(link_, &st_ln) != 0) {
		complain("case5: lstat: %s", strerror(errno));
		goto out;
	}
	if (st_hl.st_ino != st_ln.st_ino) {
		/* linkat without AT_SYMLINK_FOLLOW should produce a
		 * hardlink to the symlink (same ino as link_).  If we
		 * see a different ino, linkat followed the symlink,
		 * which is non-conforming behaviour. */
		complain("case5: linkat appears to have followed the symlink "
			 "(hardlink ino %llu != symlink ino %llu)",
			 (unsigned long long)st_hl.st_ino,
			 (unsigned long long)st_ln.st_ino);
	}
out:
	unlink(hardlink);
	unlink(link_);
	unlink(target);
}

static void case_link_at_empty_path(void)
{
#if !defined(__linux__) || !defined(AT_EMPTY_PATH)
	if (!Sflag)
		printf("NOTE: %s: case6 linkat(AT_EMPTY_PATH) skipped "
		       "(non-Linux or header-level support missing)\n",
		       myname);
#else
	/*
	 * linkat with AT_EMPTY_PATH requires either /proc or a
	 * privileged open via O_PATH; the canonical idiom is
	 *
	 *   fd = open("", O_PATH) ...
	 *
	 * but a simpler exercise is to open a scratch file, then
	 * linkat(fd, "", AT_FDCWD, newname, AT_EMPTY_PATH).  Without
	 * CAP_DAC_READ_SEARCH this returns ENOENT on many kernels;
	 * we treat ENOENT / EINVAL / EPERM as "unsupported in this
	 * config" and emit NOTE instead of failing.
	 */
	char src[64], dst[64];
	snprintf(src, sizeof(src), "t_ln.e.%ld", (long)getpid());
	snprintf(dst, sizeof(dst), "t_ln.f.%ld", (long)getpid());
	unlink(src); unlink(dst);

	if (write_tiny(src, "e\n") < 0) return;

	int fd = open(src, O_RDONLY);
	if (fd < 0) {
		complain("case6: open: %s", strerror(errno));
		unlink(src);
		return;
	}

	errno = 0;
	int rc = linkat(fd, "", AT_FDCWD, dst, AT_EMPTY_PATH);
	if (rc != 0) {
		if (errno == ENOENT || errno == EINVAL || errno == EPERM) {
			if (!Sflag)
				printf("NOTE: %s: case6 linkat AT_EMPTY_PATH "
				       "returned %s (kernel/mount config)\n",
				       myname, strerror(errno));
		} else {
			complain("case6: linkat AT_EMPTY_PATH: %s",
				 strerror(errno));
		}
		close(fd);
		unlink(src);
		return;
	}
	close(fd);

	struct stat st_src, st_dst;
	if (stat(src, &st_src) == 0 && stat(dst, &st_dst) == 0
	    && st_src.st_ino != st_dst.st_ino) {
		complain("case6: AT_EMPTY_PATH link has different ino");
	}
	unlink(src);
	unlink(dst);
#endif
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
		"link/linkat -> NFSv4 LINK (RFC 7530 S18.14)");
	cd_or_skip(myname, dir, Nflag);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	case_basic_link();
	case_shared_contents();
	case_unlink_nlink();
	case_link_to_existing();
	case_link_to_symlink();
	case_link_at_empty_path();

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}
