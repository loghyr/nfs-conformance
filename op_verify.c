/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_verify.c -- exercise NFSv4 VERIFY / NVERIFY ops (RFC 7530
 * S18.28 / S18.19) via the POSIX stat surface.
 *
 * VERIFY and NVERIFY are server-side attribute predicates: VERIFY
 * succeeds when stated attributes match the current file state;
 * NVERIFY succeeds when they don't.  The Linux NFS client uses
 * them for attribute cache validation (particularly change_attr).
 *
 * We can't issue raw VERIFY/NVERIFY from userspace, but we can
 * observe the semantics by exercising attribute consistency:
 *
 * Cases:
 *
 *   1. Stat consistency.  stat() a file twice in succession;
 *      verify st_ino, st_mode, st_uid, st_gid, st_size are
 *      identical (no one else is modifying the file).
 *      (POSIX.1-1990 stat() S5.6.2)
 *
 *   2. Size after write.  Create a file, write N bytes, fstat,
 *      close, stat by name -- sizes must match exactly.
 *      (POSIX.1-1990 stat() S5.6.2: "st_size ... total size of
 *      the file in bytes"; write() S6.4.2: updates st_size)
 *
 *   3. Mode after chmod.  Create 0644, chmod to 0600, stat;
 *      verify st_mode & 07777 == 0600.
 *      (POSIX.1-1990 chmod() S5.6.4: "Upon successful completion,
 *      chmod() shall set the access permission bits")
 *
 *   4. Mtime after write.  stat before write, write, stat after
 *      write.  Mtime after must be >= mtime before.
 *      (POSIX.1-1990 write() S6.4.2: "Upon successful completion,
 *      where nbyte is greater than 0, write() shall mark for
 *      update the st_mtime and st_ctime fields of the file")
 *
 *   5. Change-attr monotonicity.  On Linux with statx, verify
 *      STATX_CHANGE_COOKIE (stx_change_attr) increments after a
 *      write.  Skipped on non-Linux or kernels without statx
 *      change-attr support.
 *      (Linux-specific: statx(2) STATX_CHANGE_COOKIE, Linux 6.6+;
 *      maps to NFSv4 change_attr4 attribute)
 *
 *   6. Uid/Gid preserved.  Create a file, fchown to current
 *      uid/gid (no-op chown), stat, verify uid/gid unchanged.
 *      Exercises the SETATTR->GETATTR->VERIFY cycle the client
 *      runs internally after chown.
 *      (POSIX.1-1990 chown() S5.6.5: "The file's user and group
 *      IDs shall be set")
 *
 * Portable: POSIX.1-1990 S5.6.2 (stat) across Linux / FreeBSD /
 * macOS / Solaris.  Case 5 is Linux-only (statx).
 */

#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE

#include "tests.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifdef __linux__
#include <sys/syscall.h>
#include <linux/stat.h>
#endif

int Hflag = 0;
int Sflag = 0;
int Tflag = 0;
int Fflag = 0;
int Nflag = 0;

static const char *myname = "op_verify";

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  exercise attribute consistency -> NFSv4 VERIFY/NVERIFY "
		"(RFC 7530 S18.28/S18.19)\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

static void case_stat_consistency(void)
{
	char name[64];
	snprintf(name, sizeof(name), "t_vf.sc.%ld", (long)getpid());
	unlink(name);

	int fd = open(name, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("case1: open: %s", strerror(errno));
		return;
	}
	close(fd);

	struct stat s1, s2;
	if (stat(name, &s1) != 0 || stat(name, &s2) != 0) {
		complain("case1: stat: %s", strerror(errno));
		unlink(name);
		return;
	}

	if (s1.st_ino != s2.st_ino)
		complain("case1: st_ino changed between two stats");
	if (s1.st_mode != s2.st_mode)
		complain("case1: st_mode changed between two stats");
	if (s1.st_uid != s2.st_uid)
		complain("case1: st_uid changed");
	if (s1.st_gid != s2.st_gid)
		complain("case1: st_gid changed");
	if (s1.st_size != s2.st_size)
		complain("case1: st_size changed");

	unlink(name);
}

static void case_size_after_write(void)
{
	char name[64];
	snprintf(name, sizeof(name), "t_vf.sz.%ld", (long)getpid());
	unlink(name);

	int fd = open(name, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("case2: open: %s", strerror(errno));
		return;
	}

	char buf[1234];
	memset(buf, 'V', sizeof(buf));
	ssize_t w = write(fd, buf, sizeof(buf));
	if (w != (ssize_t)sizeof(buf)) {
		complain("case2: short write (%zd)", w);
		close(fd);
		unlink(name);
		return;
	}

	struct stat st_fd, st_name;
	if (fstat(fd, &st_fd) != 0) {
		complain("case2: fstat: %s", strerror(errno));
		close(fd);
		unlink(name);
		return;
	}
	close(fd);

	if (stat(name, &st_name) != 0) {
		complain("case2: stat: %s", strerror(errno));
		unlink(name);
		return;
	}

	if (st_fd.st_size != (off_t)sizeof(buf))
		complain("case2: fstat size %lld, expected %zu",
			 (long long)st_fd.st_size, sizeof(buf));
	if (st_name.st_size != st_fd.st_size)
		complain("case2: stat size %lld != fstat size %lld",
			 (long long)st_name.st_size,
			 (long long)st_fd.st_size);

	unlink(name);
}

static void case_mode_after_chmod(void)
{
	char name[64];
	snprintf(name, sizeof(name), "t_vf.md.%ld", (long)getpid());
	unlink(name);

	int fd = open(name, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("case3: open: %s", strerror(errno));
		return;
	}
	close(fd);

	if (chmod(name, 0600) != 0) {
		complain("case3: chmod: %s", strerror(errno));
		unlink(name);
		return;
	}

	struct stat st;
	if (stat(name, &st) != 0) {
		complain("case3: stat: %s", strerror(errno));
		unlink(name);
		return;
	}

	if ((st.st_mode & 07777) != 0600)
		complain("case3: mode after chmod 0600 is 0%o",
			 st.st_mode & 07777);

	unlink(name);
}

static void case_mtime_after_write(void)
{
	char name[64];
	snprintf(name, sizeof(name), "t_vf.mt.%ld", (long)getpid());
	unlink(name);

	int fd = open(name, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("case4: open: %s", strerror(errno));
		return;
	}

	struct stat st_before;
	if (fstat(fd, &st_before) != 0) {
		complain("case4: fstat before: %s", strerror(errno));
		close(fd);
		unlink(name);
		return;
	}

	/* Small delay to ensure mtime can advance. */
	usleep(50000);

	char buf[64];
	memset(buf, 'M', sizeof(buf));
	if (write(fd, buf, sizeof(buf)) != (ssize_t)sizeof(buf)) {
		complain("case4: write: %s", strerror(errno));
		close(fd);
		unlink(name);
		return;
	}

	struct stat st_after;
	if (fstat(fd, &st_after) != 0) {
		complain("case4: fstat after: %s", strerror(errno));
		close(fd);
		unlink(name);
		return;
	}

	if (st_after.st_mtime < st_before.st_mtime)
		complain("case4: mtime went backwards after write");

	close(fd);
	unlink(name);
}

static void case_change_attr(void)
{
#ifndef __linux__
	if (!Sflag)
		printf("NOTE: %s: case5 skipped (statx not available on "
		       "this platform)\n", myname);
	return;
#else
	/*
	 * Use raw syscall + raw buffer to avoid compile-time dependency
	 * on a kernel that defines stx_change_attr (added in 6.6).
	 * STATX_CHANGE_COOKIE = 0x40000000, and stx_change_attr sits
	 * at byte offset 40 in struct statx as a __u64.
	 */
#ifndef STATX_CHANGE_COOKIE
#define STATX_CHANGE_COOKIE 0x40000000U
#endif
#define STX_CHANGE_ATTR_OFF 40

	char name[64];
	snprintf(name, sizeof(name), "t_vf.ca.%ld", (long)getpid());
	unlink(name);

	int fd = open(name, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("case5: open: %s", strerror(errno));
		return;
	}

	unsigned char sx1[256];
	memset(sx1, 0, sizeof(sx1));
	if (syscall(SYS_statx, AT_FDCWD, name, 0,
		    STATX_CHANGE_COOKIE, sx1) != 0) {
		if (errno == ENOSYS || errno == EINVAL) {
			if (!Sflag)
				printf("NOTE: %s: case5 skipped (statx/"
				       "CHANGE_COOKIE not supported)\n",
				       myname);
			close(fd);
			unlink(name);
			return;
		}
		complain("case5: statx before: %s", strerror(errno));
		close(fd);
		unlink(name);
		return;
	}

	/* stx_mask is at offset 0 as a __u32. */
	uint32_t mask1;
	memcpy(&mask1, sx1, sizeof(mask1));
	if (!(mask1 & STATX_CHANGE_COOKIE)) {
		if (!Sflag)
			printf("NOTE: %s: case5 skipped (kernel did not "
			       "return STATX_CHANGE_COOKIE)\n", myname);
		close(fd);
		unlink(name);
		return;
	}

	uint64_t ca1;
	memcpy(&ca1, sx1 + STX_CHANGE_ATTR_OFF, sizeof(ca1));

	char buf[64];
	memset(buf, 'C', sizeof(buf));
	if (write(fd, buf, sizeof(buf)) != (ssize_t)sizeof(buf)) {
		complain("case5: write: %s", strerror(errno));
		close(fd);
		unlink(name);
		return;
	}
	close(fd);

	unsigned char sx2[256];
	memset(sx2, 0, sizeof(sx2));
	if (syscall(SYS_statx, AT_FDCWD, name, 0,
		    STATX_CHANGE_COOKIE, sx2) != 0) {
		complain("case5: statx after: %s", strerror(errno));
		unlink(name);
		return;
	}

	uint64_t ca2;
	memcpy(&ca2, sx2 + STX_CHANGE_ATTR_OFF, sizeof(ca2));

	if (ca2 <= ca1)
		complain("case5: change_attr did not increase after write "
			 "(before=%llu, after=%llu)",
			 (unsigned long long)ca1,
			 (unsigned long long)ca2);

	unlink(name);
#endif
}

static void case_uid_gid_preserved(void)
{
	char name[64];
	snprintf(name, sizeof(name), "t_vf.ug.%ld", (long)getpid());
	unlink(name);

	int fd = open(name, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("case6: open: %s", strerror(errno));
		return;
	}

	uid_t myuid = getuid();
	gid_t mygid = getgid();

	/* No-op chown to exercise SETATTR->GETATTR->VERIFY cycle. */
	if (fchown(fd, myuid, mygid) != 0) {
#ifdef __linux__
		if (errno == EINVAL) {
			if (!Sflag)
				printf("NOTE: %s: case6 fchown returned EINVAL "
				       "(client-side idmap cannot resolve uid %u; "
				       "start rpc.idmapd or set "
				       "nfs4_disable_idmapping=Y)\n",
				       myname, (unsigned)myuid);
		} else {
			complain("case6: fchown: %s", strerror(errno));
		}
#else
		complain("case6: fchown: %s", strerror(errno));
#endif
		close(fd);
		unlink(name);
		return;
	}

	struct stat st;
	if (fstat(fd, &st) != 0) {
		complain("case6: fstat: %s", strerror(errno));
		close(fd);
		unlink(name);
		return;
	}

	if (st.st_uid != myuid)
		complain("case6: uid %u, expected %u",
			 (unsigned)st.st_uid, (unsigned)myuid);
	if (st.st_gid != mygid)
		complain("case6: gid %u, expected %u",
			 (unsigned)st.st_gid, (unsigned)mygid);

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

	prelude(myname,
		"stat attribute consistency -> NFSv4 VERIFY/NVERIFY "
		"(RFC 7530 S18.28/S18.19)");
	cd_or_skip(myname, dir, Nflag);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_stat_consistency", case_stat_consistency());
	RUN_CASE("case_size_after_write", case_size_after_write());
	RUN_CASE("case_mode_after_chmod", case_mode_after_chmod());
	RUN_CASE("case_mtime_after_write", case_mtime_after_write());
	RUN_CASE("case_change_attr", case_change_attr());
	RUN_CASE("case_uid_gid_preserved", case_uid_gid_preserved());

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}
