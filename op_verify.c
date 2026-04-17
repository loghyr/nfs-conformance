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
 *   5. Uid/Gid preserved.  Create a file, fchown to current
 *      uid/gid (no-op chown), stat, verify uid/gid unchanged.
 *      Exercises the SETATTR->GETATTR->VERIFY cycle the client
 *      runs internally after chown.
 *      (POSIX.1-1990 chown() S5.6.5: "The file's user and group
 *      IDs shall be set")
 *
 * Portable: POSIX.1-1990 S5.6.2 (stat) across Linux / FreeBSD /
 * macOS / Solaris.
 *
 * (The former case 5, change-attr monotonicity via raw statx, was
 * removed: its hand-rolled byte offset into struct statx pointed at
 * stx_size, not stx_change_attr, so every write produced a spurious
 * "PASS" regardless of server behaviour.  op_change_attr.c exercises
 * STATX_CHANGE_COOKIE correctly via the typed kernel header.)
 */

#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE
#if defined(__APPLE__)
# define _DARWIN_C_SOURCE /* exposes struct stat st_mtimespec */
#endif

#include "tests.h"

/* struct stat timespec field names differ between Linux (st_mtim)
 * and Darwin/BSD (st_mtimespec). */
#ifdef __APPLE__
# define ST_MTIM(s) ((s).st_mtimespec)
#else
# define ST_MTIM(s) ((s).st_mtim)
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
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
	sleep_ms(50);

	char buf[64];
	memset(buf, 'M', sizeof(buf));
	if (write(fd, buf, sizeof(buf)) != (ssize_t)sizeof(buf)) {
		complain("case4: write: %s", strerror(errno));
		close(fd);
		unlink(name);
		return;
	}

	/*
	 * Flush write to server before fstat.  On NFS clients that buffer
	 * writes (e.g., FreeBSD), the server has not yet updated mtime when
	 * fstat is called without an intervening flush; fsync forces a COMMIT
	 * so the server mtime is current when we read it back.
	 */
	if (fsync(fd) != 0) {
		complain("case4: fsync: %s", strerror(errno));
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

	/*
	 * POSIX requires mtime advance on write.  Use nsec precision
	 * so a write that lands in the same wall-clock second as the
	 * pre-write stat still registers as advancement.  The old
	 * second-precision < comparison only caught regressions, not
	 * non-advancement.
	 */
	if (ST_MTIM(st_after).tv_sec < ST_MTIM(st_before).tv_sec
	    || (ST_MTIM(st_after).tv_sec == ST_MTIM(st_before).tv_sec
		&& ST_MTIM(st_after).tv_nsec <= ST_MTIM(st_before).tv_nsec))
		complain("case4: mtime did not advance after write "
			 "(%lld.%09ld -> %lld.%09ld)",
			 (long long)ST_MTIM(st_before).tv_sec,
			 ST_MTIM(st_before).tv_nsec,
			 (long long)ST_MTIM(st_after).tv_sec,
			 ST_MTIM(st_after).tv_nsec);

	close(fd);
	unlink(name);
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
	RUN_CASE("case_uid_gid_preserved", case_uid_gid_preserved());

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}
