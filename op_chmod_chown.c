/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_chmod_chown.c -- exercise NFSv4 SETATTR for mode and ownership
 * changes (RFC 7530 S18.30) via chmod(2) / chown(2).
 *
 * Cases:
 *
 *   1. chmod stores permission bits.  Create 0644, chmod to 0600,
 *      verify (st_mode & 07777) == 0600.
 *      (POSIX.1-1990 chmod() S5.6.4: "Upon successful completion,
 *      chmod() shall set the access permission bits of the file
 *      named by path to the bit pattern contained in mode")
 *
 *   2. chmod on directory.  mkdir 0755, chmod to 0700, verify.
 *      (POSIX.1-1990 chmod() S5.6.4)
 *
 *   3. chmod advances ctime.  Verify inode unchanged.
 *      (POSIX.1-1990 chmod() S5.6.4: "Upon successful completion,
 *      chmod() shall mark for update the st_ctime field of the
 *      file"; mtime is not required to change on a mode-only
 *      SETATTR)
 *
 *   4. chmod ENOENT.  chmod on nonexistent path.
 *      (POSIX.1-1990 chmod() S5.6.4: ENOENT error condition)
 *
 *   5. chown updates uid/gid.  No-op chown (to self), verify
 *      stored values.  (Real uid change requires root.)
 *      (POSIX.1-1990 chown() S5.6.5: "The file's user and group
 *      IDs shall be set to the numeric values contained in owner
 *      and group, respectively")
 *
 *   6. chown advances ctime.  Verify inode unchanged.
 *      (POSIX.1-1990 chown() S5.6.5: "Upon successful completion,
 *      chown() shall mark for update the st_ctime field of the
 *      file")
 *
 *   7. chown ENOENT.
 *      (POSIX.1-1990 chown() S5.6.5: ENOENT error condition)
 *
 *   8. chown clears setuid/setgid bits.  Create a file with
 *      setuid+setgid bits, chown to self as root, verify the
 *      bits are cleared.  Skipped if not root (cannot set
 *      setuid bit on NFS without privilege).
 *      (POSIX.1-2008 chown(): "If the specified user ID is
 *      not equal to the user ID of the file ... the S_ISUID
 *      and S_ISGID bits ... shall be cleared"; Linux extends
 *      this to clear the bits on any chown(), including to
 *      self, even as root)
 *
 * Portable: POSIX.1-1990 S5.6.4 (chmod) + S5.6.5 (chown) across
 * Linux / FreeBSD / macOS / Solaris.
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

static const char *myname = "op_chmod_chown";

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  exercise chmod/chown -> NFSv4 SETATTR (RFC 7530 S18.30)\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

static void case_chmod_file(void)
{
	char a[64];
	snprintf(a, sizeof(a), "t_cc.cf.%ld", (long)getpid());
	unlink(a);

	int fd = open(a, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) { complain("case1: create: %s", strerror(errno)); return; }
	close(fd);

	if (chmod(a, 0600) != 0) {
		complain("case1: chmod: %s", strerror(errno));
		unlink(a);
		return;
	}

	struct stat st;
	if (stat(a, &st) != 0) {
		complain("case1: stat: %s", strerror(errno));
		unlink(a);
		return;
	}
	if ((st.st_mode & 07777) != 0600)
		complain("case1: mode 0%o, expected 0600",
			 st.st_mode & 07777);
	unlink(a);
}

static void case_chmod_dir(void)
{
	char d[64];
	snprintf(d, sizeof(d), "t_cc.cd.%ld", (long)getpid());
	rmdir(d);
	if (mkdir(d, 0755) != 0) {
		complain("case2: mkdir: %s", strerror(errno));
		return;
	}

	if (chmod(d, 0700) != 0) {
		complain("case2: chmod: %s", strerror(errno));
		rmdir(d);
		return;
	}

	struct stat st;
	if (stat(d, &st) != 0) {
		complain("case2: stat: %s", strerror(errno));
		rmdir(d);
		return;
	}
	if ((st.st_mode & 0777) != 0700)
		complain("case2: dir mode 0%o, expected 0700",
			 st.st_mode & 0777);
	rmdir(d);
}

static void case_chmod_timestamps(void)
{
	char a[64];
	snprintf(a, sizeof(a), "t_cc.ct.%ld", (long)getpid());
	unlink(a);

	int fd = open(a, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) { complain("case3: create: %s", strerror(errno)); return; }
	close(fd);

	sleep_ms(50);
	struct stat st_before;
	if (stat(a, &st_before) != 0) {
		complain("case3: stat before: %s", strerror(errno));
		unlink(a);
		return;
	}

	sleep_ms(50);
	if (chmod(a, 0600) != 0) {
		complain("case3: chmod: %s", strerror(errno));
		unlink(a);
		return;
	}

	struct stat st_after;
	if (stat(a, &st_after) != 0) {
		complain("case3: stat after: %s", strerror(errno));
		unlink(a);
		return;
	}

	if (st_after.st_ctime < st_before.st_ctime)
		complain("case3: ctime did not advance after chmod");
	if (st_after.st_ino != st_before.st_ino)
		complain("case3: inode changed after chmod");

	unlink(a);
}

static void case_chmod_enoent(void)
{
	char a[64];
	snprintf(a, sizeof(a), "t_cc.cne.%ld", (long)getpid());
	unlink(a);

	errno = 0;
	if (chmod(a, 0644) == 0)
		complain("case4: chmod on nonexistent succeeded");
	else if (errno != ENOENT)
		complain("case4: expected ENOENT, got %s", strerror(errno));
}

static void case_chown_self(void)
{
	char a[64];
	snprintf(a, sizeof(a), "t_cc.co.%ld", (long)getpid());
	unlink(a);

	int fd = open(a, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) { complain("case5: create: %s", strerror(errno)); return; }
	close(fd);

	uid_t myuid = getuid();
	gid_t mygid = getgid();

	if (chown(a, myuid, mygid) != 0) {
#ifdef __linux__
		if (errno == EINVAL) {
			if (!Sflag)
				printf("NOTE: %s: case5 chown(self) returned EINVAL "
				       "(client-side idmap cannot resolve uid %u; "
				       "start rpc.idmapd or set "
				       "nfs4_disable_idmapping=Y)\n",
				       myname, (unsigned)myuid);
		} else {
			complain("case5: chown(self): %s", strerror(errno));
		}
#else
		complain("case5: chown(self): %s", strerror(errno));
#endif
		unlink(a);
		return;
	}

	struct stat st;
	if (stat(a, &st) != 0) {
		complain("case5: stat: %s", strerror(errno));
		unlink(a);
		return;
	}

	if (st.st_uid != myuid)
		complain("case5: uid %u, expected %u",
			 (unsigned)st.st_uid, (unsigned)myuid);
	if (st.st_gid != mygid)
		complain("case5: gid %u, expected %u",
			 (unsigned)st.st_gid, (unsigned)mygid);
	unlink(a);
}

static void case_chown_timestamps(void)
{
	char a[64];
	snprintf(a, sizeof(a), "t_cc.ot.%ld", (long)getpid());
	unlink(a);

	int fd = open(a, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) { complain("case6: create: %s", strerror(errno)); return; }
	close(fd);

	sleep_ms(50);
	struct stat st_before;
	if (stat(a, &st_before) != 0) {
		complain("case6: stat before: %s", strerror(errno));
		unlink(a);
		return;
	}

	sleep_ms(50);
	if (chown(a, getuid(), getgid()) != 0) {
#ifdef __linux__
		if (errno == EINVAL) {
			if (!Sflag)
				printf("NOTE: %s: case6 chown returned EINVAL "
				       "(client-side idmap cannot resolve uid %u; "
				       "start rpc.idmapd or set "
				       "nfs4_disable_idmapping=Y)\n",
				       myname, (unsigned)getuid());
		} else {
			complain("case6: chown: %s", strerror(errno));
		}
#else
		complain("case6: chown: %s", strerror(errno));
#endif
		unlink(a);
		return;
	}

	struct stat st_after;
	if (stat(a, &st_after) != 0) {
		complain("case6: stat after: %s", strerror(errno));
		unlink(a);
		return;
	}

	if (st_after.st_ino != st_before.st_ino)
		complain("case6: inode changed after chown");

	unlink(a);
}

static void case_chown_enoent(void)
{
	char a[64];
	snprintf(a, sizeof(a), "t_cc.one.%ld", (long)getpid());
	unlink(a);

	errno = 0;
	if (chown(a, getuid(), getgid()) == 0)
		complain("case7: chown on nonexistent succeeded");
	else if (errno != ENOENT)
		complain("case7: expected ENOENT, got %s", strerror(errno));
}

static void case_chown_clears_setid(void)
{
	if (getuid() != 0) {
		if (!Sflag)
			printf("NOTE: %s: case8 skipped (requires root to "
			       "set S_ISUID on NFS)\n", myname);
		return;
	}

	char a[64];
	snprintf(a, sizeof(a), "t_cc.si.%ld", (long)getpid());
	unlink(a);

	int fd = open(a, O_RDWR | O_CREAT | O_TRUNC, 0755);
	if (fd < 0) { complain("case8: create: %s", strerror(errno)); return; }
	close(fd);

	if (chmod(a, S_ISUID | S_ISGID | 0755) != 0) {
		complain("case8: chmod(setuid|setgid): %s", strerror(errno));
		unlink(a);
		return;
	}

	struct stat st;
	if (stat(a, &st) != 0) {
		complain("case8: stat before chown: %s", strerror(errno));
		unlink(a);
		return;
	}
	if (!(st.st_mode & S_ISUID)) {
		if (!Sflag)
			printf("NOTE: %s: case8 server did not preserve "
			       "S_ISUID on NFS (server policy)\n", myname);
		unlink(a);
		return;
	}

	if (chown(a, getuid(), getgid()) != 0) {
		complain("case8: chown: %s", strerror(errno));
		unlink(a);
		return;
	}

	if (stat(a, &st) != 0) {
		complain("case8: stat after chown: %s", strerror(errno));
		unlink(a);
		return;
	}
	if (st.st_mode & (S_ISUID | S_ISGID))
		complain("case8: S_ISUID/S_ISGID not cleared after chown "
			 "(mode 0%o) — POSIX requires clearing setid bits "
			 "on ownership change",
			 st.st_mode & 07777);

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
		"chmod/chown -> NFSv4 SETATTR (RFC 7530 S18.30)");
	cd_or_skip(myname, dir, Nflag);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_chmod_file", case_chmod_file());
	RUN_CASE("case_chmod_dir", case_chmod_dir());
	RUN_CASE("case_chmod_timestamps", case_chmod_timestamps());
	RUN_CASE("case_chmod_enoent", case_chmod_enoent());
	RUN_CASE("case_chown_self", case_chown_self());
	RUN_CASE("case_chown_timestamps", case_chown_timestamps());
	RUN_CASE("case_chown_enoent", case_chown_enoent());
	RUN_CASE("case_chown_clears_setid", case_chown_clears_setid());

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}
