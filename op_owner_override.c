/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_owner_override.c -- exercise owner-override semantics on files
 * the caller owns, testing both strict-POSIX and Linux-extended
 * compliance.
 *
 * Compliance modes  (-P / -L flags)
 * ----------------------------------
 *
 * Each case in this test is tagged with the standard that REQUIRES
 * the tested behaviour:
 *
 *   [POSIX]  Behaviour mandated by IEEE Std 1003.1.  Any server
 *            claiming POSIX conformance must exhibit this.
 *
 *   [LINUX]  Behaviour required by the Linux VFS and expected by
 *            Linux userspace (git, editors, package managers).  A
 *            strictly POSIX-only server may not implement this;
 *            the Linux NFS client will work around it (e.g., the
 *            kernel's access cache heuristic for owner permission).
 *
 * The test accepts a -P flag (strict POSIX) or -L flag (Linux; the
 * default).  The flag controls how "grey zone" cases are judged:
 *
 *   In -L (Linux) mode:
 *     - [POSIX] cases: FAIL if the server violates POSIX.
 *     - [LINUX] cases: FAIL if the server violates Linux semantics.
 *     - Cases where Linux extends POSIX: the Linux-extended outcome
 *       is expected; the POSIX-strict outcome is also acceptable
 *       (printed as NOTE).
 *
 *   In -P (POSIX) mode:
 *     - [POSIX] cases: FAIL if the server violates POSIX.
 *     - [LINUX] cases: the Linux-extended outcome is acceptable
 *       (printed as NOTE); the POSIX-strict outcome is expected.
 *
 * Default is -L because nfs-conformance primarily targets Linux NFS testing.
 *
 *
 * Background
 * ----------
 *
 * POSIX specifies that write access to a file requires the file's
 * permission bits to grant write to the caller (via user, group, or
 * other class).  A file with mode 0444 should be unwritable by
 * everyone except the superuser.
 *
 * Linux extends this model in ways that git and other tools depend on.
 * The file OWNER retains implicit rights:
 *
 *   - The owner can always chmod(2) their own files.  [POSIX — the
 *     owner has implicit SETATTR authority per IEEE 1003.1 S4.11.1.]
 *
 *   - The owner can unlink(2) / rename(2) files from a directory
 *     they have write permission on, regardless of the file's own
 *     permission bits.  [POSIX — unlink and rename check the
 *     directory's write+execute permission, not the file's.]
 *
 *   - An fd opened O_RDWR retains write access even after the file
 *     is chmod'd to 0444.  [POSIX — the open grants access; chmod
 *     does not revoke an existing open.]
 *
 *   - On some Linux NFS servers, the ACCESS operation returns
 *     "writable" for the owner of a 0444 file.  [LINUX — not
 *     POSIX-required; a pragmatic optimisation.]
 *
 *   - Some Linux NFS servers allow the owner to open(O_WRONLY) a
 *     0444 file directly.  [LINUX — not POSIX-required.]
 *
 *   - Some Linux NFS servers allow the owner to truncate(path) a
 *     0444 file.  [LINUX — POSIX says truncate checks permission
 *     bits, so EACCES is the conformant answer.]
 *
 *
 * Real-world impact: git
 * ----------------------
 *
 * git creates pack files and loose objects as mode 0444 (read-only)
 * to signal immutability.  But git gc and git repack unlink the old
 * 0444 file and create a new one — which works because POSIX says
 * unlink checks directory write permission, not file permission.
 *
 * On an NFS server that incorrectly enforces file permission bits on
 * REMOVE (checking file write permission instead of directory write
 * permission), git gc fails with EACCES.  This is a server bug under
 * BOTH POSIX and Linux standards.
 *
 * Editors that save by rename (write tmpfile, rename over original)
 * rely on the same POSIX rename semantics.
 *
 *
 * Cases
 * -----
 *
 *   1. [POSIX] Owner chmod on 0444 file.  The owner has implicit
 *      SETATTR authority (IEEE 1003.1 S4.11.1).  Must succeed.
 *
 *   2. [POSIX] Owner chmod on 0000 file.  Even with all bits
 *      cleared, the owner can restore permissions.  Must succeed.
 *
 *   3. [POSIX] Owner unlink of 0444 file.  POSIX: unlink checks
 *      directory write permission, not file permission.  Must
 *      succeed.  This is the git gc path.
 *
 *   4. [POSIX] Owner rename over 0444 file.  Same rule as case 3.
 *      Must succeed.  This is the editor save-by-rename path.
 *
 *   5. [POSIX] Write via pre-opened fd after chmod to 0444.  POSIX:
 *      the open fd retains its access mode; chmod does not revoke
 *      an existing open.  Must succeed.
 *
 *   6. [LINUX] Owner open(O_WRONLY) on 0444 file.
 *      POSIX says: EACCES (permission bits checked at open time).
 *      Linux servers may allow: owner-override policy.
 *      -P mode: EACCES expected; success is a compliance NOTE.
 *      -L mode: either outcome is acceptable.
 *
 *   7. [POSIX] Non-owner access denied.  Fork a child as uid
 *      nobody; it tries to chmod.  Must fail with EPERM.  Confirms
 *      the override is owner-specific.  Requires root.
 *
 *   8. [LINUX] Owner truncate(path) on 0444 file.
 *      POSIX says: EACCES (truncate checks permission bits).
 *      Linux servers may allow: owner truncate.
 *      -P mode: EACCES expected; success is a compliance NOTE.
 *      -L mode: either outcome is acceptable.
 *
 * Portable: Linux / FreeBSD / macOS / Solaris.  Case 7 requires root.
 */

#define _POSIX_C_SOURCE 200809L

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

static const char *myname = "op_owner_override";
static int posix_mode;   /* 1 = -P (strict POSIX), 0 = -L (Linux; default) */

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfnPL] [-d DIR]\n"
		"  exercise owner-override semantics on read-only files\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n"
		"  -P  strict POSIX mode: Linux-extended behaviours are\n"
		"      informational NOTEs; POSIX-strict results are expected\n"
		"  -L  Linux mode (default): both POSIX-strict and\n"
		"      Linux-extended outcomes are acceptable\n",
		myname);
}

static int make_owned_file(const char *tag, char *out, size_t outsz,
			   mode_t mode)
{
	snprintf(out, outsz, "t_oo.%s.%ld", tag, (long)getpid());
	unlink(out);
	int fd = open(out, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("%s: create: %s", tag, strerror(errno));
		return -1;
	}
	char buf[64];
	memset(buf, 'O', sizeof(buf));
	ssize_t w = write(fd, buf, sizeof(buf));
	close(fd);
	if (w != (ssize_t)sizeof(buf)) {
		complain("%s: write %zd / %zu: %s",
			 tag, w, sizeof(buf),
			 w < 0 ? strerror(errno) : "short");
		unlink(out);
		return -1;
	}
	if (chmod(out, mode) != 0) {
		complain("%s: chmod(0%o): %s", tag, mode, strerror(errno));
		unlink(out);
		return -1;
	}
	return 0;
}

/* ---- [POSIX] cases ---- */

static void case_chmod_0444(void)
{
	char name[64];
	if (make_owned_file("c4", name, sizeof(name), 0444) != 0)
		return;

	if (chmod(name, 0644) != 0)
		complain("[POSIX] case1: owner chmod 0444->0644: %s "
			 "(IEEE 1003.1 S4.11.1: owner has implicit SETATTR)",
			 strerror(errno));

	unlink(name);
}

static void case_chmod_0000(void)
{
	char name[64];
	if (make_owned_file("c0", name, sizeof(name), 0000) != 0)
		return;

	if (chmod(name, 0644) != 0)
		complain("[POSIX] case2: owner chmod 0000->0644: %s",
			 strerror(errno));

	chmod(name, 0644);
	unlink(name);
}

static void case_unlink_0444(void)
{
	char name[64];
	if (make_owned_file("ul", name, sizeof(name), 0444) != 0)
		return;

	if (unlink(name) != 0)
		complain("[POSIX] case3: owner unlink of 0444 file: %s "
			 "(POSIX: REMOVE checks directory write permission, "
			 "not file permission; git gc relies on this)",
			 strerror(errno));
}

static void case_rename_over_0444(void)
{
	char old[64], new_name[64];
	if (make_owned_file("ro", old, sizeof(old), 0444) != 0)
		return;

	snprintf(new_name, sizeof(new_name), "t_oo.rn.%ld", (long)getpid());
	unlink(new_name);
	int fd = open(new_name, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("case4: create new: %s", strerror(errno));
		chmod(old, 0644);
		unlink(old);
		return;
	}
	close(fd);

	if (rename(new_name, old) != 0)
		complain("[POSIX] case4: rename over 0444 file: %s "
			 "(POSIX: rename checks directory write permission; "
			 "editor save-by-rename relies on this)",
			 strerror(errno));

	chmod(old, 0644);
	unlink(old);
	unlink(new_name);
}

static void case_write_via_open_fd(void)
{
	char name[64];
	snprintf(name, sizeof(name), "t_oo.wf.%ld", (long)getpid());
	unlink(name);

	int fd = open(name, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("case5: create: %s", strerror(errno));
		return;
	}

	if (chmod(name, 0444) != 0) {
		complain("case5: chmod: %s", strerror(errno));
		close(fd);
		unlink(name);
		return;
	}

	char buf[32];
	memset(buf, 'W', sizeof(buf));
	errno = 0;
	ssize_t w = write(fd, buf, sizeof(buf));
	if (w != (ssize_t)sizeof(buf))
		complain("[POSIX] case5: write via pre-opened fd after chmod "
			 "0444: %s (POSIX: an open fd retains its access mode; "
			 "chmod does not revoke it.  NFS servers that re-check "
			 "permission bits on each WRITE RPC instead of "
			 "honouring the OPEN stateid will fail this)",
			 w < 0 ? strerror(errno) : "short write");

	close(fd);
	chmod(name, 0644);
	unlink(name);
}

/* ---- [LINUX] grey-zone cases ---- */

static void case_open_wronly_0444(void)
{
	char name[64];
	if (make_owned_file("ow", name, sizeof(name), 0444) != 0)
		return;

	errno = 0;
	int fd = open(name, O_WRONLY);
	if (fd >= 0) {
		if (posix_mode) {
			if (!Sflag)
				printf("NOTE: %s: [LINUX] case6 "
				       "open(O_WRONLY) on owner's 0444 file "
				       "succeeded (Linux owner-override — "
				       "not POSIX-required; strict POSIX "
				       "expects EACCES)\n", myname);
		}
		close(fd);
	} else if (errno == EACCES) {
		if (!posix_mode && !Sflag)
			printf("NOTE: %s: [POSIX] case6 open(O_WRONLY) "
			       "on owner's 0444 file returned EACCES "
			       "(strict POSIX behaviour; Linux servers "
			       "may allow this as an owner-override)\n",
			       myname);
	} else {
		complain("case6: expected EACCES (or success under Linux "
			 "owner-override), got %s", strerror(errno));
	}

	chmod(name, 0644);
	unlink(name);
}

static void case_nonowner_denied(void)
{
	if (getuid() != 0) {
		if (!Sflag)
			printf("NOTE: %s: case7 skipped (requires root to "
			       "create non-owner context via setuid)\n",
			       myname);
		return;
	}

	char name[64];
	if (make_owned_file("no", name, sizeof(name), 0444) != 0)
		return;

	pid_t pid = fork();
	if (pid < 0) {
		complain("case7: fork: %s", strerror(errno));
		chmod(name, 0644);
		unlink(name);
		return;
	}

	if (pid == 0) {
		if (setgid(65534) != 0 || setuid(65534) != 0)
			_exit(2);
		errno = 0;
		if (chmod(name, 0644) == 0)
			_exit(1);
		if (errno == EPERM)
			_exit(0);
		_exit(3);
	}

	int status;
	waitpid(pid, &status, 0);
	if (WIFEXITED(status)) {
		switch (WEXITSTATUS(status)) {
		case 0:
			break;
		case 1:
			complain("[POSIX] case7: non-owner (nobody) chmod on "
				 "0444 file succeeded — owner override must "
				 "be owner-specific, not universal");
			break;
		case 2:
			if (!Sflag)
				printf("NOTE: %s: case7 setuid to nobody "
				       "failed (NFS root_squash may prevent "
				       "this)\n", myname);
			break;
		default:
			complain("case7: non-owner chmod returned unexpected "
				 "errno (child exit %d)",
				 WEXITSTATUS(status));
		}
	} else {
		complain("case7: child did not exit normally");
	}

	chmod(name, 0644);
	unlink(name);
}

static void case_truncate_path_0444(void)
{
	char name[64];
	if (make_owned_file("tp", name, sizeof(name), 0444) != 0)
		return;

	errno = 0;
	if (truncate(name, 0) == 0) {
		if (posix_mode) {
			if (!Sflag)
				printf("NOTE: %s: [LINUX] case8 "
				       "truncate(path) on owner's 0444 file "
				       "succeeded (Linux owner-override; "
				       "strict POSIX expects EACCES)\n",
				       myname);
		}
	} else if (errno == EACCES) {
		if (!posix_mode && !Sflag)
			printf("NOTE: %s: [POSIX] case8 truncate(path) "
			       "on owner's 0444 file returned EACCES "
			       "(strict POSIX behaviour; some Linux NFS "
			       "servers allow owner truncate)\n",
			       myname);
	} else {
		complain("case8: expected EACCES (or success under Linux "
			 "owner-override), got %s", strerror(errno));
	}

	chmod(name, 0644);
	unlink(name);
}

int main(int argc, char **argv)
{
	const char *dir = ".";
	struct timespec t0, t1;
	posix_mode = 0;

	while (--argc > 0 && argv[1][0] == '-') {
		argv++;
		for (const char *p = &argv[0][1]; *p; p++) {
			switch (*p) {
			case 'h': Hflag = 1; break;
			case 's': Sflag = 1; break;
			case 't': Tflag = 1; break;
			case 'f': Fflag = 1; break;
			case 'n': Nflag = 1; break;
			case 'P': posix_mode = 1; break;
			case 'L': posix_mode = 0; break;
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

	if (!Sflag)
		printf("MODE: %s: %s compliance "
		       "(-P for strict POSIX, -L for Linux)\n",
		       myname, posix_mode ? "POSIX" : "Linux");

	prelude(myname,
		"owner-override semantics on read-only files "
		"(chmod/unlink/rename; -P POSIX / -L Linux)");
	cd_or_skip(myname, dir, Nflag);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("[POSIX] case_chmod_0444", case_chmod_0444());
	RUN_CASE("[POSIX] case_chmod_0000", case_chmod_0000());
	RUN_CASE("[POSIX] case_unlink_0444", case_unlink_0444());
	RUN_CASE("[POSIX] case_rename_over_0444", case_rename_over_0444());
	RUN_CASE("[POSIX] case_write_via_open_fd", case_write_via_open_fd());
	RUN_CASE("[LINUX] case_open_wronly_0444", case_open_wronly_0444());
	RUN_CASE("[POSIX] case_nonowner_denied", case_nonowner_denied());
	RUN_CASE("[LINUX] case_truncate_path_0444", case_truncate_path_0444());

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}
