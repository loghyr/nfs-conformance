/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_owner_override.c -- exercise the Linux owner-override semantics
 * that go beyond strict POSIX permission checking.
 *
 * Background
 * ----------
 *
 * POSIX specifies that write access to a file requires the file's
 * permission bits to grant write to the caller (via user, group, or
 * other class).  A file with mode 0444 should be unwritable by
 * everyone except the superuser.
 *
 * Linux extends this model in a critical way: the **file owner**
 * retains implicit rights that POSIX does not require:
 *
 *   1. The owner can always chmod(2) their own files, regardless of
 *      the current permission bits.  A 0000 file can be chmod'd to
 *      0644 by its owner.  This is the POSIX SETATTR semantic (the
 *      owner has implicit SETATTR authority), but its practical
 *      consequence is that the owner can always *restore* write
 *      access even after revoking it.
 *
 *   2. The owner can always unlink(2) / rename(2) their own files
 *      from a directory they have write permission on, regardless of
 *      the file's permission bits.  (This is POSIX: unlink checks
 *      directory write permission, not file permission.  But many
 *      users are surprised by it, and NFS servers must implement it
 *      correctly for tools like git to work.)
 *
 *   3. The owner can always ftruncate(2) an fd they opened with
 *      O_WRONLY or O_RDWR, even if the file's permission bits were
 *      changed to 0444 *after* the open.  The open grants access;
 *      a later chmod does not revoke it.  (This is POSIX fd
 *      semantics, but NFS servers sometimes get it wrong because the
 *      server-side permission check happens on each RPC, not just at
 *      OPEN time.)
 *
 *   4. On some Linux NFS servers, the ACCESS operation (which the
 *      client calls to populate its access cache) returns "writable"
 *      for the owner of a 0444 file, because the server recognises
 *      that the owner can chmod + write.  This is a pragmatic
 *      optimisation that avoids an EACCES / chmod / retry dance,
 *      but it is not POSIX-required.
 *
 * Real-world impact: git
 * ----------------------
 *
 * git relies heavily on these semantics.  Pack files and loose
 * objects are created mode 0444 (read-only) to signal immutability.
 * But git gc and git repack need to replace them.  They do so by
 * unlinking the old 0444 file and creating a new one -- which works
 * because the owner has directory write permission.  On an NFS
 * mount where the server incorrectly enforces file permission bits
 * on REMOVE (checking file write permission instead of directory
 * write permission), git gc fails with EACCES.
 *
 * Similarly, editors that save by rename (write tmpfile, rename over
 * original) rely on the owner being able to rename over a 0444 file
 * in a writable directory.
 *
 * Cases
 * -----
 *
 *   1. Owner chmod on 0444 file.  Create a file as the current uid,
 *      chmod to 0444, then chmod to 0644.  Must succeed for the
 *      owner.  This is the fundamental owner SETATTR right.
 *
 *   2. Owner chmod on 0000 file.  Create, chmod to 0000, then
 *      chmod to 0644.  The owner must still be able to restore
 *      permissions even when all bits are cleared.
 *
 *   3. Owner unlink of 0444 file.  Create a file mode 0444, then
 *      unlink it.  Must succeed because the parent directory is
 *      writable by the owner.  This is the git gc path.
 *
 *   4. Owner rename over 0444 file.  Create "old" mode 0444 and
 *      "new" mode 0644.  Rename "new" over "old".  Must succeed.
 *      This is the editor save-by-rename path.
 *
 *   5. Owner write via pre-opened fd after chmod to 0444.  Open
 *      O_RDWR, chmod to 0444, write via the already-open fd.
 *      Must succeed (POSIX: the open fd retains its access mode;
 *      chmod does not revoke it).  NFS servers that re-check
 *      permission bits on WRITE RPCs (instead of honouring the
 *      OPEN stateid's access mode) will fail this.
 *
 *   6. Owner open(O_WRONLY) on 0444 file — should fail.  The
 *      owner's implicit chmod right does NOT mean the owner can
 *      open a 0444 file for writing without first chmod'ing it.
 *      open(2) checks the permission bits at OPEN time.  Expect
 *      -1/EACCES.  (Some NFS servers with aggressive owner-
 *      override may allow this; NOTE rather than FAIL in that
 *      case, because it is a known server policy variation.)
 *
 *   7. Non-owner access denied.  If running as root, fork a child
 *      that setuid's to nobody (65534) and attempts to chmod a
 *      file owned by the parent.  Must fail with EPERM.  This
 *      confirms the override is owner-specific, not universal.
 *      Skipped when not running as root (cannot create a non-owner
 *      context without privilege).
 *
 *   8. Owner truncate(2) on 0444 file.  truncate(2) (not
 *      ftruncate) on a path the owner owns but cannot write.
 *      Linux returns EACCES (truncate checks current permission
 *      bits, unlike ftruncate on an open fd).  Verify.
 *
 * Portable: Linux-focused (tests Linux-specific owner semantics).
 * Most cases also pass on FreeBSD and macOS because they share the
 * same POSIX base.  Case 7 requires root.
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

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  exercise Linux owner-override semantics beyond strict "
		"POSIX\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
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
	(void)write(fd, buf, sizeof(buf));
	close(fd);
	if (chmod(out, mode) != 0) {
		complain("%s: chmod(0%o): %s", tag, mode, strerror(errno));
		unlink(out);
		return -1;
	}
	return 0;
}

static void case_chmod_0444(void)
{
	char name[64];
	if (make_owned_file("c4", name, sizeof(name), 0444) != 0)
		return;

	if (chmod(name, 0644) != 0)
		complain("case1: owner chmod 0444->0644: %s",
			 strerror(errno));

	unlink(name);
}

static void case_chmod_0000(void)
{
	char name[64];
	if (make_owned_file("c0", name, sizeof(name), 0000) != 0)
		return;

	if (chmod(name, 0644) != 0)
		complain("case2: owner chmod 0000->0644: %s",
			 strerror(errno));

	/* Restore so unlink works cleanly on all platforms. */
	chmod(name, 0644);
	unlink(name);
}

static void case_unlink_0444(void)
{
	char name[64];
	if (make_owned_file("ul", name, sizeof(name), 0444) != 0)
		return;

	if (unlink(name) != 0)
		complain("case3: owner unlink of 0444 file: %s "
			 "(git gc relies on this — REMOVE must check "
			 "directory write permission, not file permission)",
			 strerror(errno));
}

static void case_rename_over_0444(void)
{
	char old[64], new[64];
	if (make_owned_file("ro", old, sizeof(old), 0444) != 0)
		return;

	snprintf(new, sizeof(new), "t_oo.rn.%ld", (long)getpid());
	unlink(new);
	int fd = open(new, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("case4: create new: %s", strerror(errno));
		chmod(old, 0644);
		unlink(old);
		return;
	}
	close(fd);

	if (rename(new, old) != 0)
		complain("case4: rename over 0444 file: %s "
			 "(editor save-by-rename relies on this)",
			 strerror(errno));

	chmod(old, 0644);
	unlink(old);
	unlink(new);
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

	/* chmod to 0444 while the fd is still open. */
	if (chmod(name, 0444) != 0) {
		complain("case5: chmod: %s", strerror(errno));
		close(fd);
		unlink(name);
		return;
	}

	/*
	 * Write via the pre-opened fd.  POSIX says this must succeed:
	 * the fd was opened O_RDWR, and a subsequent chmod does not
	 * revoke access on an already-open fd.  NFS servers that
	 * re-check permission bits on each WRITE RPC (instead of
	 * honouring the OPEN stateid's granted access) will fail here.
	 */
	char buf[32];
	memset(buf, 'W', sizeof(buf));
	errno = 0;
	ssize_t w = write(fd, buf, sizeof(buf));
	if (w != (ssize_t)sizeof(buf))
		complain("case5: write via pre-opened fd after chmod 0444: "
			 "%s (NFS server may be re-checking permission bits "
			 "on WRITE RPC instead of honouring OPEN stateid)",
			 w < 0 ? strerror(errno) : "short write");

	close(fd);
	chmod(name, 0644);
	unlink(name);
}

static void case_open_wronly_0444(void)
{
	char name[64];
	if (make_owned_file("ow", name, sizeof(name), 0444) != 0)
		return;

	errno = 0;
	int fd = open(name, O_WRONLY);
	if (fd >= 0) {
		/*
		 * Some NFS servers allow the owner to open a 0444 file
		 * for writing because they recognise the owner could
		 * chmod + open.  This is a policy choice, not a bug —
		 * but it is not POSIX-required.  NOTE, not FAIL.
		 */
		if (!Sflag)
			printf("NOTE: %s: case6 open(O_WRONLY) on owner's "
			       "0444 file succeeded (server owner-override "
			       "policy — not POSIX-required)\n", myname);
		close(fd);
	} else if (errno != EACCES) {
		complain("case6: expected EACCES, got %s", strerror(errno));
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
		/*
		 * Child: become nobody (uid 65534) and try to chmod.
		 * Must fail with EPERM because we are not the owner.
		 */
		if (setgid(65534) != 0 || setuid(65534) != 0)
			_exit(2);
		errno = 0;
		if (chmod(name, 0644) == 0)
			_exit(1);    /* should not succeed */
		if (errno == EPERM)
			_exit(0);    /* correct: non-owner denied */
		_exit(3);            /* unexpected errno */
	}

	int status;
	waitpid(pid, &status, 0);
	if (WIFEXITED(status)) {
		switch (WEXITSTATUS(status)) {
		case 0:
			break;
		case 1:
			complain("case7: non-owner (nobody) chmod on 0444 "
				 "file succeeded — owner override is not "
				 "owner-specific");
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

	/*
	 * truncate(2) on a path checks the current permission bits
	 * (unlike ftruncate on an open fd).  The owner of a 0444 file
	 * should get EACCES from truncate(2).
	 */
	errno = 0;
	if (truncate(name, 0) == 0) {
		/*
		 * Some servers / kernels may allow owner truncate.
		 * NOTE, not FAIL — the distinction between truncate()
		 * and ftruncate() is subtle and some NFS implementations
		 * treat them identically for the owner.
		 */
		if (!Sflag)
			printf("NOTE: %s: case8 truncate(path) on owner's "
			       "0444 file succeeded (server may not "
			       "distinguish truncate from ftruncate for "
			       "owner)\n", myname);
	} else if (errno != EACCES) {
		complain("case8: expected EACCES, got %s", strerror(errno));
	}

	chmod(name, 0644);
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
		"Linux owner-override semantics beyond strict POSIX "
		"(chmod/unlink/rename on read-only files)");
	cd_or_skip(myname, dir, Nflag);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_chmod_0444", case_chmod_0444());
	RUN_CASE("case_chmod_0000", case_chmod_0000());
	RUN_CASE("case_unlink_0444", case_unlink_0444());
	RUN_CASE("case_rename_over_0444", case_rename_over_0444());
	RUN_CASE("case_write_via_open_fd", case_write_via_open_fd());
	RUN_CASE("case_open_wronly_0444", case_open_wronly_0444());
	RUN_CASE("case_nonowner_denied", case_nonowner_denied());
	RUN_CASE("case_truncate_path_0444", case_truncate_path_0444());

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}
