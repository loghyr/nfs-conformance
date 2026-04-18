/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_stale_handle.c -- exercise ESTALE (stale file handle) handling
 * on NFS.
 *
 * ESTALE is the #1 NFS user complaint.  It occurs when a client
 * holds a reference (fd or cached filehandle) to an object that has
 * been removed or replaced on the server.  A correct NFS client must
 * report ESTALE to the application rather than returning stale data
 * or silently failing.
 *
 * Cases:
 *
 *   1. Open file, unlink by name, read via fd.  The fd should
 *      still work (silly rename).  Already tested in op_unlink
 *      case 7, but included here as baseline.
 *
 *   2. Open file, unlink by name, stat by name.  Must return
 *      ENOENT (the name is gone).  The fd (if held) remains valid.
 *
 *   3. Open directory fd, rmdir from another path, readdir via fd.
 *      Should return ENOENT or succeed with empty results (the
 *      kernel may have cached the directory).  On NFS this tests
 *      the READDIR-on-removed-directory path.
 *
 *   4. Create, open, rename the file.  The fd should track the
 *      inode, not the name.  Write via fd, fstat — must still
 *      work after the name changed.
 *
 *   5. Hard-link open file, unlink original.  Access via fd must
 *      succeed.  Access via the surviving link name must succeed.
 *
 *   6. Symlink handle invalidation.  Open a symlink via
 *      O_PATH|O_NOFOLLOW (Linux-only), unlink the symlink itself
 *      (not its target), then fstat through the held fd.  Local
 *      filesystems typically keep the inode around while the fd
 *      is held; NFS clients commonly drop the server-side
 *      reference and return ESTALE.  The test accepts either
 *      "fstat succeeds" or "fstat returns ENOENT / ESTALE / EBADF";
 *      any OTHER errno, or a hang, is the bug.  Gated on O_PATH
 *      (Linux).
 *
 *   7. Rename-replace: fd holds the original inode.  Create file
 *      A with pattern P1, open fd to A, rename A -> B (a different
 *      name), create a NEW file at the original path A with pattern
 *      P2.  Accessing through the held fd must still see P1 (the
 *      inode that moved to B); accessing path A via a fresh open
 *      must see P2 (the new inode).  Gemini gap: server-side name
 *      replace while the client holds a handle -- a known NFS
 *      coherence trap when the client uses path-based fallbacks.
 *
 * Portable: POSIX across Linux / FreeBSD / macOS / Solaris.
 */

#define _POSIX_C_SOURCE 200809L

#include "tests.h"

#include <dirent.h>
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

static const char *myname = "op_stale_handle";

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  exercise ESTALE / stale file handle scenarios\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

static void case_open_unlink_read(void)
{
	char name[64];
	int fd = scratch_open("t_sh.or", name, sizeof(name));

	unsigned char wbuf[128];
	fill_pattern(wbuf, sizeof(wbuf), 1);
	if (pwrite_all(fd, wbuf, sizeof(wbuf), 0, "case1: write") != 0) {
		close(fd); unlink(name); return;
	}

	if (unlink(name) != 0) {
		complain("case1: unlink: %s", strerror(errno));
		close(fd); return;
	}

	unsigned char rbuf[128];
	if (pread_all(fd, rbuf, sizeof(rbuf), 0, "case1: read after unlink") == 0) {
		size_t mis = check_pattern(rbuf, sizeof(rbuf), 1);
		if (mis)
			complain("case1: data corrupted at byte %zu after "
				 "unlink (silly rename path)", mis - 1);
	}
	close(fd);
}

static void case_unlink_stat_enoent(void)
{
	char name[64];
	int fd = scratch_open("t_sh.se", name, sizeof(name));
	close(fd);

	if (unlink(name) != 0) {
		complain("case2: unlink: %s", strerror(errno));
		return;
	}

	struct stat st;
	errno = 0;
	if (stat(name, &st) == 0)
		complain("case2: stat after unlink succeeded (expected ENOENT)");
	else if (errno != ENOENT)
		complain("case2: expected ENOENT, got %s", strerror(errno));
}

static void case_rmdir_readdir(void)
{
	char d[64];
	snprintf(d, sizeof(d), "t_sh.rd.%ld", (long)getpid());
	rmdir(d);
	if (mkdir(d, 0755) != 0) {
		complain("case3: mkdir: %s", strerror(errno));
		return;
	}

	int dirfd = open(d, O_RDONLY | O_DIRECTORY);
	if (dirfd < 0) {
		complain("case3: open dir: %s", strerror(errno));
		rmdir(d);
		return;
	}

	if (rmdir(d) != 0) {
		complain("case3: rmdir: %s", strerror(errno));
		close(dirfd);
		return;
	}

	/*
	 * Materialise the dup into a named fd so we can close it on
	 * the fdopendir-failure path.  Previously `fdopendir(dup(...))`
	 * leaked the dup'd fd when fdopendir returned NULL (fdopendir
	 * takes ownership only on success).
	 */
	int tfd = dup(dirfd);
	DIR *dp = tfd >= 0 ? fdopendir(tfd) : NULL;
	if (dp) {
		struct dirent *de;
		errno = 0;
		while ((de = readdir(dp)) != NULL)
			;
		if (errno != 0 && errno != ENOENT && errno != ESTALE) {
			if (!Sflag)
				printf("NOTE: %s: case3 readdir on removed "
				       "dir: %s\n", myname, strerror(errno));
		}
		closedir(dp);
	} else {
		if (tfd >= 0) close(tfd);
		if (errno != ENOENT && errno != ESTALE && errno != EBADF) {
			if (!Sflag)
				printf("NOTE: %s: case3 fdopendir on removed "
				       "dir: %s\n", myname, strerror(errno));
		}
	}
	close(dirfd);
}

static void case_rename_fd_tracks_inode(void)
{
	char old[64], new_name[64];
	int fd = scratch_open("t_sh.ri", old, sizeof(old));
	snprintf(new_name, sizeof(new_name), "t_sh.rn.%ld", (long)getpid());
	unlink(new_name);

	unsigned char wbuf[64];
	fill_pattern(wbuf, sizeof(wbuf), 4);
	if (pwrite_all(fd, wbuf, sizeof(wbuf), 0, "case4: write") != 0) {
		close(fd); unlink(old); return;
	}

	if (rename(old, new_name) != 0) {
		complain("case4: rename: %s", strerror(errno));
		close(fd); unlink(old); return;
	}

	/* fd should still reference the inode. */
	struct stat st;
	if (fstat(fd, &st) != 0)
		complain("case4: fstat after rename: %s", strerror(errno));

	unsigned char rbuf[64];
	if (pread_all(fd, rbuf, sizeof(rbuf), 0, "case4: read after rename") == 0) {
		size_t mis = check_pattern(rbuf, sizeof(rbuf), 4);
		if (mis)
			complain("case4: data via fd corrupted after rename "
				 "at byte %zu", mis - 1);
	}

	/* Write more via fd. */
	fill_pattern(wbuf, sizeof(wbuf), 5);
	if (pwrite_all(fd, wbuf, sizeof(wbuf), 64, "case4: write2") != 0) {
		close(fd); unlink(new_name); return;
	}

	if (fstat(fd, &st) != 0)
		complain("case4: fstat after write2: %s", strerror(errno));
	else if (st.st_size != 128)
		complain("case4: size %lld after write2, expected 128",
			 (long long)st.st_size);

	close(fd);
	unlink(new_name);
	unlink(old);
}

static void case_hardlink_unlink_original(void)
{
	char a[64], b[64];
	int fd = scratch_open("t_sh.ha", a, sizeof(a));
	snprintf(b, sizeof(b), "t_sh.hb.%ld", (long)getpid());
	unlink(b);

	unsigned char wbuf[64];
	fill_pattern(wbuf, sizeof(wbuf), 6);
	if (pwrite_all(fd, wbuf, sizeof(wbuf), 0, "case5: write") != 0) {
		close(fd); unlink(a); return;
	}

	if (link(a, b) != 0) {
		if (errno == EOPNOTSUPP || errno == ENOTSUP) {
			if (!Sflag)
				printf("NOTE: %s: case5 skipped (hard links "
				       "not supported)\n", myname);
			close(fd); unlink(a); return;
		}
		complain("case5: link: %s", strerror(errno));
		close(fd); unlink(a); return;
	}

	if (unlink(a) != 0) {
		complain("case5: unlink original: %s", strerror(errno));
		close(fd); unlink(b); return;
	}

	/* fd still valid. */
	unsigned char rbuf[64];
	if (pread_all(fd, rbuf, sizeof(rbuf), 0, "case5: read via fd") == 0) {
		size_t mis = check_pattern(rbuf, sizeof(rbuf), 6);
		if (mis)
			complain("case5: fd data corrupted at byte %zu", mis - 1);
	}

	/* Second name still valid. */
	int fd2 = open(b, O_RDONLY);
	if (fd2 < 0) {
		complain("case5: open via second link: %s", strerror(errno));
	} else {
		if (pread_all(fd2, rbuf, sizeof(rbuf), 0, "case5: read via link") == 0) {
			size_t mis = check_pattern(rbuf, sizeof(rbuf), 6);
			if (mis)
				complain("case5: link data corrupted at byte %zu",
					 mis - 1);
		}
		close(fd2);
	}

	close(fd);
	unlink(b);
}

static void case_symlink_handle_stale(void)
{
#ifdef O_PATH
	char sl[64], target[64];
	snprintf(sl, sizeof(sl), "t_sh.sl.%ld", (long)getpid());
	snprintf(target, sizeof(target), "t_sh.tgt.%ld", (long)getpid());
	unlink(sl);
	unlink(target);

	/* Create a real target + a symlink to it. */
	int tfd = open(target, O_RDWR | O_CREAT, 0644);
	if (tfd < 0) {
		complain("case6: open target: %s", strerror(errno));
		return;
	}
	close(tfd);
	if (symlink(target, sl) != 0) {
		complain("case6: symlink: %s", strerror(errno));
		unlink(target);
		return;
	}

	/*
	 * Open the symlink itself, not its target.  O_PATH|O_NOFOLLOW
	 * gives us a handle to the link object; without it O_RDONLY
	 * would follow and we'd get a handle on the target.
	 */
	int slfd = open(sl, O_PATH | O_NOFOLLOW);
	if (slfd < 0) {
		if (errno == EINVAL || errno == EOPNOTSUPP) {
			if (!Sflag)
				printf("NOTE: %s: case6 O_PATH|O_NOFOLLOW "
				       "on symlink returned %s -- skipping\n",
				       myname, strerror(errno));
			unlink(sl); unlink(target);
			return;
		}
		complain("case6: open(O_PATH|O_NOFOLLOW) symlink: %s",
			 strerror(errno));
		unlink(sl); unlink(target);
		return;
	}

	/* Remove the symlink while the fd is held.  Target stays. */
	if (unlink(sl) != 0) {
		complain("case6: unlink symlink: %s", strerror(errno));
		close(slfd); unlink(target);
		return;
	}

	/*
	 * fstat through the held fd.  Legal outcomes:
	 *   - success: the client / kernel kept the inode alive
	 *     (local FS, some NFS clients with attr cache retention).
	 *   - ESTALE / ENOENT / EBADF: the server or client dropped
	 *     the reference.
	 * Anything else is a bug.  A hang would also be a bug but the
	 * test harness would time out elsewhere.
	 */
	struct stat st;
	errno = 0;
	if (fstat(slfd, &st) == 0) {
		if (!Sflag)
			printf("NOTE: %s: case6 fstat on removed symlink "
			       "succeeded (inode retained)\n", myname);
	} else if (errno != ESTALE && errno != ENOENT && errno != EBADF) {
		complain("case6: fstat on removed symlink returned %s "
			 "(expected success, ESTALE, ENOENT, or EBADF)",
			 strerror(errno));
	}

	close(slfd);
	unlink(target);
#else
	if (!Sflag)
		printf("NOTE: %s: case6 O_PATH unavailable -- skipping "
		       "symlink-handle-stale case\n", myname);
#endif
}

static void case_rename_then_recreate(void)
{
	char a[64], b[64];
	snprintf(a, sizeof(a), "t_sh.rA.%ld", (long)getpid());
	snprintf(b, sizeof(b), "t_sh.rB.%ld", (long)getpid());
	unlink(a); unlink(b);

	/* Create A with pattern P1. */
	int fd = open(a, O_RDWR | O_CREAT, 0644);
	if (fd < 0) {
		complain("case7: open A: %s", strerror(errno));
		return;
	}
	unsigned char p1[128], p2[128];
	fill_pattern(p1, sizeof(p1), 71);
	fill_pattern(p2, sizeof(p2), 72);
	if (pwrite_all(fd, p1, sizeof(p1), 0, "case7: seed P1") != 0) {
		close(fd); unlink(a); return;
	}
	if (fsync(fd) != 0) {
		complain("case7: fsync: %s", strerror(errno));
		close(fd); unlink(a); return;
	}

	/* Capture the original inode for the fd-tracks-inode check. */
	struct stat st_fd_before;
	if (fstat(fd, &st_fd_before) != 0) {
		complain("case7: fstat before rename: %s", strerror(errno));
		close(fd); unlink(a); return;
	}

	/* Rename A -> B.  The fd still references the (now-named-B) inode. */
	if (rename(a, b) != 0) {
		complain("case7: rename A -> B: %s", strerror(errno));
		close(fd); unlink(a); unlink(b); return;
	}

	/* Create a NEW file at the original path A with pattern P2. */
	int fd_new = open(a, O_RDWR | O_CREAT | O_EXCL, 0644);
	if (fd_new < 0) {
		complain("case7: create new A: %s", strerror(errno));
		close(fd); unlink(a); unlink(b); return;
	}
	if (pwrite_all(fd_new, p2, sizeof(p2), 0, "case7: seed P2") != 0) {
		close(fd_new); close(fd); unlink(a); unlink(b); return;
	}
	if (fsync(fd_new) != 0) {
		complain("case7: fsync new A: %s", strerror(errno));
	}

	struct stat st_fd_after, st_new;
	if (fstat(fd, &st_fd_after) != 0)
		complain("case7: fstat held fd after rename+recreate: %s",
			 strerror(errno));
	else if (st_fd_after.st_ino != st_fd_before.st_ino)
		complain("case7: held fd's inode changed across "
			 "rename+recreate (%lu -> %lu) -- fd should track "
			 "the original inode regardless of path-level "
			 "mutations",
			 (unsigned long)st_fd_before.st_ino,
			 (unsigned long)st_fd_after.st_ino);

	if (fstat(fd_new, &st_new) != 0) {
		complain("case7: fstat new A fd: %s", strerror(errno));
	} else if (st_new.st_ino == st_fd_before.st_ino) {
		complain("case7: new A has the same inode as the original "
			 "(rename did not actually move the inode, or the "
			 "recreate clobbered the wrong entry)");
	}

	/* Read via held fd -- must return P1 (original inode's content). */
	unsigned char rb[128];
	if (pread_all(fd, rb, sizeof(rb), 0,
		      "case7: read via held fd") == 0) {
		if (memcmp(rb, p1, sizeof(p1)) != 0)
			complain("case7: held fd read != P1 after "
				 "rename+recreate (fd followed the path "
				 "instead of the inode)");
	}

	/* Read via path A (fresh fd) -- must return P2. */
	int fd_peek = open(a, O_RDONLY);
	if (fd_peek < 0) {
		complain("case7: peek open A: %s", strerror(errno));
	} else {
		unsigned char rbp[128];
		if (pread_all(fd_peek, rbp, sizeof(rbp), 0,
			      "case7: read via path A") == 0) {
			if (memcmp(rbp, p2, sizeof(p2)) != 0)
				complain("case7: path-A read != P2 "
					 "(recreate did not place P2 "
					 "at path A)");
		}
		close(fd_peek);
	}

	close(fd_new);
	close(fd);
	unlink(a);
	unlink(b);
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

	prelude(myname, "ESTALE / stale file handle scenarios");
	cd_or_skip(myname, dir, Nflag);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_open_unlink_read", case_open_unlink_read());
	RUN_CASE("case_unlink_stat_enoent", case_unlink_stat_enoent());
	RUN_CASE("case_rmdir_readdir", case_rmdir_readdir());
	RUN_CASE("case_rename_fd_tracks_inode", case_rename_fd_tracks_inode());
	RUN_CASE("case_hardlink_unlink_original", case_hardlink_unlink_original());
	RUN_CASE("case_symlink_handle_stale", case_symlink_handle_stale());
	RUN_CASE("case_rename_then_recreate", case_rename_then_recreate());

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}
