/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_deleg_read.c -- exercise NFSv4 read-delegation behavior (RFC 7530
 * S10.4.2).  Complements op_deleg_recall, which covers write
 * delegations.
 *
 * Semantics under test (RFC 5661 S18.43, delegation type OPEN_DELEGATE_READ):
 *
 *   - A server MAY grant a read delegation on an OPEN(SHARE_ACCESS_READ).
 *   - A concurrent OPEN(SHARE_ACCESS_READ) from a different client should
 *     NOT cause CB_RECALL: read delegations are compatible with
 *     concurrent readers.
 *   - A concurrent OPEN(SHARE_ACCESS_WRITE) from a different client
 *     MUST cause CB_RECALL: the server revokes the read delegation
 *     before granting write access to the other client.
 *
 * Cases:
 *
 *   1. Local shared-read baseline.  Open the same file O_RDONLY
 *      twice in this process and read concurrently from both fds.
 *      Runs unconditionally; requires no -S.  Exercises the same-
 *      client read path that the later cases depend on.
 *
 *   2. Cross-client shared read (requires -S SERVER).  Open O_RDONLY,
 *      keep the fd open, and invoke cb_recall_probe (default: READ
 *      share).  Both opens are for READ, so the server is free to
 *      grant a read delegation to this process and deliver the
 *      probe's OPEN without any CB_RECALL.  Verify: the parent's
 *      pread returns the expected data after the probe returns.
 *
 *   3. Read-delegation recall via conflicting write (requires -S).
 *      Open O_RDONLY, run cb_recall_probe -w (opens for WRITE
 *      share).  The probe's OPEN forces CB_RECALL on any read
 *      delegation this process holds.  Verify: parent's subsequent
 *      pread still returns the correct content, and the file is
 *      unchanged on the wire (the probe issues OPEN + CLOSE without
 *      any WRITE).
 *
 * Cases 2 and 3 require cb_recall_probe to be in PATH.  If missing,
 * they emit a NOTE and skip only those cases; case 1 still runs.
 *
 * Portable: same constraints as op_deleg_recall -- Linux NFS client
 * with read-delegation support.  On servers that never grant read
 * delegations (e.g. only write delegations are enabled), the tests
 * still pass: they become structural "reads stay correct under
 * concurrent second-client access" checks.
 */

#define _POSIX_C_SOURCE 200809L

#include "tests.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

int Hflag = 0;
int Sflag = 0;
int Tflag = 0;
int Fflag = 0;
int Nflag = 0;

static const char *myname = "op_deleg_read";

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR] [-s SERVER] [-P NFSPATH_PREFIX]\n"
		"  exercise read delegation and recall (RFC 7530 S10.4.2)\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n"
		"  -S SERVER    hostname for the probe client's NFSv4.1 session\n"
		"  -P PREFIX    export-relative path prefix passed to probe\n",
		myname);
}

/*
 * run_probe -- fork/exec cb_recall_probe with the given share mode.
 * Returns:
 *    0     probe succeeded (opened + closed)
 *    77    probe binary not in PATH (skip caller)
 *   -1     probe failed or interrupted
 */
static int run_probe(const char *server, const char *probe_path,
		     int write_open)
{
	int pfd[2];
	if (pipe(pfd) != 0) {
		complain("pipe: %s", strerror(errno));
		return -1;
	}
	pid_t pid = fork();
	if (pid < 0) {
		complain("fork: %s", strerror(errno));
		close(pfd[0]); close(pfd[1]);
		return -1;
	}
	if (pid == 0) {
		close(pfd[0]);
		if (dup2(pfd[1], STDOUT_FILENO) < 0) _exit(1);
		close(pfd[1]);
		const char *argv_r[] = { "cb_recall_probe",
					 "-s", server,
					 "-p", probe_path, NULL };
		const char *argv_w[] = { "cb_recall_probe",
					 "-s", server,
					 "-p", probe_path, "-w", NULL };
		execvp("cb_recall_probe",
		       (char *const *)(write_open ? argv_w : argv_r));
		_exit(errno == ENOENT ? 77 : 1);
	}

	close(pfd[1]);
	char out[128] = { 0 };
	ssize_t n;
	do { n = read(pfd[0], out, sizeof(out) - 1); }
	while (n < 0 && errno == EINTR);
	close(pfd[0]);
	if (n > 0) out[n] = '\0';

	int wstatus = 0;
	waitpid(pid, &wstatus, 0);
	int rc = WIFEXITED(wstatus) ? WEXITSTATUS(wstatus) : -1;

	if (rc == 77)
		return 77;
	if (rc != 0) {
		complain("cb_recall_probe%s exited %d (OPEN failed)",
			 write_open ? " -w" : "", rc);
		return -1;
	}
	return 0;
}

/* case 1 ---------------------------------------------------------------- */

static void case_local_shared_read(void)
{
	char f[64];
	snprintf(f, sizeof(f), "t_dr.lc.%ld", (long)getpid());
	unlink(f);

	int fd = open(f, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("case1: open: %s", strerror(errno));
		return;
	}
	unsigned char wbuf[4096];
	fill_pattern(wbuf, sizeof(wbuf), 1);
	if (pwrite_all(fd, wbuf, sizeof(wbuf), 0,
		       "case1: pwrite") != 0) {
		close(fd); unlink(f); return;
	}
	if (close(fd) < 0) {
		complain("case1: close after seed: %s", strerror(errno));
		unlink(f); return;
	}

	int fd1 = open(f, O_RDONLY);
	int fd2 = open(f, O_RDONLY);
	if (fd1 < 0 || fd2 < 0) {
		complain("case1: open two O_RDONLY fds: %s", strerror(errno));
		if (fd1 >= 0) close(fd1);
		if (fd2 >= 0) close(fd2);
		unlink(f); return;
	}

	unsigned char r1[4096], r2[4096];
	if (pread_all(fd1, r1, sizeof(r1), 0, "case1: pread fd1") != 0 ||
	    pread_all(fd2, r2, sizeof(r2), 0, "case1: pread fd2") != 0) {
		close(fd1); close(fd2); unlink(f); return;
	}
	if (check_pattern(r1, sizeof(r1), 1) != 0)
		complain("case1: fd1 data mismatch");
	if (check_pattern(r2, sizeof(r2), 1) != 0)
		complain("case1: fd2 data mismatch");

	close(fd1); close(fd2);
	unlink(f);
}

/* case 2 ---------------------------------------------------------------- */

static void case_shared_read(const char *server, const char *nfs_dir)
{
	char f[64];
	char probe_path[256];
	snprintf(f, sizeof(f), "t_dr.rd.%ld", (long)getpid());
	unlink(f);

	int plen;
	if (nfs_dir && nfs_dir[0] != '\0')
		plen = snprintf(probe_path, sizeof(probe_path), "%s/%s",
				nfs_dir, f);
	else
		plen = snprintf(probe_path, sizeof(probe_path), "%s", f);
	if (plen < 0 || (size_t)plen >= sizeof(probe_path)) {
		complain("case2: NFS path prefix too long (>%zu chars)",
			 sizeof(probe_path) - 1);
		return;
	}

	/* Create and seed the file. */
	int fd = open(f, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("case2: open: %s", strerror(errno));
		return;
	}
	unsigned char wbuf[4096];
	fill_pattern(wbuf, sizeof(wbuf), 101);
	if (pwrite_all(fd, wbuf, sizeof(wbuf), 0,
		       "case2: pwrite") != 0) {
		close(fd); unlink(f); return;
	}
	if (close(fd) < 0) {
		complain("case2: close after seed: %s", strerror(errno));
		unlink(f); return;
	}

	/*
	 * Reopen O_RDONLY and hold.  The kernel may now request a READ
	 * delegation from the server (the test works either way).
	 */
	fd = open(f, O_RDONLY);
	if (fd < 0) {
		complain("case2: reopen O_RDONLY: %s", strerror(errno));
		unlink(f); return;
	}
	/* A pread before the probe ensures the client has cached state. */
	unsigned char pre[4096];
	if (pread_all(fd, pre, sizeof(pre), 0,
		      "case2: pread before probe") != 0) {
		close(fd); unlink(f); return;
	}
	if (check_pattern(pre, sizeof(pre), 101) != 0) {
		complain("case2: pre-probe data mismatch");
		close(fd); unlink(f); return;
	}

	int rc = run_probe(server, probe_path, 0 /* read */);
	if (rc == 77) {
		fprintf(stderr,
			"NOTE: case2: cb_recall_probe not in PATH "
			"-- build nfs-conformance and add to PATH\n");
		close(fd); unlink(f); return;
	}
	if (rc != 0) {
		close(fd); unlink(f); return;
	}

	/* Parent's read must still see the pattern; no recall expected. */
	unsigned char post[4096];
	if (pread_all(fd, post, sizeof(post), 0,
		      "case2: pread after read-probe") != 0) {
		close(fd); unlink(f); return;
	}
	size_t off = check_pattern(post, sizeof(post), 101);
	if (off != 0)
		complain("case2: post-probe data mismatch at byte %zu "
			 "(concurrent read open disturbed our data)",
			 off - 1);

	close(fd);
	unlink(f);
}

/* case 3 ---------------------------------------------------------------- */

static void case_recall_by_write(const char *server, const char *nfs_dir)
{
	char f[64];
	char probe_path[256];
	snprintf(f, sizeof(f), "t_dr.rw.%ld", (long)getpid());
	unlink(f);

	int plen;
	if (nfs_dir && nfs_dir[0] != '\0')
		plen = snprintf(probe_path, sizeof(probe_path), "%s/%s",
				nfs_dir, f);
	else
		plen = snprintf(probe_path, sizeof(probe_path), "%s", f);
	if (plen < 0 || (size_t)plen >= sizeof(probe_path)) {
		complain("case3: NFS path prefix too long (>%zu chars)",
			 sizeof(probe_path) - 1);
		return;
	}

	int fd = open(f, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("case3: open: %s", strerror(errno));
		return;
	}
	unsigned char wbuf[4096];
	fill_pattern(wbuf, sizeof(wbuf), 202);
	if (pwrite_all(fd, wbuf, sizeof(wbuf), 0,
		       "case3: pwrite") != 0) {
		close(fd); unlink(f); return;
	}
	if (close(fd) < 0) {
		complain("case3: close after seed: %s", strerror(errno));
		unlink(f); return;
	}

	fd = open(f, O_RDONLY);
	if (fd < 0) {
		complain("case3: reopen O_RDONLY: %s", strerror(errno));
		unlink(f); return;
	}
	unsigned char pre[4096];
	if (pread_all(fd, pre, sizeof(pre), 0,
		      "case3: pread before probe") != 0) {
		close(fd); unlink(f); return;
	}
	if (check_pattern(pre, sizeof(pre), 202) != 0) {
		complain("case3: pre-probe data mismatch");
		close(fd); unlink(f); return;
	}

	/* Probe opens for WRITE; server must recall any read delegation. */
	int rc = run_probe(server, probe_path, 1 /* write */);
	if (rc == 77) {
		fprintf(stderr,
			"NOTE: case3: cb_recall_probe not in PATH\n");
		close(fd); unlink(f); return;
	}
	if (rc != 0) {
		close(fd); unlink(f); return;
	}

	/*
	 * The probe performed OPEN + CLOSE without any WRITE, so the
	 * file content is unchanged.  The delegation (if granted) was
	 * recalled before the server let the probe's OPEN complete.
	 */
	unsigned char post[4096];
	if (pread_all(fd, post, sizeof(post), 0,
		      "case3: pread after write-probe") != 0) {
		close(fd); unlink(f); return;
	}
	size_t off = check_pattern(post, sizeof(post), 202);
	if (off != 0)
		complain("case3: data changed at byte %zu after write-probe "
			 "(probe should have opened + closed without writing)",
			 off - 1);

	close(fd);
	unlink(f);
}

int main(int argc, char **argv)
{
	const char *dir      = ".";
	const char *server   = NULL;
	const char *nfs_dir  = "";
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
				argv++; argc--;
				goto next;
			case 'S':
				if (argc < 2) { usage(); return TEST_FAIL; }
				server = argv[1];
				argv++; argc--;
				goto next;
			case 'P':
				if (argc < 2) { usage(); return TEST_FAIL; }
				nfs_dir = argv[1];
				argv++; argc--;
				goto next;
			default: usage(); return TEST_FAIL;
			}
		}
next:
		;
	}
	if (Hflag) { usage(); return TEST_PASS; }

	prelude(myname,
		"NFSv4 read delegation + CB_RECALL on conflicting write "
		"(RFC 7530 S10.4.2)");
	cd_or_skip(myname, dir, Nflag);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_local_shared_read", case_local_shared_read());
	if (server) {
		RUN_CASE("case_shared_read",
			 case_shared_read(server, nfs_dir));
		RUN_CASE("case_recall_by_write",
			 case_recall_by_write(server, nfs_dir));
	} else if (!Sflag) {
		printf("NOTE: %s: -S SERVER not provided; skipping "
		       "cross-client cases 2 and 3\n", myname);
	}

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}
