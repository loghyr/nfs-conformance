/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_deleg_recall.c -- test NFSv4 delegation recall via CB_RECALL.
 *
 * Background: CB_RECALL
 * ----------------------
 * When a client holds a WRITE delegation on a file and a second client
 * opens the same file (RFC 5661 §20.3), the server MUST issue a CB_RECALL
 * callback to the delegating client.  The delegating client must flush all
 * dirty data to the server and return the delegation before the second
 * client's OPEN is granted.
 *
 * Cases:
 *
 *   1. Write + delegation return on close (baseline).  Open a file for write,
 *      write a 16 KiB pattern (kernel holds a WRITE delegation while the
 *      file is open), close (which returns the delegation), reopen read-only,
 *      and verify the data round-trips correctly.  Does not require a second
 *      client.  Exercises the delegation-return path on close.
 *
 *   2. CB_RECALL via independent second client.  Requires -S SERVER and
 *      optionally -P NFSPATH_PREFIX.  Opens a file for write and pwrite 4 KiB
 *      while keeping the file descriptor open (kernel holds the delegation).
 *      exec()s cb_recall_probe as a separate NFSv4.1 client that sends OPEN
 *      on the same file; the server must issue CB_RECALL to this process
 *      before granting the probe's OPEN.  Verifies:
 *        a. The probe exits 0 (OPEN+CLOSE succeeded).
 *        b. stat() shows the correct size while the fd is still open.
 *        c. After close + reopen, the data pattern is intact.
 *      Silently skipped if cb_recall_probe is not in PATH.
 *
 * On servers that do not grant WRITE delegations the probe OPEN still
 * succeeds (no CB_RECALL is issued), but the test still passes — it
 * verifies data integrity through the open/close cycle regardless.
 *
 * Portable: POSIX across Linux / FreeBSD / macOS / Solaris (case 1).
 * Case 2 requires a Linux/Unix NFS server on TCP port 2049 and
 * cb_recall_probe installed alongside this binary in PATH.
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

static const char *myname = "op_deleg_recall";

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR] [-S SERVER] [-P NFSPATH_PREFIX]\n"
		"  test NFSv4 delegation recall (RFC 5661 §20.3 CB_RECALL)\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n"
		"  -S SERVER          enable case 2: NFS server for CB_RECALL probe\n"
		"  -P NFSPATH_PREFIX  export-relative prefix to test dir (default \"\")\n",
		myname);
}

/* case 1 ---------------------------------------------------------------- */

static void case_write_commit(void)
{
	char f[64];
	snprintf(f, sizeof(f), "t_dr.wc.%ld", (long)getpid());
	unlink(f);

	int fd = open(f, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("case1: open: %s", strerror(errno));
		return;
	}

	/* Write 16 KiB — kernel likely holds WRITE delegation while open. */
	unsigned char wbuf[16384];
	fill_pattern(wbuf, sizeof(wbuf), 1);
	if (pwrite_all(fd, wbuf, sizeof(wbuf), 0, "case1: pwrite") != 0) {
		close(fd); unlink(f); return;
	}

	struct stat st;
	if (fstat(fd, &st) != 0) {
		complain("case1: fstat: %s", strerror(errno));
		close(fd); unlink(f); return;
	}
	if (st.st_size != (off_t)sizeof(wbuf))
		complain("case1: fstat size %lld != %zu",
			 (long long)st.st_size, sizeof(wbuf));

	/*
	 * close() returns the WRITE delegation to the server.  At this point
	 * the server should have committed the data.
	 */
	if (close(fd) < 0) {
		complain("case1: close (delegation return): %s", strerror(errno));
		unlink(f); return;
	}

	fd = open(f, O_RDONLY);
	if (fd < 0) {
		complain("case1: reopen O_RDONLY: %s", strerror(errno));
		unlink(f); return;
	}

	if (fstat(fd, &st) != 0) {
		complain("case1: fstat after reopen: %s", strerror(errno));
		close(fd); unlink(f); return;
	}
	if (st.st_size != (off_t)sizeof(wbuf))
		complain("case1: size after delegation return: %lld != %zu",
			 (long long)st.st_size, sizeof(wbuf));

	unsigned char rbuf[16384];
	if (pread_all(fd, rbuf, sizeof(rbuf), 0, "case1: pread") != 0) {
		close(fd); unlink(f); return;
	}

	size_t off = check_pattern(rbuf, sizeof(rbuf), 1);
	if (off != 0)
		complain("case1: data mismatch at byte %zu after delegation "
			 "return (close did not commit data to server)",
			 off - 1);

	close(fd);
	unlink(f);
}

/* case 2 ---------------------------------------------------------------- */

static void case_recall(const char *server, const char *nfs_dir)
{
	char f[64];
	char probe_path[256];
	snprintf(f, sizeof(f), "t_dr.cb.%ld", (long)getpid());
	unlink(f);

	int plen;
	if (nfs_dir && nfs_dir[0] != '\0')
		plen = snprintf(probe_path, sizeof(probe_path), "%s/%s", nfs_dir, f);
	else
		plen = snprintf(probe_path, sizeof(probe_path), "%s", f);
	if (plen < 0 || (size_t)plen >= sizeof(probe_path)) {
		complain("case2: NFS path prefix too long (>%zu chars)",
			 sizeof(probe_path) - 1);
		return;
	}

	/* Open and write 4 KiB — kernel acquires WRITE delegation on OPEN. */
	int fd = open(f, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("case2: open: %s", strerror(errno));
		return;
	}

	unsigned char wbuf[4096];
	fill_pattern(wbuf, sizeof(wbuf), 2);
	if (pwrite_all(fd, wbuf, sizeof(wbuf), 0, "case2: pwrite") != 0) {
		close(fd); unlink(f); return;
	}

	/*
	 * File is still open.  If the server granted a WRITE delegation the
	 * kernel now holds it.  Run cb_recall_probe as a separate NFSv4.1
	 * client: its OPEN causes the server to issue CB_RECALL to this
	 * process.  The kernel flushes our data and returns the delegation
	 * before the probe receives its OPEN response.
	 */
	int pfd[2];
	if (pipe(pfd) != 0) {
		complain("case2: pipe: %s", strerror(errno));
		close(fd); unlink(f); return;
	}

	pid_t pid = fork();
	if (pid < 0) {
		complain("case2: fork: %s", strerror(errno));
		close(pfd[0]); close(pfd[1]);
		close(fd); unlink(f); return;
	}

	if (pid == 0) {
		close(pfd[0]);
		if (dup2(pfd[1], STDOUT_FILENO) < 0) _exit(1);
		close(pfd[1]);
		const char *probe_argv[] = {
			"cb_recall_probe",
			"-s", server,
			"-p", probe_path,
			NULL
		};
		execvp("cb_recall_probe", (char *const *)probe_argv);
		_exit(errno == ENOENT ? 77 : 1);
	}

	close(pfd[1]);
	char out[128] = { 0 };
	ssize_t n;
	do { n = read(pfd[0], out, sizeof(out) - 1); } while (n < 0 && errno == EINTR);
	close(pfd[0]);
	if (n > 0) out[n] = '\0';

	int wstatus = 0;
	waitpid(pid, &wstatus, 0);
	int rc = WIFEXITED(wstatus) ? WEXITSTATUS(wstatus) : -1;

	if (rc == 77) {
		fprintf(stderr,
			"NOTE: case2: cb_recall_probe not in PATH "
			"-- build nfsv42-tests and add to PATH\n");
		close(fd); unlink(f);
		return;
	}
	if (rc != 0) {
		complain("case2: cb_recall_probe exited %d (OPEN failed)", rc);
		close(fd); unlink(f); return;
	}

	/*
	 * Probe opened and closed.  If CB_RECALL happened, the kernel has
	 * returned the delegation and the server has committed our data.
	 * Verify size is still correct while our fd is open.
	 */
	struct stat st;
	if (stat(f, &st) != 0) {
		complain("case2: stat after probe: %s", strerror(errno));
	} else if (st.st_size != 4096) {
		complain("case2: stat size %lld != 4096 after delegation recall",
			 (long long)st.st_size);
	}

	/* Close our fd, reopen read-only, verify data. */
	if (close(fd) < 0) {
		complain("case2: close after recall: %s", strerror(errno));
		unlink(f); return;
	}

	fd = open(f, O_RDONLY);
	if (fd < 0) {
		complain("case2: reopen after recall: %s", strerror(errno));
		unlink(f); return;
	}

	unsigned char rbuf[4096];
	if (pread_all(fd, rbuf, sizeof(rbuf), 0, "case2: pread after recall") != 0) {
		close(fd); unlink(f); return;
	}

	size_t off = check_pattern(rbuf, sizeof(rbuf), 2);
	if (off != 0)
		complain("case2: data mismatch at byte %zu after delegation "
			 "recall (data not committed before recall completed)",
			 off - 1);

	close(fd);
	unlink(f);
}

/* main ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
	const char *dir       = ".";
	const char *cb_server = NULL;
	const char *cb_nfsdir = NULL;
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
				cb_server = argv[1];
				argv++; argc--;
				goto next;
			case 'P':
				if (argc < 2) { usage(); return TEST_FAIL; }
				cb_nfsdir = argv[1];
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
		"NFSv4 delegation recall via CB_RECALL (RFC 5661 §20.3)");
	cd_or_skip(myname, dir, Nflag);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	case_write_commit();

	if (cb_server)
		case_recall(cb_server, cb_nfsdir ? cb_nfsdir : "");

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}
