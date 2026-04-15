/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_deleg_attr.c -- probe NFSv4 attribute tracking under open files
 * and write delegations (RFC 7530 S18.7 GETATTR / S20.1 CB_GETATTR).
 *
 * Background: WRITE delegation
 * ----------------------------
 * When a client holds a WRITE delegation the server transfers attribute
 * authority for `size` and `change` to the delegating client.  If a
 * second client asks the server "what is the current size of file F?"
 * the server must issue a CB_GETATTR callback to the delegating client
 * to retrieve the authoritative values before answering.  If CB_GETATTR
 * is broken the second client receives stale (pre-delegation) attributes.
 *
 * What this test verifies
 * -----------------------
 * The test exercises the client-side attribute tracking that CB_GETATTR
 * depends on.  All cases are single-client (one NFS mount), so CB_GETATTR
 * itself is not triggered.  To observe CB_GETATTR:
 *
 *   1. Run this binary with -d /mnt/nfs on client A.
 *   2. While a case holds a file open, run `stat <file>` from client B
 *      on the same server/export.
 *   3. Use tcpdump/wireshark (port 2049, filter "nfs and rpc.program==1")
 *      on the server to see the CB_GETATTR compound on the callback
 *      channel, followed by the GETATTR reply from client A.
 *
 * Cases:
 *
 *   1. fstat / stat size agreement after pwrite.  Open O_RDWR, pwrite
 *      8 KiB, verify fstat(fd).st_size == stat(path).st_size == 8192.
 *      Exercises that the client attribute cache is updated on write
 *      and that both query paths return consistent values.
 *
 *   2. Incremental size tracking.  pwrite 1 KiB, stat → 1024; pwrite
 *      another 1 KiB at offset 1024, stat → 2048.  Tests that size
 *      is updated monotonically with each write while the file is open.
 *
 *   3. Fork: child stat after parent pwrite.  fork(), parent pwrite
 *      4 KiB, signal child via pipe, child stat(path) → 4096.  On a
 *      single NFS client both processes share the VFS attribute cache,
 *      so this exercises the same client-side attribute update path
 *      that CB_GETATTR queries on a multi-client deployment.
 *
 *   4. ftruncate attribute update.  pwrite 4 KiB, ftruncate(fd, 0),
 *      fstat → 0, stat(path) → 0.  Tests that a truncation through
 *      the delegated fd is reflected in both stat paths immediately.
 *
 *   5. Delegation return on close.  pwrite a known pattern, close()
 *      (which returns the delegation to the server), reopen O_RDONLY,
 *      pread and verify pattern.  Tests that data written under
 *      delegation is committed to the server on delegation return.
 *
 *   6. lseek(SEEK_END) vs stat size agreement.  pwrite 4 KiB, compare
 *      lseek(fd, 0, SEEK_END) to stat(path).st_size.  Both should
 *      return 4096; a mismatch indicates the client's in-kernel size
 *      tracking diverged from the attribute cache.
 *
 *   7. CB_GETATTR via independent second client.  Requires -S SERVER and
 *      optionally -P NFSPATH_PREFIX (export-relative prefix for the test
 *      directory; omit if the NFS mount is at the server export root).
 *      Opens a file and pwrite 4 KiB (holding the WRITE delegation), then
 *      exec()s cb_getattr_probe as a separate NFSv4.1 client that issues
 *      PUTROOTFH + LOOKUP + GETATTR, which causes the server to issue
 *      CB_GETATTR to this client.  Verifies that the probe receives the
 *      delegated size (4096).  Silently skipped if cb_getattr_probe is not
 *      in PATH (install it from nfsv42-tests alongside this binary).
 *
 *   8. Same-client thread stat.  pthread_create a worker that does
 *      stat(f) while the main thread holds the write delegation.  Because
 *      the worker shares the kernel's NFS client, the server sees no
 *      conflicting OPEN and sends no CB_GETATTR; the client answers the
 *      stat from the delegation's in-core attribute cache.  Always
 *      verifies attribute correctness.  With -m ("mountstats-strict"),
 *      additionally parses /proc/self/mountstats to assert that no wire
 *      GETATTR was sent for the mount during the thread's stat -- the
 *      observable proxy for "no CB_GETATTR could have fired."  -m is
 *      Linux-only and requires a quiet mount: concurrent traffic from
 *      other users, test runs, or monitoring agents bumps the GETATTR
 *      counter and produces a false positive, so -m is opt-in.
 *
 * Portable: POSIX across Linux / FreeBSD / macOS / Solaris (cases 1-6).
 * Case 7 requires a Linux/Unix NFS server on port 2049 (TCP).  Case 8's
 * attribute-correctness assertion is POSIX; its -m strict mountstats
 * assertion is Linux-only.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE     /* for realpath declaration on some glibc versions */

#include "tests.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Some POSIX systems do not define PATH_MAX in <limits.h>; fall back to
 * the Linux default so the mountstats path buffer is still sized. */
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

int Hflag = 0;
int Sflag = 0;
int Tflag = 0;
int Fflag = 0;
int Nflag = 0;
static int Mflag = 0;	/* -m: enable mountstats-strict assertion in case 8 */

static const char *myname = "op_deleg_attr";

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfnm] [-d DIR] [-S SERVER] [-P NFSPATH_PREFIX]\n"
		"  probe NFSv4 attribute tracking under write delegations\n"
		"  (RFC 7530 S18.7 GETATTR / S20.1 CB_GETATTR)\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n"
		"  -m case 8 strict: assert no wire GETATTR during thread stat\n"
		"     (Linux only; requires a QUIET mount -- concurrent test\n"
		"     runs or background traffic on the same mount produce\n"
		"     false positives; opt-in acknowledgement of that risk)\n"
		"  -S SERVER          enable case 7: NFS server for CB_GETATTR probe\n"
		"  -P NFSPATH_PREFIX  export-relative prefix to test dir (default \"\")\n",
		myname);
}

/* case 1 ---------------------------------------------------------------- */

static void case_fstat_stat_agree(void)
{
	char f[64];
	snprintf(f, sizeof(f), "t_da.fs.%ld", (long)getpid());
	unlink(f);

	int fd = open(f, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("case1: open: %s", strerror(errno));
		return;
	}

	unsigned char buf[8192];
	fill_pattern(buf, sizeof(buf), 1);
	if (pwrite_all(fd, buf, sizeof(buf), 0, "case1: pwrite") != 0) {
		close(fd); unlink(f); return;
	}

	struct stat fst, pst;
	if (fstat(fd, &fst) != 0) {
		complain("case1: fstat: %s", strerror(errno));
		close(fd); unlink(f); return;
	}
	if (stat(f, &pst) != 0) {
		complain("case1: stat: %s", strerror(errno));
		close(fd); unlink(f); return;
	}

	if (fst.st_size != 8192)
		complain("case1: fstat size %lld != 8192",
			 (long long)fst.st_size);
	if (pst.st_size != 8192)
		complain("case1: stat size %lld != 8192",
			 (long long)pst.st_size);
	if (fst.st_size != pst.st_size)
		complain("case1: fstat size %lld != stat size %lld "
			 "(attribute cache / delegation size mismatch)",
			 (long long)fst.st_size, (long long)pst.st_size);

	close(fd);
	unlink(f);
}

/* case 2 ---------------------------------------------------------------- */

static void case_incremental_size(void)
{
	char f[64];
	snprintf(f, sizeof(f), "t_da.is.%ld", (long)getpid());
	unlink(f);

	int fd = open(f, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("case2: open: %s", strerror(errno));
		return;
	}

	unsigned char chunk[1024];
	fill_pattern(chunk, sizeof(chunk), 2);

	/* First write: 1 KiB at offset 0. */
	if (pwrite_all(fd, chunk, sizeof(chunk), 0, "case2: write1") != 0) {
		close(fd); unlink(f); return;
	}
	struct stat st;
	if (stat(f, &st) != 0) {
		complain("case2: stat after write1: %s", strerror(errno));
		close(fd); unlink(f); return;
	}
	if (st.st_size != 1024)
		complain("case2: after write1, stat size %lld != 1024",
			 (long long)st.st_size);

	/* Second write: 1 KiB at offset 1024. */
	fill_pattern(chunk, sizeof(chunk), 3);
	if (pwrite_all(fd, chunk, sizeof(chunk), 1024, "case2: write2") != 0) {
		close(fd); unlink(f); return;
	}
	if (stat(f, &st) != 0) {
		complain("case2: stat after write2: %s", strerror(errno));
		close(fd); unlink(f); return;
	}
	if (st.st_size != 2048)
		complain("case2: after write2, stat size %lld != 2048",
			 (long long)st.st_size);

	close(fd);
	unlink(f);
}

/* case 3 ---------------------------------------------------------------- */

static void case_fork_child_stat(void)
{
	char f[64];
	snprintf(f, sizeof(f), "t_da.fk.%ld", (long)getpid());
	unlink(f);

	int pfd[2];
	if (pipe(pfd) != 0) {
		complain("case3: pipe: %s", strerror(errno));
		return;
	}

	int fd = open(f, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("case3: open: %s", strerror(errno));
		close(pfd[0]); close(pfd[1]);
		return;
	}

	pid_t pid = fork();
	if (pid < 0) {
		complain("case3: fork: %s", strerror(errno));
		close(fd);
		close(pfd[0]); close(pfd[1]);
		unlink(f);
		return;
	}

	if (pid == 0) {
		/* ---- Child ---- */
		close(pfd[1]);
		close(fd);

		char ready;
		ssize_t n;
		do { n = read(pfd[0], &ready, 1); } while (n < 0 && errno == EINTR);
		close(pfd[0]);
		if (n != 1 || ready != 'S')
			_exit(0); /* parent had an error; it already complained */

		struct stat st;
		if (stat(f, &st) != 0) {
			fprintf(stderr, "FAIL: case3: child stat: %s\n",
				strerror(errno));
			_exit(1);
		}
		if (st.st_size != 4096) {
			fprintf(stderr,
				"FAIL: case3: child stat size %lld != 4096 "
				"(attr not visible from second process "
				"while parent holds delegation)\n",
				(long long)st.st_size);
			_exit(1);
		}
		_exit(0);
	}

	/* ---- Parent ---- */
	close(pfd[0]);

	unsigned char buf[4096];
	fill_pattern(buf, sizeof(buf), 77);

	char sig;
	if (pwrite_all(fd, buf, sizeof(buf), 0, "case3: pwrite") != 0) {
		sig = 'F'; /* write failed; complain already called */
	} else {
		sig = 'S';
	}
	ssize_t wr;
	do { wr = write(pfd[1], &sig, 1); } while (wr < 0 && errno == EINTR);
	if (wr < 0)
		bail("case3: write to child pipe: %s", strerror(errno));
	close(pfd[1]);

	int status = 0;
	waitpid(pid, &status, 0);
	if (WIFEXITED(status) && WEXITSTATUS(status) != 0)
		complain("case3: child saw stale size after parent pwrite "
			 "(delegation attribute cache not updated)");

	close(fd);
	unlink(f);
}

/* case 4 ---------------------------------------------------------------- */

static void case_ftruncate_attr(void)
{
	char f[64];
	snprintf(f, sizeof(f), "t_da.tr.%ld", (long)getpid());
	unlink(f);

	int fd = open(f, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("case4: open: %s", strerror(errno));
		return;
	}

	unsigned char buf[4096];
	fill_pattern(buf, sizeof(buf), 4);
	if (pwrite_all(fd, buf, sizeof(buf), 0, "case4: pwrite") != 0) {
		close(fd); unlink(f); return;
	}

	if (ftruncate(fd, 0) != 0) {
		complain("case4: ftruncate(0): %s", strerror(errno));
		close(fd); unlink(f); return;
	}

	struct stat fst, pst;
	if (fstat(fd, &fst) != 0) {
		complain("case4: fstat after truncate: %s", strerror(errno));
		close(fd); unlink(f); return;
	}
	if (stat(f, &pst) != 0) {
		complain("case4: stat after truncate: %s", strerror(errno));
		close(fd); unlink(f); return;
	}

	if (fst.st_size != 0)
		complain("case4: fstat size %lld after ftruncate(0) "
			 "(expected 0)",
			 (long long)fst.st_size);
	if (pst.st_size != 0)
		complain("case4: stat size %lld after ftruncate(0) "
			 "(expected 0)",
			 (long long)pst.st_size);

	close(fd);
	unlink(f);
}

/* case 5 ---------------------------------------------------------------- */

static void case_close_reopen(void)
{
	char f[64];
	snprintf(f, sizeof(f), "t_da.cr.%ld", (long)getpid());
	unlink(f);

	int fd = open(f, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("case5: open: %s", strerror(errno));
		return;
	}

	unsigned char wbuf[512];
	fill_pattern(wbuf, sizeof(wbuf), 5);
	if (pwrite_all(fd, wbuf, sizeof(wbuf), 0, "case5: pwrite") != 0) {
		close(fd); unlink(f); return;
	}

	/*
	 * close() causes the client to return the write delegation to the
	 * server.  The server must see the committed data after this point.
	 */
	if (close(fd) < 0) {
		complain("case5: close (delegation return): %s", strerror(errno));
		unlink(f); return;
	}

	fd = open(f, O_RDONLY);
	if (fd < 0) {
		complain("case5: reopen O_RDONLY: %s", strerror(errno));
		unlink(f);
		return;
	}

	struct stat st;
	if (fstat(fd, &st) != 0) {
		complain("case5: fstat after reopen: %s", strerror(errno));
		close(fd); unlink(f); return;
	}
	if (st.st_size != 512)
		complain("case5: size after delegation return: %lld != 512",
			 (long long)st.st_size);

	unsigned char rbuf[512];
	if (pread_all(fd, rbuf, sizeof(rbuf), 0, "case5: pread") != 0) {
		close(fd); unlink(f); return;
	}

	size_t off = check_pattern(rbuf, sizeof(rbuf), 5);
	if (off != 0)
		complain("case5: data mismatch at byte %zu after delegation "
			 "return (close did not commit data to server)",
			 off - 1);

	close(fd);
	unlink(f);
}

/* case 6 ---------------------------------------------------------------- */

static void case_seek_end_vs_stat(void)
{
	char f[64];
	snprintf(f, sizeof(f), "t_da.se.%ld", (long)getpid());
	unlink(f);

	int fd = open(f, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("case6: open: %s", strerror(errno));
		return;
	}

	unsigned char buf[4096];
	fill_pattern(buf, sizeof(buf), 6);
	if (pwrite_all(fd, buf, sizeof(buf), 0, "case6: pwrite") != 0) {
		close(fd); unlink(f); return;
	}

	off_t end = lseek(fd, 0, SEEK_END);
	if (end < 0) {
		complain("case6: lseek(SEEK_END): %s", strerror(errno));
		close(fd); unlink(f); return;
	}
	if (end != 4096)
		complain("case6: lseek(SEEK_END) returned %lld (expected 4096)",
			 (long long)end);

	struct stat st;
	if (stat(f, &st) != 0) {
		complain("case6: stat: %s", strerror(errno));
		close(fd); unlink(f); return;
	}
	if (st.st_size != 4096)
		complain("case6: stat size %lld (expected 4096)",
			 (long long)st.st_size);
	if (end != st.st_size)
		complain("case6: lseek(SEEK_END) %lld != stat size %lld "
			 "(client in-kernel size diverged from attribute cache)",
			 (long long)end, (long long)st.st_size);

	close(fd);
	unlink(f);
}

/* case 7 ---------------------------------------------------------------- */

static void case_cb_getattr(const char *server, const char *nfs_dir)
{
	char f[64];
	char probe_path[256];
	snprintf(f, sizeof(f), "t_da.cb.%ld", (long)getpid());
	unlink(f);

	/*
	 * Build the export-relative path for the probe:
	 * If nfs_dir is non-empty, it's the export-relative path to the
	 * test directory, so the file is at "nfs_dir/filename".
	 * If empty (mount is at export root), use just the filename.
	 */
	int plen;
	if (nfs_dir && nfs_dir[0] != '\0')
		plen = snprintf(probe_path, sizeof(probe_path), "%s/%s", nfs_dir, f);
	else
		plen = snprintf(probe_path, sizeof(probe_path), "%s", f);
	if (plen < 0 || (size_t)plen >= sizeof(probe_path)) {
		complain("case7: NFS path prefix too long (>%zu chars)",
			 sizeof(probe_path) - 1);
		return;
	}

	int fd = open(f, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("case7: open: %s", strerror(errno));
		return;
	}

	unsigned char buf[4096];
	fill_pattern(buf, sizeof(buf), 7);
	if (pwrite_all(fd, buf, sizeof(buf), 0, "case7: pwrite") != 0) {
		close(fd); unlink(f); return;
	}

	/*
	 * File is still open.  If the server granted a WRITE delegation
	 * the kernel now holds it.  Exec cb_getattr_probe as a separate
	 * NFSv4.1 client: it performs EXCHANGE_ID + CREATE_SESSION +
	 * SEQUENCE + PUTROOTFH + LOOKUP + GETATTR.  The server must issue
	 * CB_GETATTR to this process before answering.
	 */
	int pfd[2];
	if (pipe(pfd) != 0) {
		complain("case7: pipe: %s", strerror(errno));
		close(fd); unlink(f); return;
	}

	pid_t pid = fork();
	if (pid < 0) {
		complain("case7: fork: %s", strerror(errno));
		close(pfd[0]); close(pfd[1]);
		close(fd); unlink(f); return;
	}

	if (pid == 0) {
		/* Child: redirect stdout → pipe, exec the probe */
		close(pfd[0]);
		if (dup2(pfd[1], STDOUT_FILENO) < 0) _exit(1);
		close(pfd[1]);

		const char *probe_argv[] = {
			"cb_getattr_probe",
			"-s", server,
			"-p", probe_path,
			NULL
		};
		execvp("cb_getattr_probe", (char *const *)probe_argv);
		/* exec failed — signal SKIP (77) if binary not found */
		_exit(errno == ENOENT ? 77 : 1);
	}

	/* Parent: collect probe output */
	close(pfd[1]);
	char out[128] = { 0 };
	ssize_t n = read(pfd[0], out, sizeof(out) - 1);
	close(pfd[0]);
	if (n > 0)
		out[n] = '\0';

	int wstatus = 0;
	waitpid(pid, &wstatus, 0);
	int rc = WIFEXITED(wstatus) ? WEXITSTATUS(wstatus) : -1;

	if (rc == 77) {
		fprintf(stderr,
			"NOTE: case7: cb_getattr_probe not in PATH "
			"-- build nfsv42-tests and add to PATH\n");
		close(fd); unlink(f);
		return; /* not a failure */
	}
	if (rc != 0) {
		complain("case7: cb_getattr_probe exited %d", rc);
		close(fd); unlink(f); return;
	}

	/* Parse "size=N change=N" */
	unsigned long long probe_size = 0;
	if (sscanf(out, "size=%llu", &probe_size) != 1) {
		complain("case7: cannot parse probe output: '%s'", out);
		close(fd); unlink(f); return;
	}

	if (probe_size != 4096)
		complain("case7: probe size %llu != 4096 "
			 "(CB_GETATTR returned wrong size, "
			 "or server does not grant WRITE delegations)",
			 probe_size);

	close(fd);
	unlink(f);
}

/* case 8 ---------------------------------------------------------------- */

/*
 * read_mount_getattr_count -- return the outgoing GETATTR RPC count for
 * the NFS mount whose mountpoint path is `dir`.  Parses Linux
 * /proc/self/mountstats.  The format (per Documentation/filesystems/nfs/
 * and nfs-utils source) has a "device ... mounted on <path>" line, then
 * after "per-op statistics" a line per op: "NAME: c1 c2 c3 ... c8" where
 * c1 is the "bind count" (outgoing RPC count).
 *
 * Returns 0 on success with *count filled, -1 on any error (file
 * missing, parse failure, mount not found).  Non-fatal -- caller treats
 * -1 as "mountstats unavailable; skip strict check."
 *
 * Linux only.  Non-Linux builds return -1 unconditionally.
 */
static int read_mount_getattr_count(const char *dir, unsigned long long *count)
{
#ifdef __linux__
	FILE *fp = fopen("/proc/self/mountstats", "r");
	if (!fp)
		return -1;

	/*
	 * Resolve `dir` to an absolute path so we match mountstats' "mounted
	 * on <abs>" line regardless of how the caller spelled -d.
	 */
	char abs_dir[PATH_MAX];
	if (!realpath(dir, abs_dir)) {
		fclose(fp);
		return -1;
	}

	char line[1024];
	int in_target_mount = 0;
	int in_per_op = 0;
	int found = -1;

	while (fgets(line, sizeof(line), fp)) {
		if (strncmp(line, "device ", 7) == 0) {
			/* Format: "device X mounted on Y with fstype Z..." */
			in_target_mount = 0;
			in_per_op = 0;
			const char *m = strstr(line, " mounted on ");
			if (!m)
				continue;
			m += strlen(" mounted on ");
			/* Copy mountpoint up to the next " " or end of line */
			char mp[PATH_MAX];
			size_t i = 0;
			while (*m && *m != ' ' && *m != '\n' &&
			       i + 1 < sizeof(mp))
				mp[i++] = *m++;
			mp[i] = '\0';
			if (strcmp(mp, abs_dir) == 0)
				in_target_mount = 1;
			continue;
		}
		if (!in_target_mount)
			continue;
		if (strstr(line, "per-op statistics")) {
			in_per_op = 1;
			continue;
		}
		if (in_per_op) {
			/*
			 * Per-op lines are indented with a tab + variable
			 * spaces (the label is right-aligned): e.g.
			 *     "\t     GETATTR: 6319 6319 0 ...".
			 * Skip all leading whitespace before matching.
			 */
			const char *p = line;
			while (*p == ' ' || *p == '\t')
				p++;
			if (strncmp(p, "GETATTR:", 8) == 0) {
				unsigned long long c = 0;
				if (sscanf(p + 8, " %llu", &c) == 1) {
					*count = c;
					found = 0;
				}
				break;
			}
		}
	}

	fclose(fp);
	return found;
#else
	(void)dir;
	(void)count;
	return -1;
#endif
}

struct thread_stat_args {
	const char *path;
	off_t observed_size;
	int rc;
	int err;
};

static void *thread_stat_fn(void *arg)
{
	struct thread_stat_args *a = (struct thread_stat_args *)arg;
	struct stat st;
	if (stat(a->path, &st) != 0) {
		a->rc = -1;
		a->err = errno;
	} else {
		a->rc = 0;
		a->observed_size = st.st_size;
	}
	return NULL;
}

static void case_thread_stat_no_callback(const char *dir)
{
	char f[64];
	snprintf(f, sizeof(f), "t_da.th.%ld", (long)getpid());
	unlink(f);

	int fd = open(f, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("case8: open: %s", strerror(errno));
		return;
	}

	unsigned char buf[4096];
	fill_pattern(buf, sizeof(buf), 8);
	if (pwrite_all(fd, buf, sizeof(buf), 0, "case8: pwrite") != 0) {
		close(fd); unlink(f); return;
	}

	/* Snapshot for strict assertion.  On non-Linux or if the mount
	 * is not in /proc/self/mountstats, have_before stays -1 and we
	 * silently fall back to lenient mode. */
	unsigned long long ga_before = 0, ga_after = 0;
	int have_before = -1, have_after = -1;
	if (Mflag)
		have_before = read_mount_getattr_count(dir, &ga_before);

	struct thread_stat_args arg = { .path = f, .observed_size = -1,
					.rc = 0, .err = 0 };
	pthread_t tid;
	int pr = pthread_create(&tid, NULL, thread_stat_fn, &arg);
	if (pr != 0) {
		complain("case8: pthread_create: %s", strerror(pr));
		close(fd); unlink(f); return;
	}
	pthread_join(tid, NULL);

	if (arg.rc != 0) {
		complain("case8: thread stat(%s): %s", f, strerror(arg.err));
		close(fd); unlink(f); return;
	}
	if (arg.observed_size != 4096)
		complain("case8: thread saw size %lld != 4096 "
			 "(delegation attr cache did not reflect the write)",
			 (long long)arg.observed_size);

	if (Mflag)
		have_after = read_mount_getattr_count(dir, &ga_after);

	if (Mflag) {
		if (have_before < 0 || have_after < 0) {
			if (!Sflag)
				printf("NOTE: %s: case8 -m: /proc/self/mountstats "
				       "unavailable for %s; strict assertion "
				       "skipped\n",
				       myname, dir);
		} else if (ga_after != ga_before) {
			complain("case8: -m strict: GETATTR count rose by "
				 "%llu during thread stat "
				 "(client issued wire GETATTR despite holding "
				 "a delegation, OR concurrent traffic bumped "
				 "the counter -- -m requires a quiet mount)",
				 ga_after - ga_before);
		}
	}

	close(fd);
	unlink(f);
}

/* main ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
	const char *dir       = ".";
	const char *cb_server = NULL;  /* -S SERVER for case 7 */
	const char *cb_nfsdir = NULL;  /* -P PREFIX for case 7 */
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
			case 'm': Mflag = 1; break;
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
		"NFSv4 attribute tracking under write delegation "
		"(RFC 7530 S18.7/S20.1)");
	cd_or_skip(myname, dir, Nflag);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	case_fstat_stat_agree();
	case_incremental_size();
	case_fork_child_stat();
	case_ftruncate_attr();
	case_close_reopen();
	case_seek_end_vs_stat();

	if (cb_server)
		case_cb_getattr(cb_server, cb_nfsdir ? cb_nfsdir : "");

	case_thread_stat_no_callback(dir);

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}
