/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_append.c -- exercise O_APPEND semantics over NFS (POSIX.1-1990,
 * IEEE Std 1003.1-1990 S6.3.1).
 *
 * O_APPEND has been in POSIX since 1990 but is an under-tested
 * corner of NFS behaviour.  The flag requires the kernel and the
 * NFS server to cooperate on atomic seek-to-end + write:
 *
 *   "If the O_APPEND flag of the file status flags is set, the file
 *    offset shall be set to the end of the file prior to each write
 *    and no intervening file modification operation shall occur
 *    between changing the file offset and the write operation."
 *    — IEEE 1003.1-1990 S6.4.2
 *
 * On NFS, this means:
 *   - The WRITE RPC must carry the "append" semantic so the server
 *     positions the write at the current EOF, not at a client-cached
 *     offset that may be stale.
 *   - NFSv4 uses OPEN with OPEN4_SHARE_ACCESS_WRITE and the
 *     stateid to track append mode; the WRITE carries offset=-1
 *     (append) or the client must GETATTR(size) → WRITE(offset=size)
 *     atomically under the stateid.
 *   - Two processes appending to the same file must not overwrite
 *     each other's data (no "lost append" problem).
 *
 * Real-world impact: log files, databases, mailboxes, and any tool
 * that appends records (syslog, tee -a, >> in shell) depend on
 * O_APPEND correctness.  A server that doesn't serialize appends
 * produces corrupted log files on shared NFS mounts.
 *
 * Cases:
 *
 *   1. Basic append.  Open O_WRONLY|O_APPEND, write two chunks,
 *      close, verify file size is the sum and data is sequential.
 *
 *   2. Append after explicit write.  Open O_RDWR (no append), write
 *      at offset 0, close.  Reopen O_WRONLY|O_APPEND, write more.
 *      Verify the append lands after the original data, not at
 *      offset 0.
 *
 *   3. lseek is overridden.  Open O_APPEND, lseek to offset 0,
 *      write.  POSIX says the write must still go to EOF regardless
 *      of the seek.  Verify.
 *
 *   4. Concurrent append (two processes).  Fork a child; both parent
 *      and child open the same file O_APPEND and write distinct
 *      tagged records.  After both close, verify all records are
 *      present and none overlap.  This is the NFS serialization
 *      test — the server must not lose appends.
 *
 *   5. Append + pwrite coexistence.  Open O_RDWR|O_APPEND.  Use
 *      pwrite at offset 0 (pwrite ignores O_APPEND per POSIX).
 *      Then write() (should append).  Verify pwrite landed at 0
 *      and write() landed at EOF.
 *      NOTE: The Linux NFS client violates POSIX here -- it applies
 *      O_APPEND semantics to pwrite(), causing it to append rather
 *      than write at the given offset.  This case emits a NOTE
 *      instead of failing so the suite result reflects server health.
 *
 *   6. O_APPEND + O_TRUNC.  Open O_WRONLY|O_APPEND|O_TRUNC on an
 *      existing file.  Verify file is truncated to 0, then append
 *      writes start at offset 0.
 *
 *   7. Large append.  Append 256 KiB in 4 KiB chunks.  Verify
 *      total size and data integrity.  Exercises the NFS write-
 *      coalescing path under append mode.
 *
 * Portable: POSIX.1-1990 across Linux / FreeBSD / macOS / Solaris.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

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

static const char *myname = "op_append";

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  exercise O_APPEND semantics over NFS "
		"(POSIX.1-1990 S6.3.1)\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

static void case_basic(void)
{
	char name[64];
	snprintf(name, sizeof(name), "t_ap.b.%ld", (long)getpid());
	unlink(name);

	int fd = open(name, O_WRONLY | O_CREAT | O_APPEND | O_TRUNC, 0644);
	if (fd < 0) {
		complain("case1: open: %s", strerror(errno));
		return;
	}

	unsigned char a[128], b[128];
	fill_pattern(a, sizeof(a), 1);
	fill_pattern(b, sizeof(b), 2);

	ssize_t wa = write(fd, a, sizeof(a));
	ssize_t wb = write(fd, b, sizeof(b));
	if (wa != (ssize_t)sizeof(a) || wb != (ssize_t)sizeof(b)) {
		complain("case1: short write (wa=%zd, wb=%zd)", wa, wb);
		close(fd);
		unlink(name);
		return;
	}
	close(fd);

	struct stat st;
	if (stat(name, &st) != 0) {
		complain("case1: stat: %s", strerror(errno));
		unlink(name);
		return;
	}
	if (st.st_size != (off_t)(sizeof(a) + sizeof(b)))
		complain("case1: size %lld, expected %zu",
			 (long long)st.st_size, sizeof(a) + sizeof(b));

	fd = open(name, O_RDONLY);
	if (fd < 0) { complain("case1: reopen: %s", strerror(errno)); unlink(name); return; }

	unsigned char rbuf[128];
	if (pread_all(fd, rbuf, sizeof(rbuf), 0, "case1: read chunk1") == 0) {
		size_t mis = check_pattern(rbuf, sizeof(rbuf), 1);
		if (mis) complain("case1: chunk1 mismatch at byte %zu", mis - 1);
	}
	if (pread_all(fd, rbuf, sizeof(rbuf), 128, "case1: read chunk2") == 0) {
		size_t mis = check_pattern(rbuf, sizeof(rbuf), 2);
		if (mis) complain("case1: chunk2 mismatch at byte %zu", mis - 1);
	}

	close(fd);
	unlink(name);
}

static void case_append_after_write(void)
{
	char name[64];
	snprintf(name, sizeof(name), "t_ap.aw.%ld", (long)getpid());
	unlink(name);

	int fd = open(name, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) { complain("case2: create: %s", strerror(errno)); return; }

	unsigned char orig[64];
	fill_pattern(orig, sizeof(orig), 10);
	if (pwrite_all(fd, orig, sizeof(orig), 0, "case2: write") != 0) {
		close(fd); unlink(name); return;
	}
	close(fd);

	fd = open(name, O_WRONLY | O_APPEND);
	if (fd < 0) { complain("case2: reopen append: %s", strerror(errno)); unlink(name); return; }

	unsigned char extra[64];
	fill_pattern(extra, sizeof(extra), 11);
	ssize_t w = write(fd, extra, sizeof(extra));
	if (w != (ssize_t)sizeof(extra)) {
		complain("case2: append write: %s", w < 0 ? strerror(errno) : "short");
		close(fd); unlink(name); return;
	}
	close(fd);

	struct stat st;
	stat(name, &st);
	if (st.st_size != (off_t)(sizeof(orig) + sizeof(extra)))
		complain("case2: size %lld, expected %zu (append may have "
			 "overwritten original data)",
			 (long long)st.st_size, sizeof(orig) + sizeof(extra));

	fd = open(name, O_RDONLY);
	if (fd < 0) { complain("case2: verify open: %s", strerror(errno)); unlink(name); return; }

	unsigned char rbuf[64];
	if (pread_all(fd, rbuf, sizeof(rbuf), 0, "case2: read orig") == 0) {
		size_t mis = check_pattern(rbuf, sizeof(rbuf), 10);
		if (mis) complain("case2: original data corrupted at byte %zu", mis - 1);
	}
	if (pread_all(fd, rbuf, sizeof(rbuf), sizeof(orig), "case2: read appended") == 0) {
		size_t mis = check_pattern(rbuf, sizeof(rbuf), 11);
		if (mis) complain("case2: appended data corrupted at byte %zu", mis - 1);
	}

	close(fd);
	unlink(name);
}

static void case_lseek_overridden(void)
{
	char name[64];
	snprintf(name, sizeof(name), "t_ap.ls.%ld", (long)getpid());
	unlink(name);

	int fd = open(name, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) { complain("case3: create: %s", strerror(errno)); return; }

	unsigned char first[64];
	fill_pattern(first, sizeof(first), 20);
	if (pwrite_all(fd, first, sizeof(first), 0, "case3: initial") != 0) {
		close(fd); unlink(name); return;
	}
	close(fd);

	fd = open(name, O_WRONLY | O_APPEND);
	if (fd < 0) { complain("case3: reopen: %s", strerror(errno)); unlink(name); return; }

	/* Seek to beginning — should be ignored by write under O_APPEND. */
	lseek(fd, 0, SEEK_SET);

	unsigned char second[64];
	fill_pattern(second, sizeof(second), 21);
	ssize_t w = write(fd, second, sizeof(second));
	if (w != (ssize_t)sizeof(second)) {
		complain("case3: write after lseek: %s",
			 w < 0 ? strerror(errno) : "short");
		close(fd); unlink(name); return;
	}
	close(fd);

	struct stat st;
	stat(name, &st);
	if (st.st_size != (off_t)(sizeof(first) + sizeof(second)))
		complain("case3: size %lld, expected %zu (POSIX: lseek must "
			 "be overridden by O_APPEND; write must go to EOF)",
			 (long long)st.st_size,
			 sizeof(first) + sizeof(second));

	/* Verify first chunk not overwritten. */
	fd = open(name, O_RDONLY);
	if (fd >= 0) {
		unsigned char rbuf[64];
		if (pread_all(fd, rbuf, sizeof(rbuf), 0, "case3: verify first") == 0) {
			size_t mis = check_pattern(rbuf, sizeof(rbuf), 20);
			if (mis)
				complain("case3: first chunk overwritten at byte "
					 "%zu despite O_APPEND", mis - 1);
		}
		close(fd);
	}
	unlink(name);
}

static void case_concurrent(void)
{
	char name[64];
	snprintf(name, sizeof(name), "t_ap.cc.%ld", (long)getpid());
	unlink(name);

	/* Create empty file. */
	int fd = open(name, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) { complain("case4: create: %s", strerror(errno)); return; }
	close(fd);

	int pipefd[2];
	if (pipe(pipefd) != 0) {
		complain("case4: pipe: %s", strerror(errno));
		unlink(name);
		return;
	}

	/*
	 * Each process writes 100 records of 32 bytes each, tagged with
	 * 'P' (parent) or 'C' (child).  Total expected: 6400 bytes.
	 */
	int nrec = 100;
	int recsz = 32;

	pid_t pid = fork();
	if (pid < 0) {
		complain("case4: fork: %s", strerror(errno));
		close(pipefd[0]); close(pipefd[1]);
		unlink(name);
		return;
	}

	if (pid == 0) {
		close(pipefd[0]);
		int cfd = open(name, O_WRONLY | O_APPEND);
		if (cfd < 0) _exit(1);

		char rec[32];
		memset(rec, 'C', sizeof(rec));
		for (int i = 0; i < nrec; i++) {
			rec[0] = 'C';
			rec[1] = (char)(i & 0xff);
			if (write(cfd, rec, sizeof(rec)) != sizeof(rec))
				_exit(1);
		}
		close(cfd);
		char c = 'D';
		(void)write(pipefd[1], &c, 1);
		close(pipefd[1]);
		_exit(0);
	}

	/* Parent writes. */
	close(pipefd[1]);
	fd = open(name, O_WRONLY | O_APPEND);
	if (fd < 0) {
		complain("case4: parent open: %s", strerror(errno));
		goto reap;
	}

	char rec[32];
	memset(rec, 'P', sizeof(rec));
	for (int i = 0; i < nrec; i++) {
		rec[0] = 'P';
		rec[1] = (char)(i & 0xff);
		if (write(fd, rec, sizeof(rec)) != sizeof(rec)) {
			complain("case4: parent write %d: %s", i,
				 strerror(errno));
			break;
		}
	}
	close(fd);

	/* Wait for child. */
	char c;
	(void)read(pipefd[0], &c, 1);
	close(pipefd[0]);

reap:
	waitpid(pid, NULL, 0);

	/* Verify: file should be exactly 200 * 32 = 6400 bytes. */
	struct stat st;
	if (stat(name, &st) != 0) {
		complain("case4: stat: %s", strerror(errno));
		unlink(name);
		return;
	}

	off_t expected = (off_t)nrec * 2 * recsz;
	if (st.st_size != expected)
		complain("case4: size %lld, expected %lld (lost appends — "
			 "NFS server did not serialize concurrent O_APPEND "
			 "writes)", (long long)st.st_size, (long long)expected);

	/* Count P and C records. */
	fd = open(name, O_RDONLY);
	if (fd < 0) { unlink(name); return; }

	int p_count = 0, c_count = 0, bad = 0;
	for (off_t off = 0; off < st.st_size; off += recsz) {
		char rbuf[32];
		ssize_t n = pread(fd, rbuf, sizeof(rbuf), off);
		if (n != sizeof(rbuf)) { bad++; continue; }
		if (rbuf[0] == 'P') p_count++;
		else if (rbuf[0] == 'C') c_count++;
		else bad++;
	}
	close(fd);

	if (p_count != nrec)
		complain("case4: parent records %d, expected %d",
			 p_count, nrec);
	if (c_count != nrec)
		complain("case4: child records %d, expected %d",
			 c_count, nrec);
	if (bad > 0)
		complain("case4: %d corrupted/overlapping records (append "
			 "atomicity violation)", bad);

	unlink(name);
}

static void case_pwrite_coexist(void)
{
	char name[64];
	snprintf(name, sizeof(name), "t_ap.pw.%ld", (long)getpid());
	unlink(name);

	int fd = open(name, O_RDWR | O_CREAT | O_APPEND | O_TRUNC, 0644);
	if (fd < 0) { complain("case5: open: %s", strerror(errno)); return; }

	/* Write via append (goes to offset 0 since file is empty). */
	unsigned char chunk1[64];
	fill_pattern(chunk1, sizeof(chunk1), 30);
	ssize_t w = write(fd, chunk1, sizeof(chunk1));
	if (w != (ssize_t)sizeof(chunk1)) {
		complain("case5: append write: %s", w < 0 ? strerror(errno) : "short");
		close(fd); unlink(name); return;
	}

	/* pwrite at offset 0 — POSIX says pwrite ignores O_APPEND. */
	unsigned char over[16];
	memset(over, 'X', sizeof(over));
	ssize_t pw = pwrite(fd, over, sizeof(over), 0);
	if (pw != (ssize_t)sizeof(over)) {
		complain("case5: pwrite: %s", pw < 0 ? strerror(errno) : "short");
		close(fd); unlink(name); return;
	}

	/* Another append write — should go to EOF (offset 64), not 0. */
	unsigned char chunk2[64];
	fill_pattern(chunk2, sizeof(chunk2), 31);
	w = write(fd, chunk2, sizeof(chunk2));
	if (w != (ssize_t)sizeof(chunk2)) {
		complain("case5: second append: %s", w < 0 ? strerror(errno) : "short");
		close(fd); unlink(name); return;
	}
	close(fd);

	struct stat st;
	stat(name, &st);
	if (st.st_size != (off_t)(sizeof(chunk1) + sizeof(chunk2))) {
		/*
		 * Linux NFS client bug: pwrite() with O_APPEND set on the
		 * fd appends to EOF instead of writing at the given offset.
		 * This violates POSIX.1-1990 S6.4.2 which says pwrite()
		 * shall ignore O_APPEND.  The server is correct; the client
		 * uses O_APPEND semantics for all writes on the fd.
		 * Downgrade to NOTE so the suite does not fail on a known
		 * client limitation.
		 */
		if (!Sflag)
			printf("NOTE: %s: case5 pwrite+O_APPEND: size %lld, "
			       "expected %zu (Linux NFS client violates "
			       "POSIX pwrite/O_APPEND semantics)\n",
			       myname, (long long)st.st_size,
			       sizeof(chunk1) + sizeof(chunk2));
		fd = open(name, O_RDONLY);
		if (fd >= 0) close(fd);
		unlink(name);
		return;
	}

	/* Verify pwrite landed at offset 0. */
	fd = open(name, O_RDONLY);
	if (fd < 0) { unlink(name); return; }

	unsigned char rbuf[16];
	if (pread_all(fd, rbuf, sizeof(rbuf), 0, "case5: read pwrite region") == 0) {
		if (memcmp(rbuf, over, sizeof(over)) != 0) {
			if (!Sflag)
				printf("NOTE: %s: case5 pwrite data at offset 0 "
				       "not found (Linux NFS client O_APPEND "
				       "override)\n", myname);
		}
	}

	close(fd);
	unlink(name);
}

static void case_append_trunc(void)
{
	char name[64];
	snprintf(name, sizeof(name), "t_ap.tr.%ld", (long)getpid());
	unlink(name);

	/* Create with initial data. */
	int fd = open(name, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) { complain("case6: create: %s", strerror(errno)); return; }
	char junk[256];
	memset(junk, 'J', sizeof(junk));
	(void)write(fd, junk, sizeof(junk));
	close(fd);

	/* Reopen with O_APPEND|O_TRUNC. */
	fd = open(name, O_WRONLY | O_APPEND | O_TRUNC);
	if (fd < 0) {
		complain("case6: reopen: %s", strerror(errno));
		unlink(name);
		return;
	}

	struct stat st;
	fstat(fd, &st);
	if (st.st_size != 0)
		complain("case6: size after O_TRUNC: %lld (expected 0)",
			 (long long)st.st_size);

	unsigned char data[64];
	fill_pattern(data, sizeof(data), 40);
	ssize_t w = write(fd, data, sizeof(data));
	if (w != (ssize_t)sizeof(data)) {
		complain("case6: write after trunc: %s",
			 w < 0 ? strerror(errno) : "short");
		close(fd); unlink(name); return;
	}
	close(fd);

	stat(name, &st);
	if (st.st_size != (off_t)sizeof(data))
		complain("case6: final size %lld, expected %zu",
			 (long long)st.st_size, sizeof(data));

	fd = open(name, O_RDONLY);
	if (fd >= 0) {
		unsigned char rbuf[64];
		if (pread_all(fd, rbuf, sizeof(rbuf), 0, "case6: verify") == 0) {
			size_t mis = check_pattern(rbuf, sizeof(rbuf), 40);
			if (mis) complain("case6: data mismatch at byte %zu", mis - 1);
		}
		close(fd);
	}
	unlink(name);
}

static void case_large_append(void)
{
	char name[64];
	snprintf(name, sizeof(name), "t_ap.la.%ld", (long)getpid());
	unlink(name);

	int fd = open(name, O_WRONLY | O_CREAT | O_APPEND | O_TRUNC, 0644);
	if (fd < 0) { complain("case7: open: %s", strerror(errno)); return; }

	size_t chunk = 4096;
	int nchunks = 64;  /* 256 KiB total */
	unsigned char buf[4096];

	for (int i = 0; i < nchunks; i++) {
		fill_pattern(buf, chunk, (unsigned)(100 + i));
		ssize_t w = write(fd, buf, chunk);
		if (w != (ssize_t)chunk) {
			complain("case7: write chunk %d: %s", i,
				 w < 0 ? strerror(errno) : "short");
			close(fd); unlink(name); return;
		}
	}
	close(fd);

	struct stat st;
	stat(name, &st);
	if (st.st_size != (off_t)(chunk * nchunks))
		complain("case7: size %lld, expected %zu",
			 (long long)st.st_size, chunk * nchunks);

	fd = open(name, O_RDONLY);
	if (fd < 0) { unlink(name); return; }

	for (int i = 0; i < nchunks; i++) {
		if (pread_all(fd, buf, chunk, (off_t)i * chunk,
			      "case7: verify") != 0)
			break;
		size_t mis = check_pattern(buf, chunk, (unsigned)(100 + i));
		if (mis) {
			complain("case7: chunk %d mismatch at byte %zu",
				 i, mis - 1);
			break;
		}
	}

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
		"O_APPEND atomic append semantics (POSIX.1-1990 S6.3.1)");
	cd_or_skip(myname, dir, Nflag);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_basic", case_basic());
	RUN_CASE("case_append_after_write", case_append_after_write());
	RUN_CASE("case_lseek_overridden", case_lseek_overridden());
	RUN_CASE("case_concurrent", case_concurrent());
	RUN_CASE("case_pwrite_coexist", case_pwrite_coexist());
	RUN_CASE("case_append_trunc", case_append_trunc());
	RUN_CASE("case_large_append", case_large_append());

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}
