/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_allocate.c -- exercise posix_fallocate(3), which NFSv4.2 servers
 * translate into an ALLOCATE op (RFC 7862 S4).
 *
 * Cases:
 *
 *   1. Extend-by-preallocation.  Create a 0-byte file; posix_fallocate
 *      to len.  Size == len; file reads all zeros.
 *
 *   2. Grow-from-existing.  Create file with dense prefix; allocate
 *      extension past EOF.  Size grows; prefix intact; tail zero.
 *
 *   3. Inside-existing no-op.  Allocate inside an already-dense
 *      region: size unchanged, data unchanged.
 *
 *   4. Zero-length is legal.  POSIX says len=0 is either 0 or EINVAL;
 *      accept either.
 *
 *   5. Negative offset returns EINVAL.
 *
 *   6. ALLOCATE over an existing hole.  Create a sparse file with a
 *      hole in the middle, posix_fallocate() the hole range, verify
 *      the hole bytes now read as zeros (unchanged) AND that the
 *      surrounding dense regions are untouched.  Catches servers
 *      that translate ALLOCATE into zero-filled WRITE past EOF
 *      cleanly but get the mid-file hole-fill path wrong (e.g.,
 *      leaving stale server-side allocated-but-unwritten bytes).
 *
 *   7. Overlapping ALLOCATE ranges.  posix_fallocate(file, 0, 64K)
 *      then posix_fallocate(file, 32K, 64K).  Union ends at 96K,
 *      overlap region is [32K..64K).  Post-state: size >= 96K,
 *      every byte in [0..96K) reads zero (allocate must not leak
 *      stale bytes, even across repeated allocations of the same
 *      range).  Complements op_deallocate's overlapping-punches
 *      case; catches servers that over-count allocated blocks or
 *      fail idempotency across overlapping ALLOCATEs.
 *
 * Indicative server-op check: after the extend in case 1, st_blocks
 * should be greater than zero on backends that actually allocated.
 * A client that emulates ALLOCATE via WRITE-of-zeros also produces
 * nonzero st_blocks, so this is not conclusive -- but st_blocks == 0
 * after a nominally-successful extend is a strong hint that the
 * allocation was a no-op.
 *
 * macOS does not implement posix_fallocate (POSIX XSI); stub out.
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

static const char *myname = "op_allocate";

#if defined(__APPLE__)
int main(void)
{
	skip("%s: posix_fallocate(3) not available on macOS (macOS implements "
	     "fcntl(F_PREALLOCATE) with different semantics)",
	     myname);
	return TEST_SKIP;
}
#else

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  exercise posix_fallocate -> NFSv4.2 ALLOCATE\n"
		"  -h  help\n"
		"  -s  silent (suppress non-error output)\n"
		"  -t  print timing\n"
		"  -f  function-only\n"
		"  -n  do not create the working directory\n"
		"  -d  run under DIR (default: current directory)\n",
		myname);
}

/*
 * posix_fallocate returns errno as int and does NOT set errno.
 * This wrapper normalises to "0 on success, errno value on failure".
 */
static int do_fallocate(int fd, off_t off, off_t len)
{
	return posix_fallocate(fd, off, len);
}

/*
 * Case 1: extend-from-zero, check size, all-zero contents, and
 * st_blocks sanity (WARNs if 0 when len>0; does not FAIL).
 */
static void case_extend_from_zero(const char *path, off_t len)
{
	char name[64];
	(void)path; /* prefix passed in but we use scratch_open here */

	int fd = scratch_open("t10c1", name, sizeof(name));
	int rc = do_fallocate(fd, 0, len);
	if (rc == EINVAL) {
		close(fd);
		unlink(name);
		skip("%s: posix_fallocate returned EINVAL -- NFS client "
		     "does not map posix_fallocate(3) to the NFSv4.2 "
		     "ALLOCATE op on this mount",
		     myname);
	}
	if (rc != 0) {
		complain("case1: posix_fallocate(0, %lld): %s",
			 (long long)len, strerror(rc));
		goto out;
	}

	struct stat st;
	if (fstat(fd, &st) != 0) {
		complain("case1: fstat: %s", strerror(errno));
		goto out;
	}
	if (st.st_size != len) {
		complain("case1: size %lld != expected %lld",
			 (long long)st.st_size, (long long)len);
		goto out;
	}
	if (st.st_blocks == 0 && len > 0 && !Sflag) {
		printf("NOTE: %s: st_blocks == 0 after ALLOCATE -- suspicious "
		       "(did the server actually allocate?)\n",
		       myname);
	}

	unsigned char *buf = malloc((size_t)len);
	if (!buf) {
		complain("case1: malloc(%lld)", (long long)len);
		goto out;
	}
	if (pread_all(fd, buf, (size_t)len, 0, "case1") < 0) {
		free(buf);
		goto out;
	}
	if (!all_zero(buf, (size_t)len))
		complain("case1: allocated region not all zero");
	free(buf);
out:
	close(fd);
	unlink(name);
}

static void case_grow_from_existing(off_t dense, off_t extend)
{
	char name[64];
	int fd = scratch_open("t10c2", name, sizeof(name));

	unsigned char *src = malloc((size_t)dense);
	if (!src) {
		complain("case2: malloc");
		goto out;
	}
	fill_pattern(src, (size_t)dense, 0xDEADBEEF);
	if (pwrite_all(fd, src, (size_t)dense, 0, "case2:prefix") < 0) {
		free(src);
		goto out;
	}

	int rc = do_fallocate(fd, dense, extend);
	if (rc != 0) {
		complain("case2: posix_fallocate(%lld, %lld): %s",
			 (long long)dense, (long long)extend, strerror(rc));
		free(src);
		goto out;
	}

	struct stat st;
	if (fstat(fd, &st) != 0) {
		complain("case2: fstat: %s", strerror(errno));
		free(src);
		goto out;
	}
	if (st.st_size != dense + extend) {
		complain("case2: size %lld != %lld + %lld",
			 (long long)st.st_size, (long long)dense,
			 (long long)extend);
		free(src);
		goto out;
	}

	/* Prefix must be intact */
	unsigned char *vbuf = malloc((size_t)dense);
	if (!vbuf) {
		complain("case2: malloc vbuf");
	} else if (pread_all(fd, vbuf, (size_t)dense, 0, "case2:vprefix") == 0) {
		size_t miss = check_pattern(vbuf, (size_t)dense, 0xDEADBEEF);
		if (miss)
			complain("case2: prefix corrupted at byte %zu",
				 miss - 1);
	}
	free(vbuf);

	/* Tail must be zero */
	unsigned char *tail = malloc((size_t)extend);
	if (!tail) {
		complain("case2: malloc tail");
	} else if (pread_all(fd, tail, (size_t)extend, dense, "case2:tail") == 0) {
		if (!all_zero(tail, (size_t)extend))
			complain("case2: preallocated tail not zero");
	}
	free(tail);
	free(src);
out:
	close(fd);
	unlink(name);
}

static void case_inside_existing(off_t dense)
{
	char name[64];
	int fd = scratch_open("t10c3", name, sizeof(name));

	unsigned char *src = malloc((size_t)dense);
	if (!src) {
		complain("case3: malloc");
		goto out;
	}
	fill_pattern(src, (size_t)dense, 0xCAFEBABE);
	if (pwrite_all(fd, src, (size_t)dense, 0, "case3:write") < 0) {
		free(src);
		goto out;
	}

	off_t off = dense / 2;
	off_t len = dense / 4;
	int rc = do_fallocate(fd, off, len);
	if (rc != 0) {
		complain("case3: posix_fallocate(%lld, %lld): %s",
			 (long long)off, (long long)len, strerror(rc));
		free(src);
		goto out;
	}

	struct stat st;
	if (fstat(fd, &st) != 0) {
		complain("case3: fstat: %s", strerror(errno));
		free(src);
		goto out;
	}
	if (st.st_size != dense) {
		complain("case3: in-range allocate changed size: %lld != "
			 "%lld",
			 (long long)st.st_size, (long long)dense);
		free(src);
		goto out;
	}

	unsigned char *vbuf = malloc((size_t)dense);
	if (!vbuf) {
		complain("case3: malloc vbuf");
	} else if (pread_all(fd, vbuf, (size_t)dense, 0, "case3:verify") == 0) {
		size_t miss = check_pattern(vbuf, (size_t)dense, 0xCAFEBABE);
		if (miss)
			complain("case3: in-range allocate corrupted data "
				 "at byte %zu",
				 miss - 1);
	}
	free(vbuf);
	free(src);
out:
	close(fd);
	unlink(name);
}

static void case_zero_length(void)
{
	char name[64];
	int fd = scratch_open("t10c4", name, sizeof(name));
	int rc = do_fallocate(fd, 0, 0);
	close(fd);
	unlink(name);
	/* POSIX allows either 0 or EINVAL for len<=0 */
	if (rc != 0 && rc != EINVAL)
		complain("case4: posix_fallocate(0,0) returned %s "
			 "(expected 0 or EINVAL)",
			 strerror(rc));
}

static void case_negative_offset(void)
{
	char name[64];
	int fd = scratch_open("t10c5", name, sizeof(name));
	int rc = do_fallocate(fd, -1, 4096);
	close(fd);
	unlink(name);
	if (rc != EINVAL)
		complain("case5: posix_fallocate(-1, 4096) returned %s "
			 "(expected EINVAL)",
			 rc == 0 ? "0" : strerror(rc));
}

/*
 * Case 6: ALLOCATE over an existing hole.  The file looks like
 *
 *     [0 .. dense)       pattern A
 *     [dense .. 2*dense) hole (sparse, zeros on read)
 *     [2*dense .. 3*dense) pattern B
 *
 * posix_fallocate([dense .. 2*dense)) then:
 *   - file size unchanged;
 *   - head pattern A intact;
 *   - allocated-hole bytes still read as zero;
 *   - tail pattern B intact.
 *
 * Gemini gap: existing cases cover extend-past-EOF and
 * allocate-inside-already-dense; the mid-file hole-fill was not
 * exercised, and is the NFSv4.2 ALLOCATE path that is subtly
 * different from a WRITE-of-zeros emulation.
 */
static void case_allocate_into_hole(off_t dense)
{
	char name[64];
	int fd = scratch_open("t10c6", name, sizeof(name));

	const off_t size = 3 * dense;

	/* Create sparse layout: pwrite A at [0..dense), then pwrite B
	 * at [2*dense..3*dense); the middle [dense..2*dense) is a hole. */
	unsigned char *a = malloc((size_t)dense);
	unsigned char *b = malloc((size_t)dense);
	if (!a || !b) {
		complain("case6: malloc");
		free(a); free(b); close(fd); unlink(name); return;
	}
	fill_pattern(a, (size_t)dense, 0xA606);
	fill_pattern(b, (size_t)dense, 0xB606);

	if (pwrite_all(fd, a, (size_t)dense, 0, "case6: A") < 0
	    || pwrite_all(fd, b, (size_t)dense, 2 * dense,
			  "case6: B") < 0) {
		free(a); free(b); close(fd); unlink(name); return;
	}
	fdatasync(fd);

	struct stat st_before;
	if (fstat(fd, &st_before) != 0) {
		complain("case6: fstat before: %s", strerror(errno));
		free(a); free(b); close(fd); unlink(name); return;
	}
	if (st_before.st_size != size) {
		complain("case6: pre-fallocate size %lld != %lld "
			 "(sparse layout setup failed)",
			 (long long)st_before.st_size, (long long)size);
		free(a); free(b); close(fd); unlink(name); return;
	}

	int rc = do_fallocate(fd, dense, dense);
	if (rc == EINVAL || rc == ENOSYS || rc == EOPNOTSUPP) {
		if (!Sflag)
			printf("NOTE: %s: case6 posix_fallocate returned %s -- "
			       "skipping\n", myname, strerror(rc));
		free(a); free(b); close(fd); unlink(name); return;
	}
	if (rc != 0) {
		complain("case6: posix_fallocate([%lld, %lld)): %s",
			 (long long)dense, (long long)(2 * dense),
			 strerror(rc));
		free(a); free(b); close(fd); unlink(name); return;
	}

	struct stat st_after;
	if (fstat(fd, &st_after) != 0) {
		complain("case6: fstat after: %s", strerror(errno));
		free(a); free(b); close(fd); unlink(name); return;
	}
	if (st_after.st_size != size)
		complain("case6: size changed across hole-fill "
			 "(%lld -> %lld)",
			 (long long)st_before.st_size,
			 (long long)st_after.st_size);

	/* Head intact. */
	unsigned char *rh = malloc((size_t)dense);
	if (rh && pread_all(fd, rh, (size_t)dense, 0,
			    "case6: verify head") == 0) {
		if (memcmp(rh, a, (size_t)dense) != 0)
			complain("case6: head pattern A corrupted by "
				 "mid-file ALLOCATE");
	}
	free(rh);

	/* Filled hole reads zero. */
	unsigned char *rhole = malloc((size_t)dense);
	if (rhole && pread_all(fd, rhole, (size_t)dense, dense,
			       "case6: verify hole") == 0) {
		if (!all_zero(rhole, (size_t)dense))
			complain("case6: allocated hole bytes non-zero "
				 "after mid-file ALLOCATE "
				 "(server exposed stale backing bytes?)");
	}
	free(rhole);

	/* Tail intact. */
	unsigned char *rt = malloc((size_t)dense);
	if (rt && pread_all(fd, rt, (size_t)dense, 2 * dense,
			    "case6: verify tail") == 0) {
		if (memcmp(rt, b, (size_t)dense) != 0)
			complain("case6: tail pattern B corrupted by "
				 "mid-file ALLOCATE");
	}
	free(rt);

	free(a);
	free(b);
	close(fd);
	unlink(name);
}

static void case_overlapping_allocate(void)
{
	char name[64];
	int fd = scratch_open("t10c7", name, sizeof(name));

	const off_t off_a = 0;
	const off_t len_a = 64 * 1024;
	const off_t off_b = 32 * 1024;
	const off_t len_b = 64 * 1024;
	const off_t union_end = off_b + len_b;  /* 96 KiB */

	int rc = do_fallocate(fd, off_a, len_a);
	if (rc == EINVAL || rc == ENOSYS || rc == EOPNOTSUPP) {
		if (!Sflag)
			printf("NOTE: %s: case7 first ALLOCATE %s -- "
			       "skipping\n", myname, strerror(rc));
		close(fd); unlink(name); return;
	}
	if (rc != 0) {
		complain("case7: first posix_fallocate: %s", strerror(rc));
		close(fd); unlink(name); return;
	}

	rc = do_fallocate(fd, off_b, len_b);
	if (rc != 0) {
		complain("case7: second overlapping posix_fallocate: %s "
			 "(server must accept repeated/overlapping ALLOCATE)",
			 strerror(rc));
		close(fd); unlink(name); return;
	}

	struct stat st;
	if (fstat(fd, &st) != 0) {
		complain("case7: fstat: %s", strerror(errno));
		close(fd); unlink(name); return;
	}
	if (st.st_size < union_end)
		complain("case7: size %lld < union end %lld after "
			 "overlapping ALLOCATEs",
			 (long long)st.st_size, (long long)union_end);

	/*
	 * Every byte in [0..96K) must read as zero.  A server that
	 * didn't properly zero-fill the overlap region, or that
	 * somehow re-exposed stale backing bytes when the second
	 * ALLOCATE covered already-allocated space, fails here.
	 */
	unsigned char *buf = malloc((size_t)union_end);
	if (!buf) {
		complain("case7: malloc");
		close(fd); unlink(name); return;
	}
	if (pread_all(fd, buf, (size_t)union_end, 0,
		      "case7: verify union") == 0) {
		if (!all_zero(buf, (size_t)union_end))
			complain("case7: union [0..%lld) not all-zero "
				 "after overlapping ALLOCATEs "
				 "(stale backing bytes exposed?)",
				 (long long)union_end);
	}
	free(buf);

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

	prelude(myname, "posix_fallocate -> NFSv4.2 ALLOCATE (RFC 7862 S4)");
	cd_or_skip(myname, dir, Nflag);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_extend_from_zero", case_extend_from_zero(NULL, 4 * 1024 * 1024));
	RUN_CASE("case_grow_from_existing", case_grow_from_existing(1 * 1024 * 1024, 2 * 1024 * 1024));
	RUN_CASE("case_inside_existing", case_inside_existing(1 * 1024 * 1024));
	RUN_CASE("case_zero_length", case_zero_length());
	RUN_CASE("case_negative_offset", case_negative_offset());
	RUN_CASE("case_allocate_into_hole",
		 case_allocate_into_hole(512 * 1024));
	RUN_CASE("case_overlapping_allocate",
		 case_overlapping_allocate());

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}

#endif /* __APPLE__ */
