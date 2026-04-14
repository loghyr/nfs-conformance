/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * op_xattr.c -- exercise user extended attribute syscalls
 * (setxattr/getxattr/listxattr/removexattr), which NFSv4.2 servers
 * translate into the SETXATTR/GETXATTR/LISTXATTRS/REMOVEXATTR ops
 * added by RFC 8276.
 *
 * Scope: the `user.*` namespace only.  `trusted.*` requires
 * CAP_SYS_ADMIN and `security.*` is owned by SELinux / Smack, so
 * neither fits a portable userspace test.
 *
 * Cases:
 *
 *   1. Round trip.  setxattr(user.pets, "dog"), getxattr returns
 *      "dog"; listxattr returns a list containing user.pets;
 *      removexattr removes it; listxattr no longer lists it.
 *
 *   2. CREATE flag.  setxattr(user.x, v1, XATTR_CREATE) succeeds;
 *      a second setxattr with XATTR_CREATE returns EEXIST.
 *
 *   3. REPLACE flag.  setxattr(user.missing, v, XATTR_REPLACE) on
 *      an absent name returns ENODATA.
 *
 *   4. Multiple xattrs on the same file.  Set user.a, user.b,
 *      user.c; listxattr returns all three (embedded in a
 *      NUL-separated buffer); getxattr on each returns the
 *      original value.
 *
 *   5. Large value.  setxattr(user.big, 64 KiB payload); getxattr
 *      round-trip matches.  Many servers cap xattr values below
 *      this -- test accepts E2BIG / ERANGE as a valid "server
 *      cap reached" outcome, not a failure.
 *
 * Runtime SKIP conditions:
 *   - First setxattr returns ENOTSUP / EOPNOTSUPP (server or backing
 *     FS doesn't support user xattrs; RFC 8276 is optional).
 *   - listxattr on no-xattr file returns ENOTSUP (same reason).
 *
 * Compile-time SKIP: macOS has a superset API with a position
 * argument and different namespace conventions; we stub out there.
 * FreeBSD uses extattr_*; also stubbed.
 */

#define _GNU_SOURCE

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

static const char *myname = "op_xattr";

#if !defined(__linux__)
int main(void)
{
	skip("%s: user.* xattrs tested via Linux sys/xattr.h; other platforms "
	     "use different APIs (macOS adds a position arg; FreeBSD uses "
	     "extattr_*)",
	     myname);
	return TEST_SKIP;
}
#else

#include <sys/xattr.h>

#define BIG_LEN (64 * 1024)

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  exercise user.* xattrs -> NFSv4.2 XATTR ops (RFC 8276)\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

/*
 * feature_probe -- attempt a tiny setxattr; if the backend does not
 * support user xattrs (ENOTSUP / EOPNOTSUPP) skip the whole test.
 * The RFC 8276 support feature flag is advisory; the real signal is
 * an actual setxattr rejection.
 */
static void feature_probe(const char *path)
{
	if (setxattr(path, "user.__probe", "x", 1, 0) == 0) {
		removexattr(path, "user.__probe");
		return;
	}
	if (errno == ENOTSUP || errno == EOPNOTSUPP) {
		skip("%s: setxattr returned %s; server / FS does not "
		     "support user.* xattrs",
		     myname, strerror(errno));
	}
	/*
	 * Some kernels refuse with EPERM when the mount isn't
	 * user_xattr-enabled (legacy ext4 tune, pre-default).
	 * Treat as SKIP rather than FAIL.
	 */
	if (errno == EPERM) {
		skip("%s: setxattr returned EPERM; mount likely needs "
		     "user_xattr option",
		     myname);
	}
	bail("feature_probe: unexpected setxattr error: %s", strerror(errno));
}

/*
 * list_contains -- does the xattr list buffer (NUL-separated names,
 * total size list_len) contain `name`?  Returns 1 if yes, 0 if no.
 */
static int list_contains(const char *list, ssize_t list_len, const char *name)
{
	ssize_t i = 0;
	while (i < list_len) {
		const char *cur = list + i;
		if (strcmp(cur, name) == 0)
			return 1;
		i += (ssize_t)strlen(cur) + 1;
	}
	return 0;
}

static void case_roundtrip(const char *path)
{
	const char *name = "user.pets";
	const char *val = "dog";

	if (setxattr(path, name, val, strlen(val), 0) != 0) {
		complain("case1: setxattr(%s): %s", name, strerror(errno));
		return;
	}

	char buf[64];
	ssize_t got = getxattr(path, name, buf, sizeof(buf));
	if (got < 0) {
		complain("case1: getxattr(%s): %s", name, strerror(errno));
		return;
	}
	if ((size_t)got != strlen(val) || memcmp(buf, val, (size_t)got) != 0) {
		complain("case1: getxattr value mismatch (got %zd bytes)", got);
		return;
	}

	char list[256];
	ssize_t llen = listxattr(path, list, sizeof(list));
	if (llen < 0) {
		complain("case1: listxattr: %s", strerror(errno));
		return;
	}
	if (!list_contains(list, llen, name))
		complain("case1: listxattr did not return %s", name);

	if (removexattr(path, name) != 0) {
		complain("case1: removexattr(%s): %s", name, strerror(errno));
		return;
	}
	llen = listxattr(path, list, sizeof(list));
	if (llen < 0 && errno != ENOTSUP) {
		complain("case1: post-remove listxattr: %s", strerror(errno));
		return;
	}
	if (llen > 0 && list_contains(list, llen, name))
		complain("case1: listxattr still lists %s after remove", name);
}

static void case_create_flag(const char *path)
{
	const char *name = "user.c1";
	if (setxattr(path, name, "a", 1, XATTR_CREATE) != 0) {
		complain("case2: first setxattr XATTR_CREATE: %s",
			 strerror(errno));
		return;
	}
	int rc = setxattr(path, name, "b", 1, XATTR_CREATE);
	if (rc == 0) {
		complain("case2: second setxattr XATTR_CREATE unexpectedly "
			 "succeeded");
	} else if (errno != EEXIST) {
		complain("case2: second setxattr XATTR_CREATE: expected "
			 "EEXIST, got %s",
			 strerror(errno));
	}
	removexattr(path, name);
}

static void case_replace_flag(const char *path)
{
	int rc = setxattr(path, "user.absent", "v", 1, XATTR_REPLACE);
	if (rc == 0) {
		complain("case3: setxattr REPLACE on missing name "
			 "unexpectedly succeeded");
	} else if (errno != ENODATA) {
		complain("case3: setxattr REPLACE on missing name: expected "
			 "ENODATA, got %s",
			 strerror(errno));
	}
}

static void case_multiple(const char *path)
{
	const char *names[] = { "user.a", "user.b", "user.c" };
	const char *values[] = { "alpha", "beta", "gamma" };
	const int N = 3;

	for (int i = 0; i < N; i++) {
		if (setxattr(path, names[i], values[i], strlen(values[i]), 0)
		    != 0) {
			complain("case4: setxattr(%s): %s", names[i],
				 strerror(errno));
			return;
		}
	}

	char list[512];
	ssize_t llen = listxattr(path, list, sizeof(list));
	if (llen < 0) {
		complain("case4: listxattr: %s", strerror(errno));
		goto cleanup;
	}
	for (int i = 0; i < N; i++) {
		if (!list_contains(list, llen, names[i])) {
			complain("case4: listxattr missing %s", names[i]);
			goto cleanup;
		}
	}

	for (int i = 0; i < N; i++) {
		char buf[32];
		ssize_t got = getxattr(path, names[i], buf, sizeof(buf));
		if (got < 0) {
			complain("case4: getxattr(%s): %s", names[i],
				 strerror(errno));
			continue;
		}
		if ((size_t)got != strlen(values[i])
		    || memcmp(buf, values[i], (size_t)got) != 0)
			complain("case4: %s value mismatch", names[i]);
	}

cleanup:
	for (int i = 0; i < N; i++)
		removexattr(path, names[i]);
}

static void case_large_value(const char *path)
{
	unsigned char *val = malloc(BIG_LEN);
	if (!val) {
		complain("case5: malloc");
		return;
	}
	fill_pattern(val, BIG_LEN, 0xBABE);

	if (setxattr(path, "user.big", val, BIG_LEN, 0) != 0) {
		/*
		 * Servers may cap xattr values well below 64 KiB.
		 * E2BIG / ERANGE / ENOSPC are valid "cap reached"
		 * responses; note but don't fail.
		 */
		if (errno == E2BIG || errno == ERANGE || errno == ENOSPC) {
			if (!Sflag)
				printf("NOTE: %s: case5 large-value set "
				       "returned %s (server cap)\n",
				       myname, strerror(errno));
			free(val);
			return;
		}
		complain("case5: setxattr large: %s", strerror(errno));
		free(val);
		return;
	}

	unsigned char *readback = malloc(BIG_LEN);
	if (!readback) {
		complain("case5: malloc readback");
		free(val);
		return;
	}
	ssize_t got = getxattr(path, "user.big", readback, BIG_LEN);
	if (got != BIG_LEN) {
		complain("case5: getxattr large: got %zd, want %d",
			 got, BIG_LEN);
	} else if (memcmp(val, readback, BIG_LEN) != 0) {
		complain("case5: large-value roundtrip corrupted");
	}

	removexattr(path, "user.big");
	free(val);
	free(readback);
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
		"user.* xattrs -> NFSv4.2 XATTR ops (RFC 8276)");
	cd_or_skip(myname, dir, Nflag);

	char name[64];
	int fd = scratch_open("t_xattr", name, sizeof(name));
	close(fd); /* xattr syscalls take paths; fd not needed */

	feature_probe(name);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	case_roundtrip(name);
	case_create_flag(name);
	case_replace_flag(name);
	case_multiple(name);
	case_large_value(name);

	unlink(name);

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}

#endif /* __linux__ */
