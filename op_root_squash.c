/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_root_squash.c -- verify root_squash NFS export behavior.
 *
 * root_squash is the default NFS export setting: the server maps
 * uid 0 (root) on the client to the anonymous uid (typically 65534 /
 * nobody).  This is the #1 NFS permission confusion — admins expect
 * root to have full access and are surprised when it doesn't.
 *
 * This test requires root.  It auto-skips for non-root.
 *
 * Cases:
 *
 *   1. File created as root: stat uid.  Under root_squash, the
 *      server stores the file as anonuid (typically 65534).  Under
 *      no_root_squash, uid is 0.  Report which mode is active.
 *
 *   2. Chown to root.  chown(file, 0, 0).  Under root_squash,
 *      should fail with EPERM (the mapped-to-nobody user cannot
 *      change ownership to root).  Under no_root_squash, succeeds.
 *
 *   3. Read 0600 file owned by another uid.  Create a file as
 *      root (mapped to anonuid), chmod 0600.  Then access(R_OK)
 *      as root.  Under root_squash, root is nobody and cannot
 *      read a 0600 file owned by anonuid (unless anonuid == mapped
 *      uid).  Under no_root_squash, root bypasses DAC.
 *
 *   4. Mkdir permissions.  mkdir as root.  Under root_squash,
 *      the directory is owned by anonuid.  Verify.
 *
 * The test does NOT fail — it reports what mode the server is in.
 * Both root_squash and no_root_squash are valid configurations.
 * The test validates that the behavior is CONSISTENT with whichever
 * mode is detected.
 *
 * Portable: POSIX across Linux / FreeBSD / macOS / Solaris.
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

static const char *myname = "op_root_squash";
static int squash_detected;  /* 1 = root_squash active */

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  verify root_squash NFS export behavior (requires root)\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

static void case_create_uid(void)
{
	char name[64];
	snprintf(name, sizeof(name), "t_rsq.cu.%ld", (long)getpid());
	unlink(name);

	int fd = open(name, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		complain("case1: create: %s", strerror(errno));
		return;
	}
	close(fd);

	struct stat st;
	if (stat(name, &st) != 0) {
		complain("case1: stat: %s", strerror(errno));
		unlink(name);
		return;
	}

	if (st.st_uid == 0) {
		squash_detected = 0;
		if (!Sflag)
			printf("NOTE: %s: case1 file owned by uid 0 — "
			       "no_root_squash is active\n", myname);
	} else {
		squash_detected = 1;
		if (!Sflag)
			printf("NOTE: %s: case1 file owned by uid %u — "
			       "root_squash is active (root mapped to "
			       "anonuid)\n", myname, (unsigned)st.st_uid);
	}
	unlink(name);
}

static void case_chown_to_root(void)
{
	char name[64];
	snprintf(name, sizeof(name), "t_rsq.co.%ld", (long)getpid());
	unlink(name);

	int fd = open(name, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) { complain("case2: create: %s", strerror(errno)); return; }
	close(fd);

	errno = 0;
	int rc = chown(name, 0, 0);

	if (squash_detected) {
		if (rc == 0)
			complain("case2: chown(root) succeeded under "
				 "root_squash (expected EPERM)");
		else if (errno != EPERM)
			complain("case2: expected EPERM under root_squash, "
				 "got %s", strerror(errno));
	} else {
		if (rc != 0)
			complain("case2: chown(root) failed under "
				 "no_root_squash: %s", strerror(errno));
	}
	unlink(name);
}

static void case_read_0600(void)
{
	char name[64];
	snprintf(name, sizeof(name), "t_rsq.rd.%ld", (long)getpid());
	unlink(name);

	int fd = open(name, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) { complain("case3: create: %s", strerror(errno)); return; }
	(void)write(fd, "test", 4);
	close(fd);

	if (chmod(name, 0600) != 0) {
		complain("case3: chmod: %s", strerror(errno));
		unlink(name);
		return;
	}

	errno = 0;
	fd = open(name, O_RDONLY);

	if (squash_detected) {
		/*
		 * Root is mapped to anonuid.  If the file is owned by
		 * anonuid (from case1), then the mapped user IS the owner
		 * and should be able to read 0600.  If somehow the uid
		 * differs, EACCES.  Accept either — the key is consistency.
		 */
		if (fd >= 0) {
			if (!Sflag)
				printf("NOTE: %s: case3 root can read 0600 "
				       "under root_squash (mapped uid is "
				       "the file owner)\n", myname);
			close(fd);
		} else {
			if (!Sflag)
				printf("NOTE: %s: case3 root cannot read 0600 "
				       "under root_squash: %s\n",
				       myname, strerror(errno));
		}
	} else {
		if (fd < 0)
			complain("case3: root cannot read 0600 under "
				 "no_root_squash: %s (DAC bypass expected)",
				 strerror(errno));
		else
			close(fd);
	}
	unlink(name);
}

static void case_mkdir_uid(void)
{
	char d[64];
	snprintf(d, sizeof(d), "t_rsq.md.%ld", (long)getpid());
	rmdir(d);

	if (mkdir(d, 0755) != 0) {
		complain("case4: mkdir: %s", strerror(errno));
		return;
	}

	struct stat st;
	if (stat(d, &st) != 0) {
		complain("case4: stat: %s", strerror(errno));
		rmdir(d);
		return;
	}

	if (squash_detected) {
		if (st.st_uid == 0)
			complain("case4: dir owned by uid 0 despite "
				 "root_squash (expected anonuid)");
	} else {
		if (st.st_uid != 0)
			complain("case4: dir owned by uid %u despite "
				 "no_root_squash (expected 0)",
				 (unsigned)st.st_uid);
	}
	rmdir(d);
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

	if (getuid() != 0)
		skip("%s: requires root (run as root to test root_squash "
		     "behavior)", myname);

	prelude(myname, "root_squash NFS export behavior");
	cd_or_skip(myname, dir, Nflag);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_create_uid", case_create_uid());
	RUN_CASE("case_chown_to_root", case_chown_to_root());
	RUN_CASE("case_read_0600", case_read_0600());
	RUN_CASE("case_mkdir_uid", case_mkdir_uid());

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}
