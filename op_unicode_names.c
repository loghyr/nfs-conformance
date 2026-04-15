/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_unicode_names.c -- exercise UTF-8 filenames through the NFSv4
 * name encoding (RFC 7530 S1.4.2).
 *
 * NFSv4 defines filenames as UTF-8 strings and requires servers to
 * accept any valid UTF-8 byte sequence.  Older servers may silently
 * transliterate to 7-bit ASCII, truncate non-ASCII bytes, or reject
 * the name with EINVAL/EILSEQ.  This test creates files with
 * progressively wider UTF-8 code points and verifies each name
 * round-trips intact through readdir(3), lookup via stat(2), and
 * rename(2).
 *
 * Cases:
 *
 *   1. ASCII (control): "t_un.A.PID".  Verifies the harness itself
 *      works before introducing non-ASCII.  If case 1 fails the
 *      later cases are meaningless.
 *
 *   2. 2-byte UTF-8 (Latin-1 supplement): "café.PID".  The 'é' at
 *      U+00E9 encodes as 0xC3 0xA9.
 *
 *   3. 3-byte UTF-8 (BMP, CJK): "日本.PID".  Each glyph at U+65E5 /
 *      U+672C encodes as three UTF-8 bytes.
 *
 *   4. 4-byte UTF-8 (supplementary plane, emoji): "🎉.PID".  U+1F389
 *      encodes as 0xF0 0x9F 0x8E 0x89.  Some servers with older
 *      name-encoding libraries fail only at this width.
 *
 *   5. Rename round-trip across widths: create "café.PID", rename to
 *      "日本.PID", rename to "🎉.PID", remove.  Exercises the server
 *      RENAME path with non-ASCII on both sides.
 *
 * Each case verifies: create succeeds, readdir returns the exact
 * bytes, stat on the created name succeeds, remove succeeds.
 *
 * Portable: UTF-8 literals are standard C99 and compile on every
 * reasonable toolchain.  Requires the terminal/locale not to mangle
 * the strings, which in practice means running under UTF-8 locale
 * (LANG=C.UTF-8 or similar).  Filesystems must accept arbitrary
 * bytes in names (ext4, xfs, btrfs, zfs all do; FAT and HFS+ do
 * normalisation that can confuse this test, so runtests isolates
 * its scratch files in the -d directory and does not depend on a
 * specific normalisation form).
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

static const char *myname = "op_unicode_names";

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hstfn] [-d DIR]\n"
		"  exercise UTF-8 filenames -> NFSv4 name encoding (RFC 7530 S1.4.2)\n"
		"  -h help  -s silent  -t timing  -f function-only\n"
		"  -n no mkdir  -d DIR  (default cwd)\n",
		myname);
}

/* Create an empty file with exactly the given name. */
static int touch(const char *name)
{
	int fd = open(name, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0)
		return -1;
	close(fd);
	return 0;
}

/*
 * scan_for_name -- open the current directory and return 1 if an entry
 * with the exact byte sequence `target` appears in readdir output.
 */
static int scan_for_name(const char *target)
{
	DIR *dp = opendir(".");
	if (!dp)
		return -1;
	int found = 0;
	struct dirent *de;
	while ((de = readdir(dp)) != NULL) {
		if (strcmp(de->d_name, target) == 0) {
			found = 1;
			break;
		}
	}
	closedir(dp);
	return found;
}

/*
 * verify_name_roundtrip -- exercises create, readdir, stat, remove for
 * the exact UTF-8 byte sequence in `name`.  Caller supplies `label` so
 * failure messages name the case.
 */
static void verify_name_roundtrip(const char *label, const char *name)
{
	if (touch(name) != 0) {
		complain("%s: create(%s): %s", label, name, strerror(errno));
		return;
	}

	int found = scan_for_name(name);
	if (found < 0) {
		complain("%s: opendir failed: %s", label, strerror(errno));
		unlink(name);
		return;
	}
	if (!found) {
		complain("%s: readdir did not return %s "
			 "(server may be normalising or truncating)",
			 label, name);
		unlink(name);
		return;
	}

	struct stat st;
	if (stat(name, &st) != 0) {
		complain("%s: stat(%s): %s "
			 "(server accepted create but lookup mangled the name)",
			 label, name, strerror(errno));
		unlink(name);
		return;
	}
	if (!S_ISREG(st.st_mode))
		complain("%s: %s is not a regular file (mode=0%o)",
			 label, name, (unsigned)(st.st_mode & S_IFMT));

	if (unlink(name) != 0)
		complain("%s: unlink(%s): %s",
			 label, name, strerror(errno));
}

/* case 1 ---------------------------------------------------------------- */

static void case_ascii(void)
{
	char f[64];
	snprintf(f, sizeof(f), "t_un.A.%ld", (long)getpid());
	verify_name_roundtrip("case1", f);
}

/* case 2 ---------------------------------------------------------------- */

static void case_latin1(void)
{
	char f[96];
	/* "café" -- 'é' = U+00E9 = 0xC3 0xA9 */
	snprintf(f, sizeof(f), "caf\xC3\xA9.%ld", (long)getpid());
	verify_name_roundtrip("case2", f);
}

/* case 3 ---------------------------------------------------------------- */

static void case_cjk(void)
{
	char f[96];
	/* "日本" -- U+65E5 (0xE6 0x97 0xA5) U+672C (0xE6 0x9C 0xAC) */
	snprintf(f, sizeof(f), "\xE6\x97\xA5\xE6\x9C\xAC.%ld",
		 (long)getpid());
	verify_name_roundtrip("case3", f);
}

/* case 4 ---------------------------------------------------------------- */

static void case_emoji(void)
{
	char f[96];
	/* "🎉" -- U+1F389 = 0xF0 0x9F 0x8E 0x89 */
	snprintf(f, sizeof(f), "\xF0\x9F\x8E\x89.%ld", (long)getpid());
	verify_name_roundtrip("case4", f);
}

/* case 5 ---------------------------------------------------------------- */

static void case_rename_across_widths(void)
{
	char a[96], b[96], c[96];
	snprintf(a, sizeof(a), "caf\xC3\xA9.%ld", (long)getpid());
	snprintf(b, sizeof(b), "\xE6\x97\xA5\xE6\x9C\xAC.%ld", (long)getpid());
	snprintf(c, sizeof(c), "\xF0\x9F\x8E\x89.%ld", (long)getpid());

	unlink(a); unlink(b); unlink(c);

	if (touch(a) != 0) {
		complain("case5: create(%s): %s", a, strerror(errno));
		return;
	}

	if (rename(a, b) != 0) {
		complain("case5: rename(2B->3B) %s -> %s: %s",
			 a, b, strerror(errno));
		unlink(a); return;
	}
	if (scan_for_name(b) != 1) {
		complain("case5: %s not visible after rename", b);
		unlink(b); return;
	}

	if (rename(b, c) != 0) {
		complain("case5: rename(3B->4B) %s -> %s: %s",
			 b, c, strerror(errno));
		unlink(b); return;
	}
	if (scan_for_name(c) != 1)
		complain("case5: %s not visible after rename", c);

	unlink(c);
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
		"UTF-8 filenames -> NFSv4 name encoding (RFC 7530 S1.4.2)");
	cd_or_skip(myname, dir, Nflag);

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	case_ascii();
	case_latin1();
	case_cjk();
	case_emoji();
	case_rename_across_widths();

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}
