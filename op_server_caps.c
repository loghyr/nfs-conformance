/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * op_server_caps.c -- discover and verify NFSv4.1 server capabilities.
 *
 * Connects directly to the NFS server on TCP port 2049 (without a kernel
 * mount) and exercises two diagnostic COMPOUNDs:
 *
 * Cases:
 *
 *   1. EXCHANGE_ID (RFC 5661 §18.35): read eir_flags and verify the pNFS
 *      role bits are self-consistent per the RFC:
 *        • At least one of USE_NON_PNFS / USE_PNFS_MDS / USE_PNFS_DS is set.
 *        • USE_NON_PNFS and USE_PNFS_MDS are mutually exclusive.
 *
 *   2. SECINFO_NO_NAME (RFC 5661 §18.45): after establishing a session,
 *      send SEQUENCE + PUTROOTFH + SECINFO_NO_NAME(CURRENT_FH) and verify
 *      the server returns at least one supported security flavor.
 *
 * Requires -S SERVER.  Skips (exit 77) if -S is not provided.
 *
 * No -d DIR is needed: this test does not create files on any filesystem.
 *
 * Output (unless -s): prints decoded eir_flags and security flavors.
 *
 * Portable: works on any POSIX host with TCP access to the NFS server.
 *
 * eir_flags bit definitions (RFC 5661 §18.35.3):
 *   EXCHGID4_FLAG_SUPP_MOVED_REFER    0x00000001  referral support
 *   EXCHGID4_FLAG_SUPP_MOVED_MIGR     0x00000002  migration support
 *   EXCHGID4_FLAG_BIND_PRINC_STATEID  0x00000100  principal binding
 *   EXCHGID4_FLAG_USE_NON_PNFS        0x00010000  non-pNFS server
 *   EXCHGID4_FLAG_USE_PNFS_MDS        0x00020000  pNFS MDS role
 *   EXCHGID4_FLAG_USE_PNFS_DS         0x00040000  pNFS DS role
 */

#define _POSIX_C_SOURCE 200809L

#include "tests.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "rpc_wire.h"

int Hflag = 0;
int Sflag = 0;
int Tflag = 0;
int Fflag = 0;
int Nflag = 0;

static const char *myname = "op_server_caps";

/* eir_flags bit constants */
#define EXCHGID4_FLAG_SUPP_MOVED_REFER   0x00000001u
#define EXCHGID4_FLAG_SUPP_MOVED_MIGR    0x00000002u
#define EXCHGID4_FLAG_BIND_PRINC_STATEID 0x00000100u
#define EXCHGID4_FLAG_USE_NON_PNFS       0x00010000u
#define EXCHGID4_FLAG_USE_PNFS_MDS       0x00020000u
#define EXCHGID4_FLAG_USE_PNFS_DS        0x00040000u
#define EXCHGID4_FLAG_MASK_USE           0x00070000u

/* NFSv4.1 operation numbers */
#define NFSPROC4_COMPOUND    1u
#define OP_PUTROOTFH        24u
#define OP_EXCHANGE_ID      42u
#define OP_CREATE_SESSION   43u
#define OP_SEQUENCE         53u
#define OP_SECINFO_NO_NAME  58u

#define NFS4_OK   0u
#define SP4_NONE  0u

/* SECINFO_NO_NAME style (RFC 5661 §18.45) */
#define SECINFO_STYLE4_CURRENT_FH 0u

#define BUF_SZ 16384u

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-hst] [-S SERVER]\n"
		"  discover NFSv4.1 server capabilities via EXCHANGE_ID and "
		"SECINFO_NO_NAME\n"
		"  -h help  -s silent  -t timing\n"
		"  -S SERVER  NFS server hostname or IP (required)\n",
		myname);
}

/* ------------------------------------------------------------------ */
/* RPC / COMPOUND helpers (shared with probe tools, duplicated here)   */
/* ------------------------------------------------------------------ */

static int tcp_connect(const char *host)
{
	struct addrinfo hints, *ai, *a;
	int fd = -1, err = 0;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family   = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	int r = getaddrinfo(host, "2049", &hints, &ai);
	if (r) {
		fprintf(stderr, "%s: %s: %s\n", myname, host, gai_strerror(r));
		return -1;
	}
	for (a = ai; a; a = a->ai_next) {
		fd = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
		if (fd < 0) { err = errno; continue; }
		if (connect(fd, a->ai_addr, a->ai_addrlen) == 0) break;
		err = errno;
		close(fd);
		fd = -1;
	}
	freeaddrinfo(ai);
	if (fd < 0)
		fprintf(stderr, "%s: connect %s:2049: %s\n",
			myname, host, strerror(err));
	return fd;
}

static int put_authsys(uint8_t *buf, size_t sz, size_t *pos)
{
	uint8_t body[20];
	size_t b = 0;

	if (!rpc_put_u32(body, sizeof(body), &b, 0u))                 return 0;
	if (!rpc_put_u32(body, sizeof(body), &b, 0u))                 return 0;
	if (!rpc_put_u32(body, sizeof(body), &b, (uint32_t)getuid())) return 0;
	if (!rpc_put_u32(body, sizeof(body), &b, (uint32_t)getgid())) return 0;
	if (!rpc_put_u32(body, sizeof(body), &b, 0u))                 return 0;

	if (!rpc_put_u32(buf, sz, pos, RPC_AUTH_SYS)) return 0;
	if (!rpc_put_u32(buf, sz, pos, (uint32_t)b))  return 0;
	if (*pos + b > sz)                             return 0;
	memcpy(buf + *pos, body, b);
	*pos += b;
	return 1;
}

static int begin_call(uint8_t *buf, size_t sz, size_t *pos, uint32_t xid)
{
	*pos = 4;
	if (!rpc_put_u32(buf, sz, pos, xid))               return 0;
	if (!rpc_put_u32(buf, sz, pos, RPC_CALL))          return 0;
	if (!rpc_put_u32(buf, sz, pos, 2u))                return 0;
	if (!rpc_put_u32(buf, sz, pos, NFS_PROGRAM))       return 0;
	if (!rpc_put_u32(buf, sz, pos, NFS_VERSION_4))     return 0;
	if (!rpc_put_u32(buf, sz, pos, NFSPROC4_COMPOUND)) return 0;
	if (!put_authsys(buf, sz, pos))                    return 0;
	if (!rpc_put_u32(buf, sz, pos, RPC_AUTH_NONE))     return 0;
	if (!rpc_put_u32(buf, sz, pos, 0u))                return 0;
	return 1;
}

static int finish_and_send(int fd, uint8_t *buf, size_t total)
{
	uint32_t rm = htonl((uint32_t)(RPC_LAST_FRAG | (total - 4)));
	memcpy(buf, &rm, 4);
	return (rpc_writen(fd, buf, total) == (ssize_t)total) ? 0 : -1;
}

static ssize_t recv_one(int fd, uint8_t *buf, size_t sz)
{
	uint8_t hdr[4];
	if (rpc_readn(fd, hdr, 4) != 4) return -1;

	uint32_t rm;
	memcpy(&rm, hdr, 4);
	rm = ntohl(rm);
	if (!(rm & RPC_LAST_FRAG)) {
		fprintf(stderr, "%s: multi-fragment reply not supported\n",
			myname);
		return -1;
	}
	uint32_t blen = rm & ~RPC_LAST_FRAG;
	if (blen > sz) {
		fprintf(stderr, "%s: reply %u > buf %zu\n", myname, blen, sz);
		return -1;
	}
	if (rpc_readn(fd, buf, blen) != (ssize_t)blen) return -1;
	return (ssize_t)blen;
}

static int skip_rpc_hdr(const uint8_t *buf, size_t len, size_t *p)
{
	uint32_t v;
	if (!rpc_get_u32(buf, len, p, &v)) return 0;
	if (!rpc_get_u32(buf, len, p, &v) || v != RPC_REPLY)        return 0;
	if (!rpc_get_u32(buf, len, p, &v) || v != RPC_MSG_ACCEPTED) return 0;
	if (!rpc_get_u32(buf, len, p, &v)) return 0;
	if (!rpc_get_u32(buf, len, p, &v)) return 0;
	if (v && !rpc_skip(len, p, (v + 3u) & ~3u)) return 0;
	if (!rpc_get_u32(buf, len, p, &v) || v != 0u) return 0;
	return 1;
}

static int skip_compound_hdr(const uint8_t *buf, size_t len, size_t *p,
			      uint32_t *nres)
{
	uint32_t status, tlen;
	if (!rpc_get_u32(buf, len, p, &status)) return 0;
	if (status != NFS4_OK) {
		fprintf(stderr, "%s: COMPOUND status %u\n", myname, status);
		return 0;
	}
	if (!rpc_get_u32(buf, len, p, &tlen)) return 0;
	if (tlen && !rpc_skip(len, p, (tlen + 3u) & ~3u)) return 0;
	return rpc_get_u32(buf, len, p, nres);
}

static int compound_hdr(uint8_t *buf, size_t sz, size_t *pos, uint32_t nops)
{
	if (!rpc_put_u32(buf, sz, pos, 0u))   return 0;
	if (!rpc_put_u32(buf, sz, pos, 1u))   return 0;
	if (!rpc_put_u32(buf, sz, pos, nops)) return 0;
	return 1;
}

/* ------------------------------------------------------------------ */
/* EXCHANGE_ID (returns clientid, seqid, and eir_flags)                */
/* ------------------------------------------------------------------ */

static int do_exchange_id(int fd, uint32_t xid, const char *owner_id,
			   uint64_t *clientid, uint32_t *seqid,
			   uint32_t *eir_flags)
{
	static uint8_t buf[BUF_SZ];
	size_t pos;

	if (!begin_call(buf, sizeof(buf), &pos, xid))  return -1;
	if (!compound_hdr(buf, sizeof(buf), &pos, 1u)) return -1;

	if (!rpc_put_u32(buf, sizeof(buf), &pos, OP_EXCHANGE_ID)) return -1;

	struct timeval tv;
	gettimeofday(&tv, NULL);
	if (!rpc_put_u32(buf, sizeof(buf), &pos, (uint32_t)tv.tv_sec)) return -1;
	if (!rpc_put_u32(buf, sizeof(buf), &pos, (uint32_t)getpid()))  return -1;
	if (!rpc_put_str(buf, sizeof(buf), &pos, owner_id, strlen(owner_id)))
		return -1;

	if (!rpc_put_u32(buf, sizeof(buf), &pos, 0u))       return -1;
	if (!rpc_put_u32(buf, sizeof(buf), &pos, SP4_NONE)) return -1;
	if (!rpc_put_u32(buf, sizeof(buf), &pos, 0u))       return -1;

	if (finish_and_send(fd, buf, pos) < 0) return -1;

	ssize_t rlen = recv_one(fd, buf, sizeof(buf));
	if (rlen < 0) return -1;

	size_t p = 0;
	uint32_t nres, resop, status = 0;
	if (!skip_rpc_hdr(buf, (size_t)rlen, &p))             return -1;
	if (!skip_compound_hdr(buf, (size_t)rlen, &p, &nres)) return -1;
	if (nres != 1)                                         return -1;

	if (!rpc_get_u32(buf, (size_t)rlen, &p, &resop) ||
	    resop != OP_EXCHANGE_ID)
		return -1;
	if (!rpc_get_u32(buf, (size_t)rlen, &p, &status) || status != NFS4_OK) {
		fprintf(stderr, "%s: EXCHANGE_ID failed: %u\n", myname, status);
		return -1;
	}

	if (!rpc_get_u64(buf, (size_t)rlen, &p, clientid))  return -1;
	if (!rpc_get_u32(buf, (size_t)rlen, &p, seqid))     return -1;
	if (!rpc_get_u32(buf, (size_t)rlen, &p, eir_flags)) return -1;
	return 0;
}

/* ------------------------------------------------------------------ */
/* CREATE_SESSION                                                       */
/* ------------------------------------------------------------------ */

static int do_create_session(int fd, uint32_t xid,
			      uint64_t clientid, uint32_t seqid,
			      uint8_t sessionid[16])
{
	static uint8_t buf[BUF_SZ];
	size_t pos;

	if (!begin_call(buf, sizeof(buf), &pos, xid))  return -1;
	if (!compound_hdr(buf, sizeof(buf), &pos, 1u)) return -1;

	if (!rpc_put_u32(buf, sizeof(buf), &pos, OP_CREATE_SESSION)) return -1;
	if (!rpc_put_u64(buf, sizeof(buf), &pos, clientid))          return -1;
	if (!rpc_put_u32(buf, sizeof(buf), &pos, seqid))             return -1;
	if (!rpc_put_u32(buf, sizeof(buf), &pos, 0u))                return -1;

	if (!rpc_put_u32(buf, sizeof(buf), &pos, 0u))       return -1;
	if (!rpc_put_u32(buf, sizeof(buf), &pos, 1048576u)) return -1;
	if (!rpc_put_u32(buf, sizeof(buf), &pos, 1048576u)) return -1;
	if (!rpc_put_u32(buf, sizeof(buf), &pos, 8192u))    return -1;
	if (!rpc_put_u32(buf, sizeof(buf), &pos, 32u))      return -1;
	if (!rpc_put_u32(buf, sizeof(buf), &pos, 1u))       return -1;
	if (!rpc_put_u32(buf, sizeof(buf), &pos, 0u))       return -1;

	if (!rpc_put_u32(buf, sizeof(buf), &pos, 0u))      return -1;
	if (!rpc_put_u32(buf, sizeof(buf), &pos, 4096u))   return -1;
	if (!rpc_put_u32(buf, sizeof(buf), &pos, 4096u))   return -1;
	if (!rpc_put_u32(buf, sizeof(buf), &pos, 4096u))   return -1;
	if (!rpc_put_u32(buf, sizeof(buf), &pos, 4u))      return -1;
	if (!rpc_put_u32(buf, sizeof(buf), &pos, 1u))      return -1;
	if (!rpc_put_u32(buf, sizeof(buf), &pos, 0u))      return -1;

	if (!rpc_put_u32(buf, sizeof(buf), &pos, 0x40000001u)) return -1;
	if (!rpc_put_u32(buf, sizeof(buf), &pos, 1u))           return -1;
	if (!rpc_put_u32(buf, sizeof(buf), &pos, 0u))           return -1;

	if (finish_and_send(fd, buf, pos) < 0) return -1;

	ssize_t rlen = recv_one(fd, buf, sizeof(buf));
	if (rlen < 0) return -1;

	size_t p = 0;
	uint32_t nres, resop, status = 0;
	if (!skip_rpc_hdr(buf, (size_t)rlen, &p))             return -1;
	if (!skip_compound_hdr(buf, (size_t)rlen, &p, &nres)) return -1;
	if (nres != 1)                                         return -1;

	if (!rpc_get_u32(buf, (size_t)rlen, &p, &resop) ||
	    resop != OP_CREATE_SESSION)
		return -1;
	if (!rpc_get_u32(buf, (size_t)rlen, &p, &status) || status != NFS4_OK) {
		fprintf(stderr, "%s: CREATE_SESSION failed: %u\n",
			myname, status);
		return -1;
	}

	if (p + 16 > (size_t)rlen) return -1;
	memcpy(sessionid, buf + p, 16);
	return 0;
}

/* ------------------------------------------------------------------ */
/* SEQUENCE + PUTROOTFH + SECINFO_NO_NAME                              */
/* ------------------------------------------------------------------ */

/*
 * parse_secinfo_array -- parse and optionally print the secinfo4 array.
 *
 * Each secinfo4 entry is: flavor(4); if flavor==RPCSEC_GSS: oid(opaque<>)
 * + qop(4) + service(4).  Returns number of flavors on success, -1 on parse
 * failure.
 */
static int parse_secinfo_array(const uint8_t *buf, size_t len, size_t *p,
				int verbose)
{
	uint32_t nflavors;
	if (!rpc_get_u32(buf, len, p, &nflavors)) return -1;

	for (uint32_t i = 0; i < nflavors; i++) {
		uint32_t flavor;
		if (!rpc_get_u32(buf, len, p, &flavor)) return -1;

		if (verbose) {
			switch (flavor) {
			case 0: printf("  flavor: AUTH_NONE\n");  break;
			case 1: printf("  flavor: AUTH_SYS\n");   break;
			case 6: printf("  flavor: RPCSEC_GSS\n"); break;
			default: printf("  flavor: %u\n", flavor); break;
			}
		}

		if (flavor == 6u /* RPCSEC_GSS */) {
			/* rpcsec_gss_info: oid(opaque<>) + qop(4) + service(4) */
			uint32_t oid_len;
			if (!rpc_get_u32(buf, len, p, &oid_len)) return -1;
			if (!rpc_skip(len, p, (oid_len + 3u) & ~3u)) return -1;
			uint32_t qop, service;
			if (!rpc_get_u32(buf, len, p, &qop))     return -1;
			if (!rpc_get_u32(buf, len, p, &service)) return -1;
			if (verbose) {
				const char *svc =
					service == 1 ? "none" :
					service == 2 ? "integrity" :
					service == 3 ? "privacy" : "?";
				printf("    gss_service: %s\n", svc);
			}
		}
	}
	return (int)nflavors;
}

static int do_secinfo(int fd, uint32_t xid,
		      const uint8_t sessionid[16], uint32_t slot_seqid,
		      int verbose)
{
	static uint8_t buf[BUF_SZ];
	size_t pos;
	uint32_t nops = 3u; /* SEQUENCE + PUTROOTFH + SECINFO_NO_NAME */

	if (!begin_call(buf, sizeof(buf), &pos, xid))   return -1;
	if (!compound_hdr(buf, sizeof(buf), &pos, nops)) return -1;

	/* SEQUENCE */
	if (!rpc_put_u32(buf, sizeof(buf), &pos, OP_SEQUENCE)) return -1;
	if (pos + 16 > sizeof(buf)) return -1;
	memcpy(buf + pos, sessionid, 16);
	pos += 16;
	if (!rpc_put_u32(buf, sizeof(buf), &pos, slot_seqid)) return -1;
	if (!rpc_put_u32(buf, sizeof(buf), &pos, 0u))          return -1;
	if (!rpc_put_u32(buf, sizeof(buf), &pos, 0u))          return -1;
	if (!rpc_put_u32(buf, sizeof(buf), &pos, 0u))          return -1;

	/* PUTROOTFH */
	if (!rpc_put_u32(buf, sizeof(buf), &pos, OP_PUTROOTFH)) return -1;

	/* SECINFO_NO_NAME: style = SECINFO_STYLE4_CURRENT_FH */
	if (!rpc_put_u32(buf, sizeof(buf), &pos, OP_SECINFO_NO_NAME))    return -1;
	if (!rpc_put_u32(buf, sizeof(buf), &pos, SECINFO_STYLE4_CURRENT_FH))
		return -1;

	if (finish_and_send(fd, buf, pos) < 0) return -1;

	ssize_t rlen = recv_one(fd, buf, sizeof(buf));
	if (rlen < 0) return -1;

	size_t p = 0;
	uint32_t nres, resop, status = 0;
	if (!skip_rpc_hdr(buf, (size_t)rlen, &p))             return -1;
	if (!skip_compound_hdr(buf, (size_t)rlen, &p, &nres)) return -1;
	if (nres != nops)                                      return -1;

	/* SEQUENCE result */
	if (!rpc_get_u32(buf, (size_t)rlen, &p, &resop) || resop != OP_SEQUENCE)
		return -1;
	if (!rpc_get_u32(buf, (size_t)rlen, &p, &status) || status != NFS4_OK) {
		fprintf(stderr, "%s: SEQUENCE failed: %u\n", myname, status);
		return -1;
	}
	if (!rpc_skip((size_t)rlen, &p, 16 + 5 * 4)) return -1;

	/* PUTROOTFH result */
	if (!rpc_get_u32(buf, (size_t)rlen, &p, &resop) || resop != OP_PUTROOTFH)
		return -1;
	if (!rpc_get_u32(buf, (size_t)rlen, &p, &status) || status != NFS4_OK) {
		fprintf(stderr, "%s: PUTROOTFH failed: %u\n", myname, status);
		return -1;
	}

	/* SECINFO_NO_NAME result */
	if (!rpc_get_u32(buf, (size_t)rlen, &p, &resop) ||
	    resop != OP_SECINFO_NO_NAME)
		return -1;
	if (!rpc_get_u32(buf, (size_t)rlen, &p, &status)) return -1;
	if (status != NFS4_OK) {
		/* Non-fatal: server may not support SECINFO_NO_NAME at root. */
		fprintf(stderr,
			"NOTE: %s: SECINFO_NO_NAME status %u "
			"(server may not support it at root)\n",
			myname, status);
		return 1; /* sentinel: skip quietly, not an empty flavor list */
	}

	return parse_secinfo_array(buf, (size_t)rlen, &p, verbose);
}

/* ------------------------------------------------------------------ */
/* Test cases                                                           */
/* ------------------------------------------------------------------ */

static void case_exchange_id(const char *server)
{
	int fd = tcp_connect(server);
	if (fd < 0) {
		complain("case1: cannot connect to %s:2049", server);
		return;
	}

	char owner_id[128];
	char hostname[64] = "probe";
	gethostname(hostname, sizeof(hostname) - 1);
	snprintf(owner_id, sizeof(owner_id), "op_server_caps:%s:%u",
		 hostname, (unsigned)getpid());

	uint32_t xid = (uint32_t)getpid() ^ 0xCA000000u;
	uint64_t clientid  = 0;
	uint32_t seqid     = 0;
	uint32_t eir_flags = 0;

	if (do_exchange_id(fd, xid, owner_id, &clientid, &seqid,
			   &eir_flags) < 0) {
		complain("case1: EXCHANGE_ID failed");
		close(fd);
		return;
	}
	close(fd);

	if (!Sflag) {
		printf("  eir_flags: 0x%08x\n", eir_flags);
		if (eir_flags & EXCHGID4_FLAG_SUPP_MOVED_REFER)
			printf("    SUPP_MOVED_REFER (referrals supported)\n");
		if (eir_flags & EXCHGID4_FLAG_SUPP_MOVED_MIGR)
			printf("    SUPP_MOVED_MIGR (migration supported)\n");
		if (eir_flags & EXCHGID4_FLAG_BIND_PRINC_STATEID)
			printf("    BIND_PRINC_STATEID\n");
		if (eir_flags & EXCHGID4_FLAG_USE_NON_PNFS)
			printf("    USE_NON_PNFS (non-pNFS server)\n");
		if (eir_flags & EXCHGID4_FLAG_USE_PNFS_MDS)
			printf("    USE_PNFS_MDS (server is a pNFS MDS)\n");
		if (eir_flags & EXCHGID4_FLAG_USE_PNFS_DS)
			printf("    USE_PNFS_DS (server is a pNFS DS)\n");
	}

	/* RFC 5661 §18.35.3 invariant: at least one USE_* bit must be set. */
	if ((eir_flags & EXCHGID4_FLAG_MASK_USE) == 0)
		complain("case1: eir_flags 0x%08x has no USE_* pNFS role bits "
			 "(RFC 5661 §18.35.3 violation)", eir_flags);

	/*
	 * USE_NON_PNFS and USE_PNFS_MDS are mutually exclusive.
	 * (A DS-only server may combine USE_PNFS_DS with either; only the
	 * combination of USE_NON_PNFS + USE_PNFS_MDS is forbidden.)
	 */
	if ((eir_flags & EXCHGID4_FLAG_USE_NON_PNFS) &&
	    (eir_flags & EXCHGID4_FLAG_USE_PNFS_MDS))
		complain("case1: eir_flags 0x%08x has both USE_NON_PNFS and "
			 "USE_PNFS_MDS set (mutually exclusive per RFC 5661 "
			 "§18.35.3)", eir_flags);
}

static void case_secinfo(const char *server)
{
	int fd = tcp_connect(server);
	if (fd < 0) {
		complain("case2: cannot connect to %s:2049", server);
		return;
	}

	char owner_id[128];
	char hostname[64] = "probe";
	gethostname(hostname, sizeof(hostname) - 1);
	snprintf(owner_id, sizeof(owner_id), "op_server_caps_si:%s:%u",
		 hostname, (unsigned)getpid());

	uint32_t xid = (uint32_t)getpid() ^ 0xCA010000u;
	uint64_t clientid  = 0;
	uint32_t seqid     = 0;
	uint32_t eir_flags = 0;

	if (do_exchange_id(fd, xid++, owner_id, &clientid, &seqid,
			   &eir_flags) < 0) {
		complain("case2: EXCHANGE_ID failed");
		close(fd);
		return;
	}

	uint8_t sessionid[16];
	if (do_create_session(fd, xid++, clientid, seqid, sessionid) < 0) {
		complain("case2: CREATE_SESSION failed");
		close(fd);
		return;
	}

	if (!Sflag)
		printf("  security flavors for root export:\n");

	int nflavors = do_secinfo(fd, xid, sessionid, seqid + 1u,
				  !Sflag /* verbose */);
	close(fd);

	if (nflavors < 0) {
		complain("case2: SECINFO_NO_NAME parse failed");
	} else if (nflavors == 0) {
		complain("case2: server returned empty security flavor list "
			 "for root export");
	}
	/* nflavors == 1: non-fatal skip (server does not support at root) */
}

/* ------------------------------------------------------------------ */
/* main                                                                 */
/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
	const char *server = NULL;
	struct timespec t0, t1;

	while (--argc > 0 && argv[1][0] == '-') {
		argv++;
		for (const char *p = &argv[0][1]; *p; p++) {
			switch (*p) {
			case 'd': /* ignored: no filesystem ops in this test */
				if (argc < 2) { usage(); return TEST_FAIL; }
				argv++; argc--;
				goto next;
			case 'h': Hflag = 1; break;
			case 's': Sflag = 1; break;
			case 't': Tflag = 1; break;
			case 'S':
				if (argc < 2) { usage(); return TEST_FAIL; }
				server = argv[1];
				argv++; argc--;
				goto next;
			default: usage(); return TEST_FAIL;
			}
		}
next:
		;
	}
	if (Hflag) { usage(); return TEST_PASS; }

	if (!server)
		skip("%s: -S SERVER required (NFS server not specified)", myname);

	prelude(myname,
		"NFSv4.1 server capabilities via EXCHANGE_ID + SECINFO_NO_NAME");

	if (Tflag) clock_gettime(CLOCK_MONOTONIC, &t0);

	RUN_CASE("case_exchange_id", case_exchange_id(server));
	RUN_CASE("case_secinfo", case_secinfo(server));

	if (Tflag) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		double ms = (t1.tv_sec - t0.tv_sec) * 1e3
			    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
		printf("TIME: %s: %.1f ms\n", myname, ms);
	}

	return finish(myname);
}
