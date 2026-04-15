/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * cb_recall_probe.c -- hand-rolled NFSv4.1 second-client OPEN+CLOSE probe.
 *
 * Creates an independent NFSv4.1 session and sends
 *   SEQUENCE + PUTROOTFH + LOOKUP* + OPEN(READ, CLAIM_NULL, NOCREATE)
 * followed by
 *   SEQUENCE + CLOSE
 *
 * Because this uses a separate clientid from the kernel NFS client, if the
 * kernel holds a WRITE delegation on the file the server MUST issue a
 * CB_RECALL callback to the kernel client before granting this OPEN.  The
 * kernel client flushes dirty data and returns the delegation before this
 * probe receives its OPEN response.
 *
 * This makes the tool useful as a "second client" in delegation recall tests
 * without requiring a second physical host.
 *
 * No external NFS library dependencies: uses raw TCP to port 2049 with
 * hand-rolled ONC RPC and NFSv4.1 XDR encoding (RFC 5531, RFC 5661).
 * AUTH_SYS credential uses the calling process's uid/gid.
 *
 * Usage:
 *   cb_recall_probe -s SERVER -p NFSPATH
 *
 *   -s SERVER   NFS server hostname or IP
 *   -p NFSPATH  Export-relative path to the file (e.g. "testdir/file")
 *
 * Output on success (stdout):
 *   opened and closed: ok
 *
 * Exit codes: 0 success, 1 NFS/RPC/network error, 2 usage error.
 *
 * NFSv4.1 protocol notes (RFC 5661):
 *   EXCHANGE_ID and CREATE_SESSION are bare COMPOUNDs (no SEQUENCE op).
 *   All subsequent COMPOUNDs must begin with SEQUENCE.  The slot table is
 *   initialized to eir_sequenceid after CREATE_SESSION; the first SEQUENCE
 *   uses sa_sequenceid = eir_sequenceid + 1.
 *
 *   OPEN with CLAIM_NULL uses the current filehandle as the parent directory;
 *   this probe LOOKUPs all path components except the last, then passes the
 *   last component as the CLAIM_NULL filename.
 */

#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "rpc_wire.h"

/* ------------------------------------------------------------------ */
/* Constants                                                           */
/* ------------------------------------------------------------------ */

#define NFSPROC4_COMPOUND   1u

/* NFSv4.1 operation numbers (RFC 5661 §15.2) */
#define OP_CLOSE            4u
#define OP_GETATTR          9u
#define OP_LOOKUP          15u
#define OP_OPEN            18u
#define OP_PUTROOTFH       24u
#define OP_EXCHANGE_ID     42u
#define OP_CREATE_SESSION  43u
#define OP_SEQUENCE        53u

#define NFS4_OK             0u
#define SP4_NONE            0u

/* OPEN share flags (RFC 5661 §18.16) */
#define OPEN4_SHARE_ACCESS_READ  1u
#define OPEN4_SHARE_DENY_NONE    0u
#define OPEN4_NOCREATE           0u   /* opentype4: RFC 5661 §18.16.1 */
#define CLAIM_NULL               0u   /* open_claim_type4 */

#define MAX_COMP  16
#define BUF_SZ    16384u

/* ------------------------------------------------------------------ */
/* TCP connect                                                          */
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
		fprintf(stderr, "cb_recall_probe: %s: %s\n",
			host, gai_strerror(r));
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
		fprintf(stderr, "cb_recall_probe: connect %s:2049: %s\n",
			host, strerror(err));
	return fd;
}

/* ------------------------------------------------------------------ */
/* RPC / COMPOUND encoding helpers                                     */
/* ------------------------------------------------------------------ */

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
		fprintf(stderr,
			"cb_recall_probe: multi-fragment reply not supported\n");
		return -1;
	}
	uint32_t blen = rm & ~RPC_LAST_FRAG;
	if (blen > sz) {
		fprintf(stderr, "cb_recall_probe: reply %u > buf %zu\n",
			blen, sz);
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
		fprintf(stderr, "cb_recall_probe: COMPOUND status %u\n", status);
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
/* EXCHANGE_ID                                                          */
/* ------------------------------------------------------------------ */

static int do_exchange_id(int fd, uint32_t xid, const char *owner_id,
			   uint64_t *clientid, uint32_t *seqid)
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
		fprintf(stderr, "cb_recall_probe: EXCHANGE_ID failed: %u\n",
			status);
		return -1;
	}

	if (!rpc_get_u64(buf, (size_t)rlen, &p, clientid)) return -1;
	if (!rpc_get_u32(buf, (size_t)rlen, &p, seqid))    return -1;
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

	/* fore channel_attrs4 */
	if (!rpc_put_u32(buf, sizeof(buf), &pos, 0u))       return -1;
	if (!rpc_put_u32(buf, sizeof(buf), &pos, 1048576u)) return -1;
	if (!rpc_put_u32(buf, sizeof(buf), &pos, 1048576u)) return -1;
	if (!rpc_put_u32(buf, sizeof(buf), &pos, 8192u))    return -1;
	if (!rpc_put_u32(buf, sizeof(buf), &pos, 32u))      return -1;
	if (!rpc_put_u32(buf, sizeof(buf), &pos, 1u))       return -1;
	if (!rpc_put_u32(buf, sizeof(buf), &pos, 0u))       return -1;

	/* back channel_attrs4 */
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
		fprintf(stderr, "cb_recall_probe: CREATE_SESSION failed: %u\n",
			status);
		return -1;
	}

	if (p + 16 > (size_t)rlen) return -1;
	memcpy(sessionid, buf + p, 16);
	return 0;
}

/* ------------------------------------------------------------------ */
/* open_delegation4 skip helper                                         */
/* ------------------------------------------------------------------ */

/*
 * skip_delegation -- advance *p past an open_delegation4 union in the
 * OPEN4resok response (RFC 5661 §18.16.4).
 *
 * dtype values:
 *   0 OPEN_DELEGATE_NONE      -- no data
 *   1 OPEN_DELEGATE_READ      -- stateid4(16) + recall(4) + nfsace4(var)
 *   2 OPEN_DELEGATE_WRITE     -- stateid4(16) + recall(4) + space_limit(12)
 *                                + nfsace4(var)
 *   3 OPEN_DELEGATE_NONE_EXT  -- why(4) + optional bool(4) (RFC 7862)
 *
 * Returns 0 on success, -1 if the delegation type is unknown or parse fails.
 */
static int skip_delegation(const uint8_t *buf, size_t len, size_t *p)
{
	uint32_t dtype;
	if (!rpc_get_u32(buf, len, p, &dtype)) return -1;

	switch (dtype) {
	case 0: /* OPEN_DELEGATE_NONE */
		return 0;

	case 1: { /* OPEN_DELEGATE_READ */
		/* stateid4(16) + recall(4) */
		if (!rpc_skip(len, p, 20)) return -1;
		/* nfsace4: acetype(4) + aceflag(4) + acemask(4) + who(opaque) */
		uint32_t ace_type, ace_flag, ace_mask, who_len;
		if (!rpc_get_u32(buf, len, p, &ace_type))  return -1;
		if (!rpc_get_u32(buf, len, p, &ace_flag))  return -1;
		if (!rpc_get_u32(buf, len, p, &ace_mask))  return -1;
		if (!rpc_get_u32(buf, len, p, &who_len))   return -1;
		return rpc_skip(len, p, (who_len + 3u) & ~3u) ? 0 : -1;
	}

	case 2: { /* OPEN_DELEGATE_WRITE */
		/* stateid4(16) + recall(4) */
		if (!rpc_skip(len, p, 20)) return -1;
		/* nfs_space_limit4: limitby(4) + 8 bytes (filesize or block pair) */
		uint32_t limitby;
		if (!rpc_get_u32(buf, len, p, &limitby)) return -1;
		if (!rpc_skip(len, p, 8)) return -1;
		/* nfsace4 */
		uint32_t ace_type, ace_flag, ace_mask, who_len;
		if (!rpc_get_u32(buf, len, p, &ace_type))  return -1;
		if (!rpc_get_u32(buf, len, p, &ace_flag))  return -1;
		if (!rpc_get_u32(buf, len, p, &ace_mask))  return -1;
		if (!rpc_get_u32(buf, len, p, &who_len))   return -1;
		return rpc_skip(len, p, (who_len + 3u) & ~3u) ? 0 : -1;
	}

	case 3: { /* OPEN_DELEGATE_NONE_EXT (RFC 7862) */
		/* ond4_why_no_deleg: why(4); WND4_CONTENTION=1 / WND4_RESOURCE=2
		 * carry an additional bool. */
		uint32_t why;
		if (!rpc_get_u32(buf, len, p, &why)) return -1;
		if (why == 1 || why == 2) {
			uint32_t bval;
			if (!rpc_get_u32(buf, len, p, &bval)) return -1;
		}
		return 0;
	}

	default:
		fprintf(stderr, "cb_recall_probe: unknown delegation type %u\n",
			dtype);
		return -1;
	}
}

/* ------------------------------------------------------------------ */
/* SEQUENCE + PUTROOTFH + LOOKUP* + OPEN                               */
/* ------------------------------------------------------------------ */

/*
 * do_open -- send OPEN(READ, NOCREATE, CLAIM_NULL) for the file at the
 * given path.  comp[0..n_comp-2] are directory components looked up via
 * LOOKUP; comp[n_comp-1] is the filename passed to CLAIM_NULL.
 *
 * On success, open_stateid[16] receives the stateid for use in CLOSE.
 */
static int do_open(int fd, uint32_t xid,
		   const uint8_t sessionid[16], uint32_t slot_seqid,
		   uint64_t clientid,
		   char **comp, int n_comp,
		   uint8_t open_stateid[16])
{
	static uint8_t buf[BUF_SZ];
	size_t pos;
	int n_lookup = n_comp - 1;
	const char *filename = comp[n_comp - 1];
	/* SEQUENCE + PUTROOTFH + LOOKUP*(n_lookup) + OPEN */
	uint32_t nops = (uint32_t)(2 + n_lookup + 1);

	if (!begin_call(buf, sizeof(buf), &pos, xid))  return -1;
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

	/* LOOKUP for each directory component */
	for (int i = 0; i < n_lookup; i++) {
		if (!rpc_put_u32(buf, sizeof(buf), &pos, OP_LOOKUP)) return -1;
		if (!rpc_put_str(buf, sizeof(buf), &pos,
				 comp[i], strlen(comp[i])))
			return -1;
	}

	/*
	 * OPEN: seqid(ignored in v4.1) + share_access + share_deny
	 *       + open_owner4{clientid, owner} + openhow{NOCREATE}
	 *       + claim{CLAIM_NULL, filename}
	 */
	if (!rpc_put_u32(buf, sizeof(buf), &pos, OP_OPEN))              return -1;
	if (!rpc_put_u32(buf, sizeof(buf), &pos, 0u))                   return -1;
	if (!rpc_put_u32(buf, sizeof(buf), &pos, OPEN4_SHARE_ACCESS_READ)) return -1;
	if (!rpc_put_u32(buf, sizeof(buf), &pos, OPEN4_SHARE_DENY_NONE))   return -1;
	if (!rpc_put_u64(buf, sizeof(buf), &pos, clientid))             return -1;
	if (!rpc_put_str(buf, sizeof(buf), &pos, "rp_owner", 8))        return -1;
	if (!rpc_put_u32(buf, sizeof(buf), &pos, OPEN4_NOCREATE))       return -1;
	if (!rpc_put_u32(buf, sizeof(buf), &pos, CLAIM_NULL))           return -1;
	if (!rpc_put_str(buf, sizeof(buf), &pos, filename, strlen(filename)))
		return -1;

	if (finish_and_send(fd, buf, pos) < 0) return -1;

	ssize_t rlen = recv_one(fd, buf, sizeof(buf));
	if (rlen < 0) return -1;

	size_t p = 0;
	uint32_t nres, resop, status = 0;
	if (!skip_rpc_hdr(buf, (size_t)rlen, &p))             return -1;
	if (!skip_compound_hdr(buf, (size_t)rlen, &p, &nres)) return -1;
	if (nres != nops)                                      return -1;

	/* SEQUENCE result: resop(4) + status(4) + SEQUENCE4resok(36) */
	if (!rpc_get_u32(buf, (size_t)rlen, &p, &resop) ||
	    resop != OP_SEQUENCE)
		return -1;
	if (!rpc_get_u32(buf, (size_t)rlen, &p, &status) || status != NFS4_OK) {
		fprintf(stderr, "cb_recall_probe: SEQUENCE failed: %u\n", status);
		return -1;
	}
	if (!rpc_skip((size_t)rlen, &p, 16 + 5 * 4)) return -1;

	/* PUTROOTFH result */
	if (!rpc_get_u32(buf, (size_t)rlen, &p, &resop) ||
	    resop != OP_PUTROOTFH)
		return -1;
	if (!rpc_get_u32(buf, (size_t)rlen, &p, &status) || status != NFS4_OK) {
		fprintf(stderr, "cb_recall_probe: PUTROOTFH failed: %u\n", status);
		return -1;
	}

	/* LOOKUP results */
	for (int i = 0; i < n_lookup; i++) {
		if (!rpc_get_u32(buf, (size_t)rlen, &p, &resop) ||
		    resop != OP_LOOKUP)
			return -1;
		if (!rpc_get_u32(buf, (size_t)rlen, &p, &status) ||
		    status != NFS4_OK) {
			fprintf(stderr,
				"cb_recall_probe: LOOKUP(%s) failed: %u\n",
				comp[i], status);
			return -1;
		}
	}

	/* OPEN result */
	if (!rpc_get_u32(buf, (size_t)rlen, &p, &resop) || resop != OP_OPEN)
		return -1;
	if (!rpc_get_u32(buf, (size_t)rlen, &p, &status) || status != NFS4_OK) {
		fprintf(stderr, "cb_recall_probe: OPEN failed: %u\n", status);
		return -1;
	}

	/*
	 * OPEN4resok: stateid4(16) + change_info4(20) + rflags(4) + attrset
	 * + open_delegation4.  We only need the stateid for CLOSE.
	 */
	if (p + 16 > (size_t)rlen) return -1;
	memcpy(open_stateid, buf + p, 16);
	p += 16;

	/* change_info4: atomic(4) + before(8) + after(8) = 20; rflags(4) */
	if (!rpc_skip((size_t)rlen, &p, 20 + 4)) return -1;

	/* attrset bitmap */
	uint32_t bm_len;
	if (!rpc_get_u32(buf, (size_t)rlen, &p, &bm_len)) return -1;
	if (!rpc_skip((size_t)rlen, &p, bm_len * 4))      return -1;

	/* delegation (best-effort parse; failure is non-fatal here) */
	if (skip_delegation(buf, (size_t)rlen, &p) < 0) {
		fprintf(stderr,
			"cb_recall_probe: warning: could not parse "
			"delegation in OPEN response (proceeding)\n");
	}

	return 0;
}

/* ------------------------------------------------------------------ */
/* SEQUENCE + CLOSE                                                     */
/* ------------------------------------------------------------------ */

static int do_close(int fd, uint32_t xid,
		    const uint8_t sessionid[16], uint32_t slot_seqid,
		    const uint8_t open_stateid[16])
{
	static uint8_t buf[BUF_SZ];
	size_t pos;
	uint32_t nops = 2u; /* SEQUENCE + CLOSE */

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

	/* CLOSE: seqid(4, ignored) + open_stateid(16) */
	if (!rpc_put_u32(buf, sizeof(buf), &pos, OP_CLOSE)) return -1;
	if (!rpc_put_u32(buf, sizeof(buf), &pos, 0u))       return -1;
	if (pos + 16 > sizeof(buf)) return -1;
	memcpy(buf + pos, open_stateid, 16);
	pos += 16;

	if (finish_and_send(fd, buf, pos) < 0) return -1;

	ssize_t rlen = recv_one(fd, buf, sizeof(buf));
	if (rlen < 0) return -1;

	size_t p = 0;
	uint32_t nres, resop, status = 0;
	if (!skip_rpc_hdr(buf, (size_t)rlen, &p))             return -1;
	if (!skip_compound_hdr(buf, (size_t)rlen, &p, &nres)) return -1;
	if (nres != nops)                                      return -1;

	if (!rpc_get_u32(buf, (size_t)rlen, &p, &resop) ||
	    resop != OP_SEQUENCE)
		return -1;
	if (!rpc_get_u32(buf, (size_t)rlen, &p, &status) || status != NFS4_OK) {
		fprintf(stderr,
			"cb_recall_probe: CLOSE SEQUENCE failed: %u\n", status);
		return -1;
	}
	if (!rpc_skip((size_t)rlen, &p, 16 + 5 * 4)) return -1;

	if (!rpc_get_u32(buf, (size_t)rlen, &p, &resop) || resop != OP_CLOSE)
		return -1;
	if (!rpc_get_u32(buf, (size_t)rlen, &p, &status) || status != NFS4_OK) {
		fprintf(stderr, "cb_recall_probe: CLOSE failed: %u\n", status);
		return -1;
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/* main                                                                 */
/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
	const char *server  = NULL;
	const char *nfspath = NULL;
	int c;

	while ((c = getopt(argc, argv, "s:p:h")) != -1) {
		switch (c) {
		case 's': server  = optarg; break;
		case 'p': nfspath = optarg; break;
		case 'h':
			printf("Usage: cb_recall_probe -s SERVER -p NFSPATH\n"
			       "Opens and closes the file via a separate NFSv4.1 session,\n"
			       "triggering CB_RECALL if the kernel holds a WRITE delegation.\n");
			return 0;
		default:
			fprintf(stderr,
				"Usage: cb_recall_probe -s SERVER -p NFSPATH\n");
			return 2;
		}
	}
	if (!server || !nfspath) {
		fprintf(stderr,
			"cb_recall_probe: -s SERVER and -p NFSPATH required\n");
		return 2;
	}

	char path_copy[1024];
	if (strlen(nfspath) >= sizeof(path_copy)) {
		fprintf(stderr, "cb_recall_probe: path too long\n");
		return 1;
	}
	strcpy(path_copy, nfspath);

	char *comp[MAX_COMP];
	int n_comp = 0;
	char *save, *tok = strtok_r(path_copy, "/", &save);
	while (tok) {
		if (*tok) {
			if (n_comp == MAX_COMP) {
				fprintf(stderr,
					"cb_recall_probe: path depth > %d\n",
					MAX_COMP);
				return 1;
			}
			comp[n_comp++] = tok;
		}
		tok = strtok_r(NULL, "/", &save);
	}
	if (n_comp == 0) {
		fprintf(stderr, "cb_recall_probe: empty or root-only path\n");
		return 1;
	}

	int fd = tcp_connect(server);
	if (fd < 0) return 1;

	char owner_id[128];
	char hostname[64] = "probe";
	gethostname(hostname, sizeof(hostname) - 1);
	snprintf(owner_id, sizeof(owner_id), "cb_recall_probe:%s:%u",
		 hostname, (unsigned)getpid());

	uint32_t xid      = (uint32_t)getpid() ^ 0xABC10000u;
	uint64_t clientid = 0;
	uint32_t seqid    = 0;

	if (do_exchange_id(fd, xid++, owner_id, &clientid, &seqid) < 0) {
		close(fd); return 1;
	}

	uint8_t sessionid[16];
	if (do_create_session(fd, xid++, clientid, seqid, sessionid) < 0) {
		close(fd); return 1;
	}

	/*
	 * First SEQUENCE after CREATE_SESSION uses sa_sequenceid = seqid + 1.
	 */
	uint8_t open_stateid[16] = { 0 };
	uint32_t slot_seqid = seqid + 1u;

	if (do_open(fd, xid++, sessionid, slot_seqid, clientid,
		    comp, n_comp, open_stateid) < 0) {
		close(fd); return 1;
	}
	slot_seqid++;

	if (do_close(fd, xid++, sessionid, slot_seqid, open_stateid) < 0) {
		close(fd); return 1;
	}

	close(fd);
	printf("opened and closed: ok\n");
	return 0;
}
