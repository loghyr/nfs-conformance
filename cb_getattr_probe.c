/* SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com> */
/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/*
 * cb_getattr_probe.c -- hand-rolled NFSv4.1 second-client GETATTR probe.
 *
 * Creates an independent NFSv4.1 session (EXCHANGE_ID → CREATE_SESSION)
 * and then sends SEQUENCE + PUTROOTFH + per-component LOOKUP + GETATTR
 * to retrieve FATTR4_SIZE and FATTR4_CHANGE for an export-relative path.
 *
 * Because this establishes a separate NFS clientid from the kernel NFS
 * client, the server will issue a CB_GETATTR callback to any client
 * holding a WRITE delegation on the file before answering.  This makes the
 * tool useful as a "second client" in delegation attribute tests without
 * requiring a second physical host.
 *
 * No external NFS library dependencies: uses raw TCP to port 2049 with
 * hand-rolled ONC RPC and NFSv4.1 XDR encoding (RFC 5531, RFC 5661).
 * AUTH_SYS credential uses the calling process's uid/gid.
 *
 * Usage:
 *   cb_getattr_probe -s SERVER -p NFSPATH
 *
 *   -s SERVER   NFS server hostname or IP
 *   -p NFSPATH  Export-relative path (e.g. "testdir/file" or "file")
 *
 * Output on success (stdout, one line):
 *   size=<N> change=<N>
 *
 * Exit codes: 0 success, 1 NFS/RPC/network error, 2 usage error.
 *
 * NFSv4.1 protocol note (RFC 5661):
 *   EXCHANGE_ID and CREATE_SESSION are bare COMPOUNDs (no SEQUENCE op).
 *   All subsequent COMPOUNDs must begin with SEQUENCE.  The slot table
 *   is initialized to eir_sequenceid after CREATE_SESSION; the first
 *   SEQUENCE uses sa_sequenceid = eir_sequenceid + 1.
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

/* NFSPROC4_COMPOUND procedure number (RFC 7530 §17) */
#define NFSPROC4_COMPOUND  1u

/* NFSv4.1 operation numbers (RFC 5661 §15.2) */
#define OP_GETATTR         9u
#define OP_LOOKUP         15u
#define OP_PUTROOTFH      24u
#define OP_EXCHANGE_ID    42u
#define OP_CREATE_SESSION 43u
#define OP_SEQUENCE       53u

/* NFS4_OK (RFC 7530 §13) */
#define NFS4_OK 0u

/* State protect: SP4_NONE (RFC 5661 §18.35) */
#define SP4_NONE 0u

/* FATTR4 attribute bits in word 0 (RFC 5661 §11.4) */
#define FATTR4_CHANGE_BIT  (1U << 3)   /* attribute 3 */
#define FATTR4_SIZE_BIT    (1U << 4)   /* attribute 4 */

/* Maximum export-relative path depth */
#define MAX_COMP 16

/* I/O buffer size (single-fragment replies only) */
#define BUF_SZ 16384u

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
		fprintf(stderr, "cb_getattr_probe: %s: %s\n",
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
		fprintf(stderr, "cb_getattr_probe: connect %s:2049: %s\n",
			host, strerror(err));
	return fd;
}

/* ------------------------------------------------------------------ */
/* RPC / COMPOUND encoding helpers                                     */
/* ------------------------------------------------------------------ */

/*
 * put_authsys -- write AUTH_SYS credential (flavor + body) at *pos.
 * stamp=0, machinename="", uid/gid from calling process, no supplementary.
 */
static int put_authsys(uint8_t *buf, size_t sz, size_t *pos)
{
	uint8_t body[20];
	size_t b = 0;

	if (!rpc_put_u32(body, sizeof(body), &b, 0u))                  return 0;
	if (!rpc_put_u32(body, sizeof(body), &b, 0u))                  return 0;
	if (!rpc_put_u32(body, sizeof(body), &b, (uint32_t)getuid()))  return 0;
	if (!rpc_put_u32(body, sizeof(body), &b, (uint32_t)getgid()))  return 0;
	if (!rpc_put_u32(body, sizeof(body), &b, 0u))                  return 0;

	if (!rpc_put_u32(buf, sz, pos, RPC_AUTH_SYS))  return 0;
	if (!rpc_put_u32(buf, sz, pos, (uint32_t)b))   return 0;
	if (*pos + b > sz)                              return 0;
	memcpy(buf + *pos, body, b);
	*pos += b;
	return 1;
}

/*
 * begin_call -- reserve 4 bytes for the TCP record marker, then write the
 * RPC CALL header + AUTH_SYS cred + AUTH_NONE verifier.  Caller appends
 * the COMPOUND body, then calls finish_and_send().
 */
static int begin_call(uint8_t *buf, size_t sz, size_t *pos, uint32_t xid)
{
	*pos = 4; /* placeholder for TCP record marker */

	if (!rpc_put_u32(buf, sz, pos, xid))                  return 0;
	if (!rpc_put_u32(buf, sz, pos, RPC_CALL))             return 0;
	if (!rpc_put_u32(buf, sz, pos, 2u))                   return 0; /* rpcvers */
	if (!rpc_put_u32(buf, sz, pos, NFS_PROGRAM))          return 0;
	if (!rpc_put_u32(buf, sz, pos, NFS_VERSION_4))        return 0;
	if (!rpc_put_u32(buf, sz, pos, NFSPROC4_COMPOUND))    return 0;
	if (!put_authsys(buf, sz, pos))                        return 0;
	if (!rpc_put_u32(buf, sz, pos, RPC_AUTH_NONE))        return 0;
	if (!rpc_put_u32(buf, sz, pos, 0u))                   return 0;
	return 1;
}

/*
 * finish_and_send -- fill in the TCP record marker and write the buffer.
 */
static int finish_and_send(int fd, uint8_t *buf, size_t total)
{
	uint32_t rm = htonl((uint32_t)(RPC_LAST_FRAG | (total - 4)));
	memcpy(buf, &rm, 4);
	return (rpc_writen(fd, buf, total) == (ssize_t)total) ? 0 : -1;
}

/*
 * recv_one -- read a single-fragment RPC reply.
 * Returns body byte count on success, -1 on error.
 */
static ssize_t recv_one(int fd, uint8_t *buf, size_t sz)
{
	uint8_t hdr[4];
	if (rpc_readn(fd, hdr, 4) != 4) return -1;

	uint32_t rm;
	memcpy(&rm, hdr, 4);
	rm = ntohl(rm);

	if (!(rm & RPC_LAST_FRAG)) {
		fprintf(stderr,
			"cb_getattr_probe: multi-fragment reply not supported\n");
		return -1;
	}
	uint32_t blen = rm & ~RPC_LAST_FRAG;
	if (blen > sz) {
		fprintf(stderr, "cb_getattr_probe: reply %u > buf %zu\n",
			blen, sz);
		return -1;
	}
	if (rpc_readn(fd, buf, blen) != (ssize_t)blen) return -1;
	return (ssize_t)blen;
}

/*
 * skip_rpc_hdr -- advance past xid / reply_stat / verf / accept_stat.
 * Returns 1 if the reply is ACCEPTED+SUCCESS, 0 otherwise.
 */
static int skip_rpc_hdr(const uint8_t *buf, size_t len, size_t *p)
{
	uint32_t v;
	if (!rpc_get_u32(buf, len, p, &v)) return 0; /* xid */
	if (!rpc_get_u32(buf, len, p, &v) || v != RPC_REPLY)        return 0;
	if (!rpc_get_u32(buf, len, p, &v) || v != RPC_MSG_ACCEPTED) return 0;
	/* verifier: flavor + len (+ optional body) */
	if (!rpc_get_u32(buf, len, p, &v)) return 0;
	if (!rpc_get_u32(buf, len, p, &v)) return 0;
	if (v && !rpc_skip(len, p, (v + 3u) & ~3u)) return 0;
	if (!rpc_get_u32(buf, len, p, &v) || v != 0u /* SUCCESS */) return 0;
	return 1;
}

/*
 * skip_compound_hdr -- read COMPOUND4res status + tag + resarray_len.
 * Returns 1 on NFS4_OK with *nres filled; 0 on error or non-OK status.
 */
static int skip_compound_hdr(const uint8_t *buf, size_t len, size_t *p,
			      uint32_t *nres)
{
	uint32_t status, tlen;
	if (!rpc_get_u32(buf, len, p, &status)) return 0;
	if (status != NFS4_OK) {
		fprintf(stderr, "cb_getattr_probe: COMPOUND status %u\n", status);
		return 0;
	}
	if (!rpc_get_u32(buf, len, p, &tlen)) return 0;
	if (tlen && !rpc_skip(len, p, (tlen + 3u) & ~3u)) return 0;
	return rpc_get_u32(buf, len, p, nres);
}

/* compound_hdr -- write COMPOUND4 tag="" + minorversion=1 + nops. */
static int compound_hdr(uint8_t *buf, size_t sz, size_t *pos, uint32_t nops)
{
	if (!rpc_put_u32(buf, sz, pos, 0u))   return 0; /* tag len=0 */
	if (!rpc_put_u32(buf, sz, pos, 1u))   return 0; /* minorversion=1 */
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

	if (!begin_call(buf, sizeof(buf), &pos, xid))       return -1;
	if (!compound_hdr(buf, sizeof(buf), &pos, 1u))      return -1;

	if (!rpc_put_u32(buf, sizeof(buf), &pos, OP_EXCHANGE_ID)) return -1;

	/*
	 * client_owner4: co_verifier (8 bytes, any unique value) + co_ownerid.
	 * Use pid + gettimeofday so restarts get a fresh clientid.
	 */
	struct timeval tv;
	gettimeofday(&tv, NULL);
	if (!rpc_put_u32(buf, sizeof(buf), &pos, (uint32_t)tv.tv_sec)) return -1;
	if (!rpc_put_u32(buf, sizeof(buf), &pos, (uint32_t)getpid()))  return -1;
	if (!rpc_put_str(buf, sizeof(buf), &pos, owner_id, strlen(owner_id)))
		return -1;

	/* eia_flags=0, spa_how=SP4_NONE=0, impl_id array len=0 */
	if (!rpc_put_u32(buf, sizeof(buf), &pos, 0u))      return -1;
	if (!rpc_put_u32(buf, sizeof(buf), &pos, SP4_NONE)) return -1;
	if (!rpc_put_u32(buf, sizeof(buf), &pos, 0u))      return -1;

	if (finish_and_send(fd, buf, pos) < 0) return -1;

	ssize_t rlen = recv_one(fd, buf, sizeof(buf));
	if (rlen < 0) return -1;

	size_t p = 0;
	uint32_t nres, resop, status = 0;
	if (!skip_rpc_hdr(buf, (size_t)rlen, &p))               return -1;
	if (!skip_compound_hdr(buf, (size_t)rlen, &p, &nres))   return -1;
	if (nres != 1)                                           return -1;

	if (!rpc_get_u32(buf, (size_t)rlen, &p, &resop) ||
	    resop != OP_EXCHANGE_ID)
		return -1;
	if (!rpc_get_u32(buf, (size_t)rlen, &p, &status) ||
	    status != NFS4_OK) {
		fprintf(stderr,
			"cb_getattr_probe: EXCHANGE_ID failed: status=%u\n",
			status);
		return -1;
	}

	if (!rpc_get_u64(buf, (size_t)rlen, &p, clientid)) return -1;
	if (!rpc_get_u32(buf, (size_t)rlen, &p, seqid))    return -1;
	/* ignore remainder: eir_flags, state_protect, server_owner, etc. */
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

	/*
	 * fore channel_attrs4: headerpadsize, maxrequestsize,
	 * maxresponsesize, maxresponsesize_cached, maxoperations,
	 * maxrequests, rdma_ird (0 elements).
	 */
	if (!rpc_put_u32(buf, sizeof(buf), &pos, 0u))        return -1;
	if (!rpc_put_u32(buf, sizeof(buf), &pos, 1048576u))  return -1;
	if (!rpc_put_u32(buf, sizeof(buf), &pos, 1048576u))  return -1;
	if (!rpc_put_u32(buf, sizeof(buf), &pos, 8192u))     return -1;
	if (!rpc_put_u32(buf, sizeof(buf), &pos, 32u))       return -1;
	if (!rpc_put_u32(buf, sizeof(buf), &pos, 1u))        return -1;
	if (!rpc_put_u32(buf, sizeof(buf), &pos, 0u))        return -1;

	/* back channel attrs (minimal; we never use the callback channel) */
	if (!rpc_put_u32(buf, sizeof(buf), &pos, 0u))        return -1;
	if (!rpc_put_u32(buf, sizeof(buf), &pos, 4096u))     return -1;
	if (!rpc_put_u32(buf, sizeof(buf), &pos, 4096u))     return -1;
	if (!rpc_put_u32(buf, sizeof(buf), &pos, 4096u))     return -1;
	if (!rpc_put_u32(buf, sizeof(buf), &pos, 4u))        return -1;
	if (!rpc_put_u32(buf, sizeof(buf), &pos, 1u))        return -1;
	if (!rpc_put_u32(buf, sizeof(buf), &pos, 0u))        return -1;

	/* csa_cb_program: choose a value unlikely to collide with kernel */
	if (!rpc_put_u32(buf, sizeof(buf), &pos, 0x40000001u)) return -1;

	/*
	 * csa_sec_parms: 1 entry, AUTH_NONE callback security.
	 * The callback channel will not actually be used by this probe;
	 * CB_GETATTR goes to the kernel client that holds the delegation.
	 */
	if (!rpc_put_u32(buf, sizeof(buf), &pos, 1u)) return -1;
	if (!rpc_put_u32(buf, sizeof(buf), &pos, 0u)) return -1; /* AUTH_NONE */

	if (finish_and_send(fd, buf, pos) < 0) return -1;

	ssize_t rlen = recv_one(fd, buf, sizeof(buf));
	if (rlen < 0) return -1;

	size_t p = 0;
	uint32_t nres, resop, status = 0;
	if (!skip_rpc_hdr(buf, (size_t)rlen, &p))               return -1;
	if (!skip_compound_hdr(buf, (size_t)rlen, &p, &nres))   return -1;
	if (nres != 1)                                           return -1;

	if (!rpc_get_u32(buf, (size_t)rlen, &p, &resop) ||
	    resop != OP_CREATE_SESSION)
		return -1;
	if (!rpc_get_u32(buf, (size_t)rlen, &p, &status) ||
	    status != NFS4_OK) {
		fprintf(stderr,
			"cb_getattr_probe: CREATE_SESSION failed: status=%u\n",
			status);
		return -1;
	}

	/* csr_sessionid: 16 bytes */
	if (p + 16 > (size_t)rlen) return -1;
	memcpy(sessionid, buf + p, 16);
	return 0;
}

/* ------------------------------------------------------------------ */
/* SEQUENCE + PUTROOTFH + LOOKUP* + GETATTR                            */
/* ------------------------------------------------------------------ */

static int do_getattr(int fd, uint32_t xid,
		       const uint8_t sessionid[16], uint32_t slot_seqid,
		       char **comp, int n_comp,
		       uint64_t *size_out, uint64_t *change_out)
{
	static uint8_t buf[BUF_SZ];
	size_t pos;
	uint32_t nops = (uint32_t)(1 + 1 + n_comp + 1);

	if (!begin_call(buf, sizeof(buf), &pos, xid))            return -1;
	if (!compound_hdr(buf, sizeof(buf), &pos, nops))         return -1;

	/* SEQUENCE */
	if (!rpc_put_u32(buf, sizeof(buf), &pos, OP_SEQUENCE))  return -1;
	if (pos + 16 > sizeof(buf))                              return -1;
	memcpy(buf + pos, sessionid, 16);
	pos += 16;
	if (!rpc_put_u32(buf, sizeof(buf), &pos, slot_seqid))   return -1;
	if (!rpc_put_u32(buf, sizeof(buf), &pos, 0u))            return -1; /* slotid */
	if (!rpc_put_u32(buf, sizeof(buf), &pos, 0u))            return -1; /* highest_slotid */
	if (!rpc_put_u32(buf, sizeof(buf), &pos, 0u))            return -1; /* cachethis=FALSE */

	/* PUTROOTFH */
	if (!rpc_put_u32(buf, sizeof(buf), &pos, OP_PUTROOTFH)) return -1;

	/* LOOKUP per path component */
	for (int i = 0; i < n_comp; i++) {
		if (!rpc_put_u32(buf, sizeof(buf), &pos, OP_LOOKUP)) return -1;
		if (!rpc_put_str(buf, sizeof(buf), &pos,
				 comp[i], strlen(comp[i])))
			return -1;
	}

	/* GETATTR: bitmap4 len=1, word0 = CHANGE_BIT | SIZE_BIT */
	if (!rpc_put_u32(buf, sizeof(buf), &pos, OP_GETATTR))             return -1;
	if (!rpc_put_u32(buf, sizeof(buf), &pos, 1u))                     return -1;
	if (!rpc_put_u32(buf, sizeof(buf), &pos,
			 FATTR4_CHANGE_BIT | FATTR4_SIZE_BIT))            return -1;

	if (finish_and_send(fd, buf, pos) < 0) return -1;

	ssize_t rlen = recv_one(fd, buf, sizeof(buf));
	if (rlen < 0) return -1;

	size_t p = 0;
	uint32_t nres, resop, status = 0;
	if (!skip_rpc_hdr(buf, (size_t)rlen, &p))               return -1;
	if (!skip_compound_hdr(buf, (size_t)rlen, &p, &nres))   return -1;
	if (nres != nops)                                        return -1;

	/* SEQUENCE result */
	if (!rpc_get_u32(buf, (size_t)rlen, &p, &resop) ||
	    resop != OP_SEQUENCE)
		return -1;
	if (!rpc_get_u32(buf, (size_t)rlen, &p, &status) || status != NFS4_OK) {
		fprintf(stderr, "cb_getattr_probe: SEQUENCE failed: %u\n",
			status);
		return -1;
	}
	/*
	 * SEQUENCE4resok: sessionid(16) + sequenceid(4) + slotid(4) +
	 * highest_slotid(4) + target_highest_slotid(4) + status_flags(4).
	 */
	if (!rpc_skip((size_t)rlen, &p, 16 + 5 * 4)) return -1;

	/* PUTROOTFH result */
	if (!rpc_get_u32(buf, (size_t)rlen, &p, &resop) ||
	    resop != OP_PUTROOTFH)
		return -1;
	if (!rpc_get_u32(buf, (size_t)rlen, &p, &status) || status != NFS4_OK) {
		fprintf(stderr, "cb_getattr_probe: PUTROOTFH failed: %u\n",
			status);
		return -1;
	}

	/* LOOKUP results */
	for (int i = 0; i < n_comp; i++) {
		if (!rpc_get_u32(buf, (size_t)rlen, &p, &resop) ||
		    resop != OP_LOOKUP)
			return -1;
		if (!rpc_get_u32(buf, (size_t)rlen, &p, &status) ||
		    status != NFS4_OK) {
			fprintf(stderr,
				"cb_getattr_probe: LOOKUP(%s) failed: %u\n",
				comp[i], status);
			return -1;
		}
	}

	/* GETATTR result */
	if (!rpc_get_u32(buf, (size_t)rlen, &p, &resop) ||
	    resop != OP_GETATTR)
		return -1;
	if (!rpc_get_u32(buf, (size_t)rlen, &p, &status) || status != NFS4_OK) {
		fprintf(stderr, "cb_getattr_probe: GETATTR failed: %u\n",
			status);
		return -1;
	}

	/*
	 * GETATTR4resok: attrmask (bitmap4) then attr_vals (opaque<>).
	 * Read the attrmask to know which attrs were returned, then parse
	 * attribute values in attribute-number order: change (3) before size (4).
	 */
	uint32_t bm_len;
	if (!rpc_get_u32(buf, (size_t)rlen, &p, &bm_len)) return -1;
	if (bm_len > 4) return -1;

	uint32_t bm[4] = { 0 };
	for (uint32_t i = 0; i < bm_len; i++) {
		if (!rpc_get_u32(buf, (size_t)rlen, &p, &bm[i])) return -1;
	}

	uint32_t attr_len;
	if (!rpc_get_u32(buf, (size_t)rlen, &p, &attr_len)) return -1;

	*change_out = 0;
	*size_out   = 0;

	if (bm[0] & FATTR4_CHANGE_BIT) {
		if (!rpc_get_u64(buf, (size_t)rlen, &p, change_out)) return -1;
	}
	if (bm[0] & FATTR4_SIZE_BIT) {
		if (!rpc_get_u64(buf, (size_t)rlen, &p, size_out)) return -1;
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
			printf("Usage: cb_getattr_probe -s SERVER -p NFSPATH\n"
			       "Prints: size=<N> change=<N>\n");
			return 0;
		default:
			fprintf(stderr,
				"Usage: cb_getattr_probe -s SERVER -p NFSPATH\n");
			return 2;
		}
	}
	if (!server || !nfspath) {
		fprintf(stderr,
			"cb_getattr_probe: -s SERVER and -p NFSPATH required\n");
		return 2;
	}

	/* Split nfspath on '/', skip empty components */
	char path_copy[1024];
	if (strlen(nfspath) >= sizeof(path_copy)) {
		fprintf(stderr, "cb_getattr_probe: path too long\n");
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
					"cb_getattr_probe: path depth > %d\n",
					MAX_COMP);
				return 1;
			}
			comp[n_comp++] = tok;
		}
		tok = strtok_r(NULL, "/", &save);
	}
	if (n_comp == 0) {
		fprintf(stderr, "cb_getattr_probe: empty or root-only path\n");
		return 1;
	}

	int fd = tcp_connect(server);
	if (fd < 0) return 1;

	/*
	 * Use a client owner distinct from the kernel's to get a fresh
	 * clientid.  Include hostname + pid so concurrent probes don't
	 * collide.
	 */
	char owner_id[128];
	char hostname[64] = "probe";
	gethostname(hostname, sizeof(hostname) - 1);
	snprintf(owner_id, sizeof(owner_id), "cb_getattr_probe:%s:%u",
		 hostname, (unsigned)getpid());

	uint32_t xid      = (uint32_t)getpid() ^ 0xABC00000u;
	uint64_t clientid = 0;
	uint32_t seqid    = 0;

	if (do_exchange_id(fd, xid++, owner_id, &clientid, &seqid) < 0) {
		close(fd);
		return 1;
	}

	uint8_t sessionid[16];
	if (do_create_session(fd, xid++, clientid, seqid, sessionid) < 0) {
		close(fd);
		return 1;
	}

	/*
	 * The slot table is initialized to eir_sequenceid (= seqid here).
	 * The first SEQUENCE op must use sa_sequenceid = seqid + 1.
	 */
	uint64_t size = 0, change = 0;
	if (do_getattr(fd, xid, sessionid, seqid + 1u,
		       comp, n_comp, &size, &change) < 0) {
		close(fd);
		return 1;
	}

	close(fd);
	printf("size=%" PRIu64 " change=%" PRIu64 "\n", size, change);
	return 0;
}
