/* Distributed Checksum Clearinghouse
 *
 * database definitions
 *
 * Copyright (c) 2014 by Rhyolite Software, LLC
 *
 * This agreement is not applicable to any entity which sells anti-spam
 * solutions to others or provides an anti-spam solution as part of a
 * security solution sold to other entities, or to a private network
 * which employs the DCC or uses data provided by operation of the DCC
 * but does not provide corresponding data to other users.
 *
 * Permission to use, copy, modify, and distribute this software without
 * changes for any purpose with or without fee is hereby granted, provided
 * that the above copyright notice and this permission notice appear in all
 * copies and any distributed versions or copies are either unchanged
 * or not called anything similar to "DCC" or "Distributed Checksum
 * Clearinghouse".
 *
 * Parties not eligible to receive a license under this agreement can
 * obtain a commercial license to use DCC by contacting Rhyolite Software
 * at sales@rhyolite.com.
 *
 * A commercial license would be for Distributed Checksum and Reputation
 * Clearinghouse software.  That software includes additional features.  This
 * free license for Distributed ChecksumClearinghouse Software does not in any
 * way grant permision to use Distributed Checksum and Reputation Clearinghouse
 * software
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND RHYOLITE SOFTWARE, LLC DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL RHYOLITE SOFTWARE, LLC
 * BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES
 * OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
 * WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
 * ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * Rhyolite Software DCC 1.3.158-1.156 $Revision$
 */

#ifndef DB_H
#define DB_H

#include "srvr_defs.h"
#include <math.h>

extern u_char grey_on;

#define DB_DCC_NAME	"dcc_db"
#define DB_GREY_NAME	"grey_db"
#define DB_HASH_SUFFIX  ".hash"
#define DB_LOCK_SUFFIX	".lock"

#define WHITELIST_NM(g)	    ((g) ? "grey_whitelist" : "whitelist")

#define DB_VERSION3_STR "DCC checksum database version 3"
#define DB_VERSION4_STR "DCC checksum database version 4"
#define DB_VERSION5_STR "DCC checksum database version 5"
#define DB_VERSION6_STR "DCC checksum database version 6"
#define DB_VERSION_STR  DB_VERSION6_STR

#define HASH_MAGIC_STR   "DCC hash 7"

/* hash table indeces are only 32 bits */
#define MAX_HASH_ENTRIES    0xffffffff

#define MIN_CLEAN_HASH_ENTRIES  1024	/* run dbclean at this size */
#define MIN_HASH_ENTRIES    (8*MIN_CLEAN_HASH_ENTRIES)
#define MIN_HASH_DIVISOR    ((MIN_HASH_ENTRIES*7)/8)


#define DB_CP3(x,v) do {u_int32_t _v = v; (x)[0] = _v>>16;		\
    (x)[1] = _v>>8; (x)[2] = _v;} while (0)
#define DB_CP4(x,v) do {u_int32_t _v = v; (x)[0] = _v>>24;		\
    (x)[1] = _v>>16; (x)[2] = _v>>8; (x)[3] = _v;} while (0)
#define DB_EX3(x) ((((u_int32_t)(x)[0])<<16) + ((x)[1]<<8) + (x)[2])
#define DB_EX4(x) ((((u_int32_t)(x)[0])<<24) + (((u_int32_t)(x)[1])<<16) \
		   + ((x)[2]<<8) + (x)[3])
/* the least significant byte should be tested first */
#define DB_ZERO3(x) ((x)[2] == 0 && (x)[1] == 0 && (x)[0] == 0)
#define DB_ZERO4(x) ((x)[3] == 0 && (x)[2] == 0 && (x)[1] == 0 && (x)[0] == 0)


/* a single checksum in a database record */
typedef u_char      DB_TGTS[3];		/* a compressed count */
typedef u_int64_t   DB_PTR;		/* database record offset */
typedef u_int32_t   DB_PTR_C;		/*      compressed by DB_PTR_CP() */
typedef struct {
    DB_PTR_C    prev;			/* previous record for this checksum */
    DB_TGTS     tgts;			/* accumulated reported targets */
    DCC_CK_TYPE_B type_fgs;
#    define      DB_CK_FG_JUNK	0x80
#     define	  DB_CK_JUNK(ck) ((ck)->type_fgs & DB_CK_FG_JUNK)
#    define	 DB_CK_FG_OSPAM	0x40	/* obsolete report of spam */
#     define	  DB_CK_OSPAM(ck) ((ck)->type_fgs & DB_CK_FG_OSPAM)
#    define	 DB_CK_MASK	0x0f
#    define      DB_CK_TYPE(ck)	((DCC_CK_TYPES)((ck)->type_fgs & DB_CK_MASK))
    DCC_SUM     sum;
} DB_RCD_CK;
#define DB_TGTS_CK_SET(ck,v) DB_CP3((ck)->tgts,v)
#define DB_TGTS_CK(ck) DB_EX3((ck)->tgts)

/* shape of a checksum database entry */
typedef struct {
    DCC_TS      ts;			/* original server's creation date */
    DCC_SRVR_ID srvr_id;		/* initial server */
#    define	 DB_RCD_ID(r)	((r)->srvr_id)
    DB_TGTS     tgts_del;		/* # target addresses or delete flag */
    u_char      fgs_num_cks;		/* # of cksums | flags */
#    define      DB_RCD_FG_TRIM	    0x80    /* some checksums deleted */
#     define	  DB_RCD_TRIMMED(r)  ((r)->fgs_num_cks & DB_RCD_FG_TRIM)
#    define	 DB_RCD_FG_SUMRY    0x40    /* fake summary record */
#     define	  DB_RCD_SUMRY(r)   ((r)->fgs_num_cks & DB_RCD_FG_SUMRY)
#    define	 DB_RCD_FG_DELAY    0x20    /* delayed for fake summary */
#     define	  DB_RCD_DELAY(r)   ((r)->fgs_num_cks & DB_RCD_FG_DELAY)
/* # define	 DB_RCD_FG_	    0x10       unused */
#    define	 DB_RCD_FG_MASK	    0x0f    /* depends on DCC_MAX_FLOD_PATHS */
#    define      DB_NUM_CKS(r)	    ((r)->fgs_num_cks & DB_RCD_FG_MASK)
    DB_RCD_CK   cks[DCC_DIM_CKS];
} DB_RCD;

#define DB_RCD_HDR_LEN (ISZ(DB_RCD) - ISZ(DB_RCD_CK)*DCC_DIM_CKS)
#define DB_RCD_LEN(r) (DB_RCD_HDR_LEN + DB_NUM_CKS(r) * ISZ(DB_RCD_CK))
#define DB_RCD_LEN_MAX sizeof(DB_RCD)

#define DB_TGTS_RCD_SET(r,v) DB_CP3((r)->tgts_del,v)
#define DB_TGTS_RCD_RAW(r) DB_EX3((r)->tgts_del)

#define DB_COOK_TGTS(raw) ((raw) == DCC_TGTS_DEL ? 0 : (raw))
#ifdef HAVE_GCC_INLINE			/* no prototypes without inline */
static inline DCC_TGTS
DB_TGTS_RCD(const DB_RCD *rcd) {return DB_COOK_TGTS(DB_TGTS_RCD_RAW(rcd));}
#else
#define DB_TGTS_RCD(rcd) DB_COOK_TGTS(DB_TGTS_RCD_RAW(rcd))
#endif

/* this allows database of up to 48 GBytes */
#define DB_PTR_MULT	    ((DB_PTR)12)    /* gcd of all sizes of DB_RCD */
#define DB_PTR_CP(v)	    ((u_int32_t)((v) / DB_PTR_MULT))
#define DB_PTR_EX(x)	    ((x) * DB_PTR_MULT)

/* The kludge to speed conversion of database addresses to page numbers
 * and offsets on 32-bit systems */
#define DB_PTR_SHIFT 8
#ifdef HAVE_64BIT_LONG
#define DB_PTR2PG_NUM(p,s) ((p) / (s))
#else
#define DB_PTR2PG_NUM(p,s) ((u_int32_t)((p) >> DB_PTR_SHIFT)		\
			    / (s >> DB_PTR_SHIFT))
#endif

#define DB_PTR_NULL	    0
#define DB_PTR_BASE	    ISZ(DB_HDR)
#define DB_PTR_MAX	    DB_PTR_EX((((DB_PTR)1)<<(sizeof(DB_PTR_C)*8)) -1)
#define DB_PTR_BAD	    (DB_PTR_MAX+1)
#define DB_PTR_IS_BAD(l)    ((l) < DB_PTR_BASE || (l) >= DB_PTR_MAX)


typedef DCC_TS DB_SN;			/* database serial number */

#define FLOD_STALE_SECS		    (24*60*60)
/* non-spam expiration */
#define DB_EXPIRE_SECS_DEF	    (24*60*60)
#define DB_EXPIRE_SECS_MAX	    DCC_MAX_SECS
#define DB_EXPIRE_SECS_MIN	    (60*60)
#define DB_EXPIRE_SECS_DEF_MIN	    (2*60*60)
/* spam expiration */
#define DB_EXPIRE_SPAMSECS_DEF	    (30*24*60*60)
#define DB_EXPIRE_SPAMSECS_DEF_MIN  (1*24*60*60)
/* reputations need consistent expirations */
#define DB_EXPIRE_REP_SECS_DEF	    (24*60*60)
#define	DB_EXPIRE_REP_SPAMSECS_DEF  (30*24*60*60)
/* so do server-IDs */
#define DB_EXPIRE_SERVER_ID	    (30*24*60*60)

/* re-announce spam this often */
#define DCC_OLD_SPAM_SECS   (DB_EXPIRE_SPAMSECS_DEF_MIN/2)


/* seconds to greylist or delay new mail messages
 *  RFC 2821 says SMTP clients should wait at least 30 minutes to retry,
 *  but 15 minutes seems more common than 30 minutes.  Many retry after
 *  only 5 minutes, and some after only 1 (one!) second.  However,
 *  many of those that retry after a few seconds keep trying for a minute
 *  or two. */
#define DEF_GREY_EMBARGO    270
#define MAX_GREY_EMBARGO    (24*60*60)

#define DEF_GREY_WINDOW	    (7*24*60*60)    /* wait as long as this */
#define MAX_GREY_WINDOW	    (10*24*60*60)
#define DEF_GREY_WHITE	    (63*24*60*60)   /* remember this long */
#define MAX_GREY_WHITE	    DB_EXPIRE_SECS_MAX


typedef DCC_TS	DB_EX_TS[DCC_DIM_CKS];
typedef struct {
    int32_t	all;			/* allsecs */
    int32_t	spam;			/* spamsecs */
} DB_EX_SEC;
typedef DB_EX_SEC DB_EX_SECS[DCC_DIM_CKS];

#define DCC_CK_OK_GREY_CLNT(t) ((t) > DCC_CK_INVALID			    \
				&& t <= DCC_CK_G_TRIPLE_R_BULK)
#define DCC_CK_OK_GREY_FLOD(t) ((t) == DCC_CK_BODY			    \
				|| ((t) >= DCC_CK_G_MSG_R_TOTAL		    \
				    && (t) <= DCC_CK_FLOD_PATH)		    \
				|| ((t) == DCC_CK_IP && grey_weak_ip))

#define DEF_FLOD_THOLDS(g,t) ((g) ? 1					    \
			      : t == DCC_CK_SRVR_ID ? 1 : BULK_THRESHOLD)

#define DCC_CK_OK_DCC_CLNT(g,t) ((t) > DCC_CK_INVALID			    \
				 && (t) <= DCC_CK_G_TRIPLE_R_BULK	    \
				 && ((g)|| (t) <= DCC_CK_FUZ2))
#define DCC_CK_OK_DB(g,t) ((t) > DCC_CK_INVALID && t <= DCC_CK_TYPE_LAST    \
			   && ((g) || ((t) != DCC_CK_G_MSG_R_TOTAL	    \
				       && (t) != DCC_CK_G_TRIPLE_R_BULK)))
#define DCC_CK_OK_FLOD(g,t) ((g) ? DCC_CK_OK_GREY_FLOD(t)		    \
			     : ((t) > DCC_CK_INVALID			    \
				&& ((t) <= DCC_CK_FUZ2			    \
				    || (t) == DCC_CK_FLOD_PATH		    \
				    || (t) == DCC_CK_SRVR_ID)))


typedef u_int32_t DB_NOKEEP_CKS;	/* bitmask of ignored checksums */
#define DB_SET_NOKEEP(map,t)	((map) |= (1<<(t)))
#define DB_RESET_NOKEEP(map,t)	((map) &= ~(1<<(t)))
#define DB_TEST_NOKEEP(map,t)	((map) & (1<<(t)))

/* relative fuzziness of checksums */
#define DCC_CK_FUZ_LVL_NO   1		/* least fuzzy */
#define DCC_CK_FUZ_LVL1	    2		/* somewhat fuzzy */
#define DCC_CK_FUZ_LVL2	    3		/* fuzzier */
#define DCC_CK_FUZ_LVL3	    4		/* reputations */
#define DCC_CK_FUZ_LVL_REP  DCC_CK_FUZ_LVL3
extern const u_char *db_ck_fuzziness;


typedef DB_PTR		    DB_HOFF;	/* byte offset into hash table */
typedef u_int32_t	    DB_HADDR;	/* index of a hash table entry */
typedef u_char DB_HADDR_C[4];		/* compressed hash chain link */
#define DB_HADDR_CP(x,v)    DB_CP4(x,v)
#define DB_HADDR_EX(x)      DB_EX4(x)
#define DB_HADDR_NULL       0		/* no-answer from hashing & linking */
#define DB_HADDR_C_NULL(x)  DB_ZERO4(x)
#define DB_HADDR_INVALID(h) ((h) < DB_HADDR_BASE || (h) >= db_hash_len)
#define DB_HADDR_C_INVALID(h) DB_HADDR_INVALID(DB_HADDR_EX(h))

typedef u_char DB_PTR_HC[4];
#define DB_HPTR_CP(x,v) {u_int32_t _v = DB_PTR_CP(v);			\
    (x)[0] = _v>>24; (x)[1] = _v>>16; (x)[2] = _v>>8; (x)[3] = _v;}
#define DB_HPTR_EX(x) DB_PTR_EX(((x)[0]<<24) + ((x)[1]<<16)		\
				+ ((x)[2]<<8) + (x)[3])


/* shape of the magic string that starts a database */
typedef char DB_VERSION_BUF[64];
typedef struct {
    DB_VERSION_BUF version;		/* see DB_VERSION_STR */
    DB_PTR      db_csize;		/* size of database contents in bytes */
    u_int32_t   pagesize;		/* size of 1 DB buffer */
    DB_SN       sn;			/* creation or expiration serial # */
    DCC_PTIME	cleared;		/* when created */
    DCC_PTIME	cleaned;		/* real instead of repair cleaning */
    DCC_PTIME	cleaned_cron;		/* cleaned by cron */
    DB_EX_TS	ex_spam;		/* recent expiration timestamps */
    DB_EX_TS	ex_all;			/* recent expiration timestamps */
    DB_EX_SECS  ex_secs;		/* recent expiration durations */
    DB_NOKEEP_CKS nokeep_cks;		/* ignore these checksums */
    u_int32_t	flags;
#    define DB_PARM_FG_GREY	0x01    /* greylist database */
#    define DB_PARM_FG_CLEARED	0x02    /* new file */
#    define DB_PARM_FG_EXP_SET	0x04	/* have explicit expiration durations */
#    define DB_PARM_FG_NO_CLR	0x08
    DB_PTR	old_db_csize;		/* size at end of last cleaning */
    DB_PTR	db_added;		/* bytes previously added to database */
    DB_HADDR	hash_used;		/* recent of entries used */
    DB_HADDR	old_hash_used;		/* entries used at last cleaning */
    DB_HADDR	hash_added;		/* entries added */
    DCC_PTIME	rate_secs;		/* denominator of rates */
#    define	 DB_MIN_RATE_SECS (12*60*60)
#    define	 DB_NEW_RATE_SECS ((7*24-1)*60*60)
#    define	 DB_GOOD_RATE_SECS (2*24*60*60)
#    define	 DB_MAX_RATE_SECS (60*24*60*60)
    DCC_PTIME	last_rate_sec;
    DB_HADDR	old_kept_cks;		/* reported checksums at cleaning */
    DB_PTR	min_confirm_pos;	/* flood after this */
    u_int32_t	failsafe_cleanings;	/* consecutive cleanings by dccd */
    DB_PTR	prev_db_added;
    DB_HADDR	prev_hash_added;
    DCC_PTIME	prev_rate_secs;
} DB_PARMS;
typedef union {
    DB_PARMS	p;
    char	c[256*3];
} DB_HDR;

#ifdef DB_VERSION5_STR
typedef struct {
    DCC_TGTS    unused;
    int32_t	all;
    int32_t	spam;
} DB_V5_EX_SEC;
typedef DB_V5_EX_SEC DB_V5_EX_SECS[DCC_DIM_CKS];
typedef struct {
    DB_VERSION_BUF version;
    DB_PTR      db_csize;
    u_int32_t   pagesize;
    DB_SN       sn;
    time_t	cleared;
    time_t	cleaned;
    time_t	cleaned_cron;
    DB_EX_TS	ex_spam;
    DB_EX_TS	ex_all;
    DB_V5_EX_SECS ex_secs;
    DB_NOKEEP_CKS nokeep_cks;
    u_int	flags;
    DB_PTR	old_db_csize;
    DB_PTR	db_added;
    DB_HADDR	hash_used;
    DB_HADDR	old_hash_used;
    DB_HADDR	hash_added;
    time_t	rate_secs;
    time_t	last_rate_sec;
    DB_HADDR	old_kept_cks;
    DB_PTR	min_confirm_pos;
    u_int	failsafe_cleanings;
} DB_V5_PARMS;
#endif
#ifdef DB_VERSION4_STR
typedef struct {
    DB_VERSION_BUF version;
    DB_PTR      db_csize;
    u_int32_t   pagesize;
    DB_SN       sn;
    time_t	cleared;
    time_t	cleaned;
    time_t	cleaned_cron;
    DB_EX_TS	ex_spam;
    DB_V5_EX_SECS ex_secs;
    DB_NOKEEP_CKS nokeep_cks;
    u_int	flags;
    DB_PTR	old_db_csize;
    DB_PTR	db_added;
    DB_HADDR	hash_used;
    DB_HADDR	old_hash_used;
    DB_HADDR	hash_added;
    time_t	rate_secs;
    time_t	last_rate_sec;
    DB_HADDR	old_kept_cks;
} DB_V4_PARMS;
#endif
#ifdef DB_VERSION3_STR
typedef struct {
    DB_VERSION_BUF version;
    DB_PTR      db_csize;
    u_int32_t   pagesize;
    DB_SN       sn;
    DB_EX_TS	ex_spam;
    DB_V5_EX_SECS ex_secs;
    DB_NOKEEP_CKS nokeep_cks;
    DCC_TGTS    unused[DCC_DIM_CKS];
    u_int	flags;
#    define DB_PARM_V3_FG_GREY		0x01
#    define DB_PARM_V3_FG_SELF_CLEAN	0x02
#    define DB_PARM_V3_FG_SELF_CLEAN2	0x04
#    define DB_PARM_V3_FG_CLEARED	0x08
    DB_PTR	old_db_csize;
    DB_PTR	db_added;
    DB_HADDR	hash_used;
    DB_HADDR	old_hash_used;
    DB_HADDR	hash_added;
    time_t	rate_secs;
    time_t	last_rate_sec;
    DB_HADDR	old_kept_cks;
} DB_V3_PARMS;
#endif

/* shape of a database hash table entry */
typedef struct {
    DB_HADDR_C  fwd, bak;		/* hash collision chain */
    u_char	hv_type[2];		/* checksum type + some hash bits */
#    define	 HE_TYPE(e)	((DCC_CK_TYPES)((e)->hv_type[0] & 0xf))
#    define	 HE_IS_FREE(e)	((e)->hv_type[0] == 0)
#    define	 HE_MERGE(e,t,s) ((e)->hv_type[0] = ((((s)->b[0])<<4) + t),\
				  (e)->hv_type[1] = (s)->b[1])
#    define	 HE_CMP(e,t,s)	((e)->hv_type[1] == (s)->b[1]		\
				 && ((e)->hv_type[0]			\
				     == (u_char)((((s)->b[0])<<4) + t)))

    DB_PTR_HC   rcd;			/* record for this hash table entry */
} HASH_ENTRY;



typedef union {
    HASH_ENTRY	h[8];			/* this must be larger than following */
    struct {
	char	    magic[16];
	u_int32_t   flags;
#	 define	     HASH_CTL_FG_CLEAN	0x01	/* 1=consistent with database */
#	 define	     HASH_CTL_FG_NOSYNC	0x02	/* 1=need to push hash to disk */
	DB_HADDR    free_fwd;		/* hash table internal free list */
	DB_HADDR    free_bak;
#	 define	     FREE_HADDR_END 1
	DB_HADDR    len;		/* size of file in entries */
	DB_HADDR    used;		/* entries actually used */
	DB_HADDR    divisor;		/* hash modulus */
	DB_PTR	    db_csize;		/* size of the database file */
	DCC_PTIME   synced;
    } s;
} HASH_CTL;


#define DB_HADDR_BASE	((DB_HADDR)((sizeof(HASH_CTL)+sizeof(HASH_ENTRY)-1) \
				    / sizeof(HASH_ENTRY)))
#define HADDR2LEN(l)	((int)((l)-DB_HADDR_BASE))  /* offset to length */


/* control a block of mapped memory */
typedef u_int16_t DB_PG_NUM;
typedef u_int32_t DB_PG_OFF;
typedef enum {
    DB_BUF_TYPE_FREE = 0,
    DB_BUF_TYPE_HASH,
    DB_BUF_TYPE_DB
} DB_BUF_TYPE;
#ifdef HAVE_64BIT_LONG
typedef u_int64_t DB_BUF_FM;
#else
typedef u_int32_t DB_BUF_FM;
#endif
#define DB_BUF_NUM_PARTS    (8*ISZ(DB_BUF_FM))
#define PART2BIT(part)	    (((DB_BUF_FM)1) << (part))
typedef struct db_buf {
    struct db_buf *fwd, *bak, **hash;
    struct db_buf *older, *newer;
    union {
	void	    *v;
	HASH_ENTRY  *h;
	char	    *c;
    } buf;
    DB_PG_NUM	pg_num;
    int		lock_cnt;
    DB_BUF_TYPE	buf_type;
    DB_BUF_FM	flush;			/* changes that can be reconstructed */
    DB_BUF_FM	flush_urgent;		/* changes that can't be reconstructed */
    struct {
	char	*lo, *hi;
    } ranges[DB_BUF_NUM_PARTS];
    u_char	flags;
#    define	 DB_BUF_FG_USE_WRITE	0x01    /* use write instead of mmap */
#    define	 DB_BUF_FG_ANON_EXTEND	0x02	/* new page in anon. memory */
} DB_BUF;

/* context for searching for or adding a record */
typedef struct {
    union {				/* pointer to data in buffer */
	void	    *v;
	HASH_ENTRY  *h;
	char	    *c;
	DB_RCD      *r;
	DB_PARMS    *parms;
	HASH_CTL    *vals;
    } d;
    union {				/* database address */
	DB_HADDR    haddr;
	DB_PTR      rptr;
    } s;
    DB_BUF      *b;
} DB_STATE;

/* see db_close() before changing this */
typedef struct {
    DB_STATE	rcd;			/* must be first */
    DB_STATE	rcd2;
    DB_STATE	sumrcd;
    DB_STATE	hash;
    DB_STATE	free;
    DB_STATE	tmp;
    DB_STATE	db_parms;
    DB_STATE	hash_ctl;		/* hash control info; must be last */
} DB_STATES;
extern DB_STATES db_sts;

extern int db_failed_line;
extern const char *db_failed_file;
#define DB_ERROR_MSG(s) db_error_msg(__LINE__,__FILE__, "%s", s)
#define DB_ERROR_MSG2(s1,s2) db_error_msg(__LINE__,__FILE__, "%s: %s", s1,s2)

extern struct timeval db_time;
#define DB_IS_TIME(tgt,lim) DCC_IS_TIME(db_time.tv_sec,tgt,lim)
#define DB_ADJ_TIMER(tgt,lim,new) DCC_ADJ_TIMER(db_time.tv_sec,tgt,lim,new)

extern u_char db_minimum_map;		/* this is dccd & dbclean is running */
extern int db_fd, db_hash_fd;
extern DCC_PATH db_nm, db_hash_nm;
extern struct timeval db_locked;	/* 0 or when database was locked */
extern int db_debug;
extern DB_SN db_sn;

extern u_int sys_pagesize;

extern DB_HOFF db_hash_fsize;		/* size of hash table file */
extern DB_HADDR db_hash_len;		/* # of hash table entries */
extern DB_HADDR db_hash_divisor;	/* hash function modulus */
extern DB_HADDR db_hash_used;		/* # of hash table entries in use */
extern u_int db_hash_page_len;		/* # of HASH_ENTRYs per buffer */
extern DB_HADDR db_max_hash_entries;	/* max size of hash table */
extern DB_PTR db_fsize;			/* size of database file */
extern DB_PTR db_csize;			/* size of database contents in bytes */
extern const DB_VERSION_BUF db_version_buf;
extern DB_PARMS db_parms;
extern DCC_TGTS db_tholds[DCC_DIM_CKS];
extern u_int db_pagesize;		/* size of 1 DB buffer */
extern u_int db_page_max;		/* only padding after this */
extern char db_window_size_str[];	/* size of mmap() window */

typedef struct {
    u_int   db_mmaps;
    u_int   hash_mmaps;
    u_int   adds;			/* reports added */
} DB_STATS;
extern DB_STATS db_stats;


/* If the two files were smaller than the typical mmap() limit of a fraction
 * of a GByte, they could be mmap()'ed directly.  They are often too large.
 *
 * Use a modest pool of buffers to map the DB hash table and the database
 * itself.
 * Each access to the files could be with a single, common buffer,
 * but that would involve many more mmap() system calls.
 * Most of the DB hash table is expected to fit in the application's memory.
 *
 * Use the same modest pool of buffers to map the database itself.
 * References to the database have a lot of locality, so the commonly used
 * checksums and counts should remain in memory.
 *
 * Common operating system limits on the number of mapped segments are
 * below 256 and so that is a bound on DB_BUF_MAX */
#define DB_BUF_MAX 128			/* maximum # of buffers */
#define DB_BUF_PARTS_MAX    (DB_BUF_MAX*DB_BUF_NUM_PARTS)

/* enough buffers so max simultaneous pointers can be satisfied */
#define DB_BUF_MIN (sizeof(DB_STATES)/sizeof(DB_STATE) + 2)

typedef enum {
    DB_BUF_MODE_WRITE,			/* use mmap() and write() */
    DB_BUF_MODE_MSYNC,			/* use mmap() and msync */
    DB_BUF_MODE_TMPFS,			/* use mmap() on memory file system */
} DB_BUF_MODE;
#define DB_BUF_MODE_B(b) ((b)->buf_type == DB_BUF_TYPE_HASH		\
			  ? db_buf_mode_hash : db_buf_mode_db)
extern DB_BUF_MODE db_buf_mode_hash, db_buf_mode_db;

extern int db_buf_total;		/* total # of db buffers */
extern DB_PTR db_max_rss;		/* maximum db resident set size */
extern DB_PTR db_max_byte;


extern time_t db_need_flush_secs;
#define DB_NEED_FLUSH_SECS	5
#define DB_STALE_SECS		(30*60)	/* limit on buffer staleness */
#define	DB_FLUSHES		(DB_STALE_SECS / DB_NEED_FLUSH_SECS)
#define DB_PARTS_PER_FLUSH	((DB_BUF_PARTS_MAX + DB_FLUSHES-1) / DB_FLUSHES)
#define DB_URGENT_NEED_FLUSH_SECS   120


/* fix configure script if this changes */
#define DB_MIN_MIN_MBYTE    32
#define DB_DEF_MIN_MBYTE    64		/* a reasonable tiny default */
#define DB_PAD_MBYTE	    128		/* RAM for rate limiting blocks etc */
#define DB_PAD_BYTE	(DB_PAD_MBYTE*1024*1024)
#define DB_MAX_2G_MBYTE	(2048-DB_PAD_MBYTE) /* <2 GByte on 32 bit machines */
#define DB_NEEDED_MBYTE	    DB_MAX_2G_MBYTE /* need at least this much RAM */
/* the database cannot exceed 48 GBytes because of DB_PTR_CP */
#define MAX_MAX_DB_MBYTE    (48*1024)
/*	fix INSTALL.html if those change */


/* srvr/db.c */
extern void db_failure(int, const char *, int, DCC_EMSG,
		       const char *, ...) DCC_PF(5,6);
extern void db_error_msg(int, const char *, const char *, ...) DCC_PF(3,4);
extern void db_set_flush(DB_STATE *, u_char, u_int);
#define SET_FLUSH_RCD(st,u)	db_set_flush(st,u, DB_RCD_LEN((st)->d.r))
#define SET_FLUSH_RCD_HDR(st,u)	db_set_flush(st,u, DB_RCD_HDR_LEN)
#define SET_FLUSH_HE(st)	db_set_flush(st, 0, sizeof(HASH_ENTRY))
#define SET_FLUSH_HCTL(u)   db_set_flush(&db_sts.hash_ctl,u, sizeof(HASH_CTL))
extern void rel_db_states(void);
extern u_char db_unload(DCC_EMSG, u_char);
extern u_char db_flush_db(DCC_EMSG);
extern u_char make_clean(u_char);
extern u_char db_close(int);
extern void db_stop(void);
extern u_char lock_dbclean(DCC_EMSG, const char *);
extern void unlock_dbclean(void);
extern u_int db_get_pagesize(u_int, u_int);
extern u_char db_buf_init(u_int, u_int);
typedef u_char DB_OPEN_MODES;
# define DB_OPEN_RDONLY		    0x01
# define DB_OPEN_LOCK_WAIT	    0x02    /* wait to get lock */
# define DB_OPEN_LOCK_NOWAIT	    0x04    /* get lock but don't wait */
# define DB_OPEN_MSYNC		    0x08    /* use msync() instead of write() */
# define DB_OPEN_PREFER_MSYNC	    0x10    /* default */
# define DB_OPEN_WRITE		    0x20    /* use write() instead of msync() */
# define DB_OPEN_PREFER_WRITE	    0x40
# define DB_OPEN_MSYNC_DBCLEAN	    0x80    /* what dbclean needs */
extern u_char db_open(DCC_EMSG, int, const char *, const char *,
		      DB_HADDR, DB_OPEN_MODES);
extern u_char db_flush_parms(DCC_EMSG );
#define DB_IS_LOCKED() (db_locked.tv_sec != 0)
extern int db_lock(void);
extern u_char db_unlock(void);
extern void db_flush_needed(void);
extern DCC_TGTS db_sum_ck(DCC_TGTS, DCC_TGTS, DCC_CK_TYPES);
extern const char *db_ptr2str(DB_PTR);
extern const char *size2str(char *, u_int, double, u_char);
extern double db_add_rate(const DB_PARMS *, u_char, u_char);
extern DB_NOKEEP_CKS def_nokeep_cks(void);
extern void set_db_tholds(DB_NOKEEP_CKS);
extern u_char db_map_rcd(DCC_EMSG, DB_STATE *, DB_PTR, int *);
extern DB_RCD_CK *db_map_rcd_ck(DCC_EMSG, DB_STATE *, DB_PTR, DCC_CK_TYPES);
extern DB_HADDR get_db_hash_divisor(DB_HADDR);
extern DB_HADDR db_hash(DCC_CK_TYPES, const DCC_SUM *);
typedef enum {
    DB_FOUND_SYSERR=0,			/* fatal error */
    DB_FOUND_IT,
    DB_FOUND_EMPTY,			/* home slot empty */
    DB_FOUND_CHAIN,			/* not in chain--have last entry */
    DB_FOUND_INTRUDER			/* intruder in home slot */
} DB_FOUND;
extern DB_FOUND db_lookup(DCC_EMSG, DCC_CK_TYPES, const DCC_SUM *,
			  DB_STATE *, DB_STATE *, DB_RCD_CK **);
extern u_char db_link_rcd(DCC_EMSG);
extern DB_PTR db_add_rcd(DCC_EMSG, const DB_RCD *);

#endif /* DB_H */
