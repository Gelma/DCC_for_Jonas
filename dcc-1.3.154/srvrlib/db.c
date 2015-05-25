/* Distributed Checksum Clearinghouse
 *
 * server database functions
 *
 * Copyright (c) 2012 by Rhyolite Software, LLC
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
 * Rhyolite Software DCC 1.3.154-1.243 $Revision$
 */

#include "srvr_defs.h"
#include <syslog.h>
#include <sys/resource.h>
#if defined(HAVE_HW_PHYSMEM) || defined(HAVE_BOOTTIME)
#include <sys/sysctl.h>
#endif
#ifdef HAVE_PSTAT_GETSTATIC		/* HP-UX */
#include <sys/pstat.h>
#endif


DB_STATS db_stats;

DB_STATES db_sts;

DCC_PATH db_path_buf;

int db_fd = -1;
DCC_PATH db_nm;
int db_hash_fd = -1;
DCC_PATH db_hash_nm;
struct timeval db_locked;		/* 1=database not locked */

struct timeval db_time;

int db_debug;

u_char grey_on;

DB_BUF_MODE db_buf_mode_hash, db_buf_mode_db;

static u_char db_dirty;
static u_char db_rdonly;
int db_failed_line;			/* bad happened at this line # */
const char *db_failed_file;		/*	in this file */
static u_char db_invalidate;		/* do not write to the files */

u_char db_minimum_map;			/* this is dccd & dbclean is running */

static u_char dirty_parts;		/* have non-urgent dirty buffers */

time_t db_need_flush_secs;
static time_t db_urgent_need_flush_secs;


/* Without mmap(MAP_NOSYNC) as on Solaris and Linux or a good msync() on BSD/OS,
 * we must rely on the kernel's update/syncer/bufdaemon/etc.  So in this
 * case just fondle the mmap()'ed pages and hope things work out.
 *
 * With the hash table in a memory file "tmpfs" on FreeBSD, Solaris, or Linux,
 * we stop worrying about flushing to disk and be happy.
 *
 * With a msync() and with mmap(MAP_NOSYNC), use MAP_NOSYNC if we can because
 * some systems flush too quickly while others such as FreeBSD 6.1 stall
 * for seconds while thinking about flushing the database.
 * But with mmap(MAP_NOSYNC) we leave large amounts of data in RAM that take
 * too long time to be pushed to the disk when the system is shutting down.
 * So
 *	- hit only those chunks of memory with real data or changes to data
 *	    with msync().  Trust dbclean to rebuild everything else at need.
 *
 *	- when it seems the system is being shut down, delete the hash table
 *	    and let it be rebuilt when the system is rebooted.  When the
 *	    hash table is rebuilt, Some markings in the data file that
 *	    might have been lost will be remade.
 *
 * A third case involves dccd -F.  It requires that all changes be pushed to
 * the disk whenever dccd unlocks the database so that dbclean can see changes
 * dccd makes.  It also requires that dbclean write all of its changes so
 * that dccd will find them when it reopens the database.
 */

#if !defined(MAP_NOSYNC) || defined(HAVE_OLD_MSYNC) || !defined(HAVE_BOOTTIME)
#undef USE_MAP_NOSYNC
#else
#define USE_MAP_NOSYNC
#endif

/* Note whether either the hash table or the data is unsynchronized with
 * the disk.  Synchronizing with or flushing to the disk makes no sense
 * when a memory or tmpfs file system is used, but the hash table can be in
 * a tmpfs file while the data should have a disk file for stable storage. */
static u_char db_not_synced;


#define DCC_MADV_WILLNEED(p) 0
#ifdef MADV_WILLNEED
#undef DCC_MADV_WILLNEED
#define DCC_MADV_WILLNEED(p) madvise(p, db_pagesize, MADV_WILLNEED)
#endif
#ifdef POSIX_MADV_WILLNEED
#undef DCC_MADV_WILLNEED
#define DCC_MADV_WILLNEED(p) posix_madvise(p, db_pagesize, POSIX_MADV_WILLNEED)
#endif

#define DCC_MADV_RANDOM(p) 0
#ifdef MADV_RANDOM
#undef DCC_MADV_RANDOM
#define DCC_MADV_RANDOM(p) madvise(p, db_pagesize, MADV_RANDOM)
#endif
#ifdef POSIX_MADV_RANDOM
#undef DCC_MADV_RANDOM
#define DCC_MADV_RANDOM(p) posix_madvise(p, db_pagesize, POSIX_MADV_RANDOM)
#endif

#define DCC_MADV_DONTNEED(p) 0
/* The Linux people claim that it is just fine that their notion of
 * MADV_DONTNEED implies discarding changes to data.  Worse, some versions of
 * Linux/GNU libc define POSIX_MADV_DONTNEED as the data-corrupting Linux
 * MADV_DONTNEED.  This seems to be because they cannot admit their mistake of
 * not distinguishing between the functions of MADV_FREE and MADV_DONTNEED and
 * their misreading of other systems' documentation for MADV_DONTNEED */
#ifndef linux
#ifdef MADV_DONTNEED
#undef DCC_MADV_DONTNEED
#define DCC_MADV_DONTNEED(p) madvise(p, db_pagesize, MADV_DONTNEED)
#endif
#ifdef POSIX_MADV_DONTNEED
#undef DCC_MADV_DONTNEED
#define DCC_MADV_DONTNEED(p) posix_madvise(p, db_pagesize, POSIX_MADV_DONTNEED)
#endif
#endif /* !linux */

#undef DCC_MADV_FREE
#ifdef MADV_FREE
#define DCC_MADV_FREE(p) madvise(p, db_pagesize, MADV_FREE)
#endif
#ifdef POSIX_MADV_FREE
#define DCC_MADV_FREE(p) posix_madvise(p, db_pagesize, POSIX_MADV_FREE)
#endif


int db_buf_total;			/* total # of db buffers */
DB_PTR db_max_rss;			/* maximum db resident set size */
DB_PTR db_max_byte;			/* maximum db bytes in both files */

u_int sys_pagesize;			/* kernel page size */

static DB_BUF db_bufs[DB_BUF_MAX];	/* control mmap()'ed blocks */
static DB_BUF *buf_oldest, *buf_newest;

#define DB_HASH_TOTAL DB_BUF_MAX
static DB_BUF *db_buf_hash[DB_HASH_TOTAL];
/* fancy 16-bit multiplicative hash assumes multiplication needs 1 cycle
 * and so the hash is faster than dealing with a collision */
#define DB_BUF_HASH(pnum,t) (&db_buf_hash[((((pnum)*(t)*0x9ccf) & 0xffff)   \
					   * DB_BUF_MAX) >> 16])

const DB_VERSION_BUF db_version_buf = DB_VERSION_STR;
DB_PARMS db_parms;
static DB_PARMS db_parms_stored;

DCC_TGTS db_tholds[DCC_DIM_CKS];

u_int db_pagesize;			/* size of 1 mmap()'ed buffer */
static u_int db_pagesize_part;

DB_HOFF db_hash_fsize;			/* size of hash table file */
static u_int hash_clear_pg_num;
DB_HADDR db_hash_len;			/* # of hash table entries */
DB_HADDR db_hash_divisor;		/* hash function modulus */
DB_HADDR db_hash_used;			/* # of hash table entries in use */
u_int db_hash_page_len;			/* # of HASH_ENTRYs per buffer */
static u_int hash_sys_pagesize;		/* HASH_ENTRYs per 1 or 2 system pages */
static u_int hash_sys_pagesize2;
DB_HADDR db_max_hash_entries = 0;	/* after db_buf_init()*/
DB_PTR db_fsize;			/* size of database file */
DB_PTR db_csize;			/* database file contents in bytes */
static DB_PTR db_csize_stored_hash;	/* DB size stored in hash file */
static DB_HADDR db_hash_used_stored_hash;
u_int db_page_max;			/* only padding after this in DB buf */
static DB_PTR db_window_size;		/* size of mmap() window */
char db_window_size_str[128];
static char db_physmem_str[80];

static const u_char dcc_ck_fuzziness[DCC_DIM_CKS] = {
	0,				/* DCC_CK_INVALID */
	DCC_CK_FUZ_LVL_NO,		/* DCC_CK_IP */
	DCC_CK_FUZ_LVL_NO,		/* DCC_CK_ENV_FROM */
	DCC_CK_FUZ_LVL_NO,		/* DCC_CK_FROM */
	DCC_CK_FUZ_LVL_NO,		/* DCC_CK_SUB */
	DCC_CK_FUZ_LVL_NO,		/* DCC_CK_MESSAGE_ID */
	DCC_CK_FUZ_LVL_NO,		/* DCC_CK_RECEIVED */
	DCC_CK_FUZ_LVL_NO,		/* DCC_CK_BODY */
	DCC_CK_FUZ_LVL1,		/* DCC_CK_FUZ1 */
	DCC_CK_FUZ_LVL2,		/* DCC_CK_FUZ2 */
	DCC_CK_FUZ_LVL_REP,		/* DCC_CK_REP_TOTAL */
	DCC_CK_FUZ_LVL_REP,		/* DCC_CK_REP_BULK */
	DCC_CK_FUZ_LVL2,		/* DCC_CK_SRVR_ID */
	DCC_CK_FUZ_LVL2			/* DCC_CK_ENV_TO */
};
static const u_char grey_ck_fuzziness[DCC_DIM_CKS] = {
	0,				/* DCC_CK_INVALID */
	DCC_CK_FUZ_LVL2,		/* DCC_CK_IP */
	DCC_CK_FUZ_LVL_NO,		/* DCC_CK_ENV_FROM */
	DCC_CK_FUZ_LVL_NO,		/* DCC_CK_FROM */
	DCC_CK_FUZ_LVL_NO,		/* DCC_CK_SUB */
	DCC_CK_FUZ_LVL_NO,		/* DCC_CK_MESSAGE_ID */
	DCC_CK_FUZ_LVL_NO,		/* DCC_CK_RECEIVED */
	DCC_CK_FUZ_LVL_NO,		/* DCC_CK_BODY */
	DCC_CK_FUZ_LVL_NO,		/* DCC_CK_FUZ1 */
	DCC_CK_FUZ_LVL_NO,		/* DCC_CK_FUZ2 */
	DCC_CK_FUZ_LVL_NO,		/* DCC_CK_GREY_MSG */
	DCC_CK_FUZ_LVL1,		/* DCC_CK_GREY_TRIPLE */
	DCC_CK_FUZ_LVL1,		/* DCC_CK_SRVR_ID */
	DCC_CK_FUZ_LVL1			/* DCC_CK_ENV_TO */
};
const u_char *db_ck_fuzziness = dcc_ck_fuzziness;


static u_char buf_flush(DCC_EMSG, DB_BUF *, u_char);
static u_char buf_munmap(DCC_EMSG, DB_BUF *);
static DB_BUF *find_buf(DCC_EMSG, DB_BUF_TYPE, DB_PG_NUM);
static u_char map_hash(DCC_EMSG, DB_HADDR, DB_STATE *, u_char);
static u_char map_hash_ctl(DCC_EMSG, u_char);
static u_char map_db(DCC_EMSG, DB_PTR, u_int, DB_STATE *, u_char);
static u_char db_set_sizes(DCC_EMSG);


/* compute the least common multiple of two numbers */
static u_int
lcm(u_int n, u_int m)
{
	u_int r, x, gcd;

	/* first get the gcd of the two numbers */
	if (n >= m) {
		x = n;
		gcd = m;
	} else {
		x = m;
		gcd = n;
	}
	for (;;) {
		r = x % gcd;
		if (r == 0)
			return n * (m / gcd);
		x = gcd;
		gcd = r;
	}
}



const char *
db_ptr2str(DB_PTR val)
{
	static int bufno;
	static struct {
	    char    str[16];
	} bufs[4];
	char *s;
	const char *units;

	if (val == 0)
		return "0";

	s = bufs[bufno].str;
	bufno = (bufno+1) % DIM(bufs);

	if (val % (1024*1024*1024) == 0) {
		val /= (1024*1024*1024);
		units = "GB";
	} else if (val % (1024*1024) == 0) {
		val /= (1024*1024);
		units = "MB";
	} else if (val % 1024 == 0) {
		val /= 1024;
		units = "KB";
	} else {
		units = "";
	}
	if (val > 1000*1000*1000)
		snprintf(s, sizeof(bufs[0].str), "%d,%03d,%03d,%03d%s",
			 (int)(val / (1000*1000*1000)),
			 (int)(val / (1000*1000)) % 1000,
			 (int)(val / 1000) % 1000,
			 (int)(val % 1000),
			 units);
	else if (val > 1000*1000)
		snprintf(s, sizeof(bufs[0].str), "%d,%03d,%03d%s",
			 (int)(val / (1000*1000)),
			 (int)(val / 1000) % 1000,
			 (int)(val % 1000),
			 units);
	else if (val > 1000*10)
		snprintf(s, sizeof(bufs[0].str), "%d,%03d%s",
			 (int)(val / 1000),
			 (int)(val % 1000),
			 units);
	else
		snprintf(s, sizeof(bufs[0].str), "%d%s",
			 (int)val,
			 units);
	return s;
}



const char *
size2str(char *buf, u_int buf_len,
	 double num, u_char bytes_or_entries)	/* 0=number 1=bytes */
{
	const char *units;
	double k;

	k = bytes_or_entries ? 1024.0 : 1000.0;

	if (num < k) {
		units = "";
	} else if (num < k*k) {
		num /= k;
		units = "K";
	} else if (num < k*k*k) {
		num /= k*k;
		units = "M";
	} else {
		num /= k*k*k;
		units = "G";
	}

	if ((int)num >= 100)
		snprintf(buf, buf_len, "%.0f%s", num, units);
	else
		snprintf(buf, buf_len, "%.2g%s", num, units);
	return buf;
}



void DCC_PF(5,6)
db_failure(int linenum, const char *file, int ex_code, DCC_EMSG emsg,
	   const char *p, ...)
{
	va_list args;

	if (!db_failed_line) {
		db_failed_line = linenum;
		db_failed_file = file;
	}
	va_start(args, p);
	dcc_vpemsg(ex_code, emsg, p, args);
	va_end(args);
}



void DCC_PF(3,4)
db_error_msg(int linenum, const char *file, const char *p, ...)
{
	va_list args;

	if (!db_failed_line) {
		db_failed_line = linenum;
		db_failed_file = file;
	}
	va_start(args, p);
	dcc_verror_msg(p, args);
	va_end(args);
}



static inline double
rate_sub(time_t total_secs, double added,
	 time_t delta_secs, double cur, double prev)
{
	if (total_secs <= 0 || total_secs > DB_MAX_RATE_SECS
	    || added <= 0.0) {
		added = 0.0;
		total_secs = 0;
	}

	if (delta_secs > 0 && delta_secs <= DB_MAX_RATE_SECS
	    && cur > prev) {
		total_secs += delta_secs;
		added += cur - prev;
	}

	if (total_secs < DB_MIN_RATE_SECS || total_secs > DB_MAX_RATE_SECS)
		return -1.0;
	return added / total_secs;
}



double					/* hashes or bytes/second */
db_add_rate(const DB_PARMS *parms,
	    u_char hash_or_db,		/* 1=hash */
	    u_char vers)		/* 0=both, 1=cur only, 2=old only */
{
	time_t delta_secs;
	double cur_rate, prev_rate;

	delta_secs = parms->last_rate_sec - ts2secs(&parms->sn);

	if (hash_or_db) {
		cur_rate = rate_sub(parms->rate_secs, parms->hash_added,
				    delta_secs,
				    parms->hash_used, parms->old_hash_used);
		prev_rate = rate_sub(parms->prev_rate_secs,
				     parms->prev_hash_added, 0, 0, 0);
	} else {
		cur_rate = rate_sub(parms->rate_secs, parms->db_added,
				    delta_secs,
				    parms->db_csize, parms->old_db_csize);
		prev_rate = rate_sub(parms->prev_rate_secs,
				     parms->prev_db_added, 0, 0, 0);
	}

	/* answer with a single rate if required */
	if (vers == 1)
		return cur_rate;
	if (vers == 2)
		return prev_rate;

	/* Answer with our best guess.  That is the current data if the
	 * past data is not good enough.  Otherwise it is the larger
	 * rate. */
	if (prev_rate > 0.0 && parms->rate_secs+delta_secs < DB_GOOD_RATE_SECS)
		return prev_rate;
	return max(prev_rate, cur_rate);
}



DB_NOKEEP_CKS
def_nokeep_cks(void)
{
	DCC_CK_TYPES type;
	DB_NOKEEP_CKS nokeep = 0;

	for (type = DCC_CK_TYPE_FIRST; type <= DCC_CK_TYPE_LAST; ++type) {
		if (DB_GLOBAL_NOKEEP(grey_on, type))
			DB_SET_NOKEEP(nokeep, type);
	}
	DB_SET_NOKEEP(nokeep, DCC_CK_INVALID);
	DB_SET_NOKEEP(nokeep, DCC_CK_FLOD_PATH);

	return nokeep;
}



void
set_db_tholds(DB_NOKEEP_CKS nokeep)
{
	DCC_CK_TYPES type;

	for (type = 0; type < DIM(db_tholds); ++type) {
		db_tholds[type] = (DB_TEST_NOKEEP(nokeep, type)
				   ? DCC_TGTS_INVALID
				   : DCC_CK_IS_REP0(grey_on, type)
				   ? DCC_TGTS_INVALID
				   : grey_on
				   ? 1
				   : type == DCC_CK_SRVR_ID
				   ? 1
				   : BULK_THRESHOLD);
	}
}



static const char *
buf2path(const DB_BUF *b)
{
	switch (b->buf_type) {
	case DB_BUF_TYPE_HASH:
		return db_hash_nm;
	case DB_BUF_TYPE_DB:
		return db_nm;
	case DB_BUF_TYPE_FREE:
	default:
		dcc_logbad(EX_SOFTWARE, "impossible buffer type for a path");
	}
}



static int
buf2fd(const DB_BUF *b)
{
	switch (b->buf_type) {
	case DB_BUF_TYPE_HASH:
		return db_hash_fd;
	case DB_BUF_TYPE_DB:
		return db_fd;
	case DB_BUF_TYPE_FREE:
	default:
		dcc_logbad(EX_SOFTWARE, "impossible buffer type for fd");
	}
}



static void
rel_db_state(DB_STATE *st)
{
	DB_BUF *b;

	b = st->b;
	if (!b)
		return;
	st->b = 0;
	st->d.v = 0;
	st->s.rptr = DB_PTR_BAD;
	if (--b->lock_cnt < 0)
		dcc_logbad(EX_SOFTWARE, "negative database buffer lock");
}



void
rel_db_states(void)
{
	DB_STATE *st;

	for (st = &db_sts.rcd; st <= &db_sts.hash_ctl; ++st) {
		rel_db_state(st);
	}
}



/* release one or all unneeded buffers */
u_char					/* 0=problem 1=did nothing 2=did>=1 */
db_unload(DCC_EMSG emsg,
	  u_char some)			/* 0=all, 1=only one, 2=finished */
{
	DB_BUF *b;
	u_char result;

	result = 1;
	for (b = buf_oldest; b != 0; b = b->newer) {
		if (b->buf_type == DB_BUF_TYPE_FREE
		    || b->lock_cnt != 0)
			continue;
		if (some == 2
		    && !(b->flags & DB_BUF_FG_USE_WRITE)
		    && 0 > DCC_MADV_DONTNEED(b->buf.v))
			dcc_error_msg("madvise(DONTNEED %s,%#x): %s",
				      buf2path(b), db_pagesize, ERROR_STR());
		if (!buf_munmap(emsg, b)) {
			emsg = 0;
			result = 0;
		} else if (result) {
			result = 2;
		}
		if (some == 1)
			return result;
	}

	return result;
}



static u_char
buf_write_part(DCC_EMSG emsg, DB_BUF *b, off_t offset, void *buf, int len)
{
	int i;

	offset += (off_t)b->pg_num * (off_t)db_pagesize;

	if (offset != lseek(buf2fd(b), offset, SEEK_SET)) {
		db_failure(__LINE__,__FILE__, EX_IOERR, emsg,
			   "buf_write_part lseek(%s,"OFF_HPAT"): %s",
			   buf2path(b), offset, ERROR_STR());
		return 0;
	}
	i = write(buf2fd(b), buf, len);
	if (i != len) {
		db_failure(__LINE__,__FILE__, EX_IOERR, emsg,
			   "buf_write_part(%s,%u)=%d: %s",
			   buf2path(b), len, i, ERROR_STR());
		return 0;
	}

	return 1;
}



/* push part of a buffer toward the disk
 *	this can be needed even when the file has been opened and mapped
 *	read-only by dbclean */
static u_char
buf_flush_part(DCC_EMSG emsg, DB_BUF *b,
	       u_int part,		/* DB_BUF_NUM_PARTS=buffer */
	       u_char async DCC_UNUSED)
{
	u_int flush_len;
	char *flush_base;
	DB_BUF_FM bit;

	bit = PART2BIT(part) & (b->flush | b->flush_urgent);
	if (!bit)
		return 1;

	/* Send a new buffer to disk at once. */
	if (b->flags & DB_BUF_FG_ANON_EXTEND) {
		DB_BUF *b1, *b0;
		u_char result;

		/* To give the file system a chance to make the hash table
		 * contiguous, first write all preceding new buffers.
		 * In almost all cases, there will be none. */
		result = 1;
		do {
			b0 = b;
			for (b1 = buf_oldest; b1 != 0; b1 = b1->newer) {
				if (!(b1->flags & DB_BUF_FG_ANON_EXTEND)
				    || b1->buf_type != b0->buf_type
				    || b1->pg_num >= b0->pg_num)
					continue;
				b0 = b1;
			}
			b0->flags &= ~DB_BUF_FG_ANON_EXTEND;
			b0->flush = 0;
			b0->flush_urgent = 0;
			if (!db_invalidate
			    && !buf_write_part(emsg, b0,
					       0, b0->buf.c, db_pagesize))
				result = 0;
		} while (b0 != b);
		return result;
	}

	flush_base = b->ranges[part].lo;
	flush_len = b->ranges[part].hi - flush_base;
	b->flush &= ~bit;
	b->flush_urgent &= ~bit;

	if (db_invalidate)
		return 1;

	if (b->flags & DB_BUF_FG_USE_WRITE) {
		static char *wbuf;
		static u_int wbuf_len;

		/* In at least FreeBSD you cannot write() to the file
		 * that underlies a mmap() region from that region */
		if (wbuf_len < db_pagesize_part) {
			/* the page size for the current file
			 * might be different from the old file */
			if (wbuf)
				free(wbuf);
			wbuf_len = db_pagesize_part;
			wbuf = malloc(wbuf_len);
		}

		memcpy(wbuf, flush_base, flush_len);
		return buf_write_part(emsg, b, flush_base - b->buf.c,
				      wbuf, flush_len);

	} else if (DB_BUF_MODE_B(b) == DB_BUF_MODE_TMPFS) {
		/* do nothing on RAM file systems */
		;

#ifndef HAVE_OLD_MSYNC
	} else if (async) {
		if (0 > MSYNC(flush_base, flush_len, MS_ASYNC)) {
			db_failure(__LINE__,__FILE__, EX_IOERR, emsg,
				   "msync(db buffer %s,%#lx,%#x,MS_ASYNC): %s",
				   buf2path(b), (long)flush_base, flush_len,
				   ERROR_STR());
			return 0;
		}
#endif
	} else {
		if (0 > MSYNC(flush_base, flush_len, MS_SYNC)) {
			db_failure(__LINE__,__FILE__, EX_IOERR, emsg,
				   "msync(db buffer %s,%#lx,%#x,MS_SYNC): %s",
				   buf2path(b), (long)flush_base, flush_len,
				   ERROR_STR());
			return 0;
		}
	}

	return 1;
}



static u_char
buf_flush(DCC_EMSG emsg, DB_BUF *b, u_char async)
{
	u_int part;
	DB_BUF_FM bits;
	u_char result = 1;

	bits = b->flush_urgent | b->flush;
	for (part = 0; bits != 0 && part < DB_BUF_NUM_PARTS; ++part) {
		if (bits & PART2BIT(part)) {
			if (!buf_flush_part(emsg, b, part, async)) {
				emsg = 0;
				result = 0;
			}
			bits = b->flush_urgent | b->flush;
		}
	}
	return result;
}



/* Try to keep the data clean so that the fsync() required by Solaris
 *	when the file is unloaded is not too expensive.
 *	Try to flush frequently so that we don't stall as long in msync().
 */
void
db_flush_needed(void)
{
	static DB_BUF *next_b = db_bufs;
	static u_int next_part;
	DB_BUF *b;
	u_int part, all_parts;
	int buf_num;
	u_char worked;

	/* send to the disk changes that cannot be recreated by dbclean */
	if (db_urgent_need_flush_secs != 0
	    && DB_IS_TIME(db_urgent_need_flush_secs,
			  DB_URGENT_NEED_FLUSH_SECS)) {
		worked = 0;
		for (b = buf_newest; b; b = b->older) {
			if (b->buf_type == DB_BUF_TYPE_FREE)
				continue;

			for (part = 0;
			     b->flush_urgent != 0 && part < DB_BUF_NUM_PARTS;
			     ++part) {
				if ((b->flush_urgent & PART2BIT(part))) {
					buf_flush_part(0, b, part, 1);
					worked = 1;
				}
			}

			/* Switch new data pages to mmap()
			 * when this is not dbclean (since only dccd calls here)
			 *	and when they are not already using mmap()
			 *	and when they are not the last data page */
			if ((b->flags & DB_BUF_FG_USE_WRITE)
			    && DB_BUF_MODE_B(b) != DB_BUF_MODE_WRITE
			    && (b->buf_type != DB_BUF_TYPE_DB
				|| (DB_PTR2PG_NUM(db_csize-1, db_pagesize)
				    != b->pg_num))) {
				if (b->lock_cnt != 0)
					rel_db_states();
				buf_munmap(0, b);
			}
		}

		/* Keep the clock running if we did any work. This tends to
		 * avoid stalls caused by colliding with the FreeBSD syncer */
		if (worked) {
			gettimeofday(&db_time, 0);
			db_urgent_need_flush_secs = (db_time.tv_sec
						+ DB_URGENT_NEED_FLUSH_SECS);
		} else {
			db_urgent_need_flush_secs = 0;
		}
	}

	/* assume there will be nothing more to do */
	db_need_flush_secs = db_urgent_need_flush_secs;

	/* if we are using mmap(MAP_NOSYNC), then there are no bits
	 * set in any b->flush words except that of the recent
	 * DB_BUF_FG_USE_WRITE extensions of the file.  It is best to let
	 * those blocks stay in RAM until the whole buffer is flushed and
	 * switched to mmap above */
	if (!dirty_parts)
		return;

	b = next_b;
	part = next_part;
	all_parts =  DB_PARTS_PER_FLUSH;
	for (buf_num = DIM(db_bufs); buf_num >= 0; --buf_num) {
		if (b > LAST(db_bufs)) {
			part = 0;
			b = db_bufs;
		}
		if (!b->flush
		    || part >= DB_BUF_NUM_PARTS
		    || b->buf_type == DB_BUF_TYPE_FREE
		    || ((b->flags & DB_BUF_FG_ANON_EXTEND)
			&& b->buf_type == DB_BUF_TYPE_DB
			&& (DB_PTR2PG_NUM(db_csize-1, db_pagesize)
			    != b->pg_num))) {
			part = 0;
			++b;
			continue;
		}

		while (part < DB_BUF_NUM_PARTS) {
			if (b->flush & PART2BIT(part)) {
				buf_flush_part(0, b, part, 1);
				if (--all_parts == 0) {
					next_part = part+1;
					next_b = b;
					db_need_flush_secs = (db_time.tv_sec
							+ DB_NEED_FLUSH_SECS);
					return;
				}
				if (!b->flush)
					part = DB_BUF_NUM_PARTS;
			}
			++part;
		}
	}

	/* it is all finished */
	dirty_parts = 0;
}



/* occassionally flush an unlocked data buffer for dbclean
 *	dbclean mostly changes only the current record, so get started
 *	writing the data to avoid stalling the system at the end. */
u_char
db_flush_db(DCC_EMSG emsg DCC_UNUSED)
{
	DB_BUF *b;
	int limit;
#ifdef USE_MAP_NOSYNC
	int pg_num;

	/* Gently push the new hash table to disk.
	 * The disk image will never be accurate.  This only allocates space.
	 * Do not do this for systems that lack mmap(MAP_NOSYNC) such as Linux
	 * that thrash themselves as the hash table is being built.  A
	 * long pause when the database is closed is not as bad as spending
	 * hours building the hash table. */
	if (db_buf_mode_hash != DB_BUF_MODE_WRITE) {
		while (hash_clear_pg_num < db_hash_fsize/db_hash_page_len) {
			pg_num = hash_clear_pg_num++;
			for (b = buf_oldest; b != 0; b = b->newer) {
				if (b->pg_num != pg_num
				    || b->buf_type != DB_BUF_TYPE_HASH)
					continue;
				if (!(b->flags & DB_BUF_FG_ANON_EXTEND))
					break;
				if (b->lock_cnt != 0)
					rel_db_states();
				return buf_munmap(emsg, b);
			}

			/* look for the next page if this one has already
			 * been flushed */
		}
	}
#endif

	/* flush some ordinary buffers that must be flushed eventually */
	limit = 2;
	for (b = buf_oldest; b != 0 && b != buf_newest; b = b->newer) {
		if (b->flush_urgent == 0
		    || b->buf_type == DB_BUF_TYPE_FREE
		    || b->lock_cnt != 0)
			continue;
		if (!buf_flush(emsg, b, 1))
			return 0;
		if (--limit <= 0)
			return 1;
	}
	return 1;
}



/* mark part of a buffer dirty
 *	"Urgent" changes are flushed by a timer.  Ordinary changes
 *	are often ignored and expected to be rebuilt if the system crashes.
 *	That the hash table is deleted as the system is shut down while the
 *	database must be flushed from the system's buffer cache is a reason
 *	to keep the disk image of the database good. */
void
db_set_flush(DB_STATE *st, u_char urgent, u_int len)
{
	DB_BUF *b;
	DB_BUF_FM bit, new_bits, old_bits;
	char *buf_base, *part_end, *start, *end;
	u_int part, i;

	/* nothing to do if the kernel is handling it
	 * or if we are letting this change be reconstructed by dbclean */
	b = st->b;
	if (!(b->flags & DB_BUF_FG_USE_WRITE)) {
#ifdef USE_MAP_NOSYNC
		if (!urgent)
			return;
#endif
		if (DB_BUF_MODE_B(b) == DB_BUF_MODE_TMPFS)
			return;
	}

	start = st->d.c;
	buf_base = b->buf.c;

	/* Increase to even pages in the hope that the file system might
	 * be able to page-flip.  This might at least avoid reading into the
	 * buffer cache to honor a write(). Besides, Solaris' msync() handles
	 * only even pages. */
	i = (start - buf_base) % sys_pagesize;
	start -= i;
	len += i;
	len = ((len + sys_pagesize-1) / sys_pagesize) * sys_pagesize;

	end = start + len;
	if (end > buf_base+db_pagesize)
		dcc_logbad(EX_SOFTWARE, "inflated dirty buffer size");

	part = (start - buf_base) / db_pagesize_part;
	part_end = buf_base + part * db_pagesize_part;
	bit = PART2BIT(part);
	new_bits = 0;
	old_bits = b->flush | b->flush_urgent;
	do {
		part_end += db_pagesize_part;
		if (part_end > end)
			part_end = end;

		if (!(old_bits & bit)) {
			b->ranges[part].lo = start;
			b->ranges[part].hi = part_end;
		} else {
			if (b->ranges[part].lo > start)
				b->ranges[part].lo = start;
			if (b->ranges[part].hi < part_end)
				b->ranges[part].hi = part_end;
		}
		new_bits |= bit;

		start = part_end;
		bit <<= 1;
		++part;
	} while (part_end < end);

	if (urgent) {
		b->flush_urgent |= new_bits;
		if (!db_urgent_need_flush_secs) {
			db_urgent_need_flush_secs = (db_time.tv_sec
						+ DB_URGENT_NEED_FLUSH_SECS);
			if (db_need_flush_secs == 0)
				db_need_flush_secs = db_urgent_need_flush_secs;
		}
	} else {
		b->flush |= new_bits;
		dirty_parts = 1;
		if (db_need_flush_secs == 0
		    || db_need_flush_secs > db_time.tv_sec+DB_NEED_FLUSH_SECS)
			db_need_flush_secs = db_time.tv_sec+DB_NEED_FLUSH_SECS;
	}
}



/* Shut down the database, including flushing and releasing all
 *	mmap()'ed buffers
 * Do nothing to the files for mode=-1 because the file is new and garbage
 *	or the caller is a fork of the server shedding memory. */
u_char
db_close(int mode)			/* -1=invalidate, 0=dirty, 1=clean */
{
	u_char result;

	if (mode >= 0) {
		/* flush the data and then release and flush the dirty flags */
		result = make_clean(mode == 0 ? 0 : 1);
		if (!db_unload(0, 0))
			result = 0;
	} else {
		db_invalidate = 1;
		rel_db_states();
		result = (db_unload(0, 0) > 0);
	}

	/* Close the hash table first because the server is often
	 * waiting for the lock on the main file held by dbclean.
	 * Destroy the hash table if it is bad */
	if (db_hash_fd >= 0) {
		if (0 > close(db_hash_fd)) {
			dcc_error_msg("close(%s): %s",
				  db_hash_nm, ERROR_STR());
			result = 0;
		}
		db_hash_fd = -1;
	}
	if (db_fd >= 0) {
		if (0 > close(db_fd)) {
			dcc_error_msg("close(%s): %s", db_nm, ERROR_STR());
			result = 0;
		}
		db_fd = -1;
	}

	db_locked.tv_sec = 0;
	return result;
}



/* Delete the hash table if the system is being rebooted and we
 * don't trust the file system to get all of the hash table.
 * This might make system shut down faster */
void
db_stop(void)
{
	if (db_hash_fd < 0
	    || db_rdonly
	    || !db_not_synced
	    || db_hash_nm[0] == '\0'
	    || db_lock() < 0)
		return;

	make_clean(0);

	if (0 > unlink(db_hash_nm)
	    && errno != ENOENT)
		dcc_error_msg("unlink(%s): %s", db_hash_nm, ERROR_STR());
}



/* see if (another) instance of dbclean is already running */
static int dbclean_lock_fd = -1;
static DCC_PATH dbclean_lock_nm;

u_char					/* 1=no (other) dbclean */
lock_dbclean(DCC_EMSG emsg, const char *cur_db_nm)
{
	char pid[32];
	int i;

	dcc_fnm2rel_good(dbclean_lock_nm, cur_db_nm, DB_LOCK_SUFFIX);
	dbclean_lock_fd = dcc_lock_open(emsg, dbclean_lock_nm,
					O_RDWR|O_CREAT,
					DCC_LOCK_OPEN_NOWAIT,
					DCC_LOCK_ALL_FILE, 0);
	if (dbclean_lock_fd < 0)
		return 0;

	i = 1+snprintf(pid, sizeof(pid), "%ld\n", (long)getpid());
	if (i != write(dbclean_lock_fd, pid, i))
		dcc_logbad(EX_IOERR, "write(%s, pid): %s",
			   dbclean_lock_nm, ERROR_STR());

	/* Let anyone write in it in case we are running as root
	 * and get interrupted by a crash or gdb.  A stray, stale
	 * private lock file cannot be locked */
	chmod(dbclean_lock_nm, 0666);

	return 1;
}



void
unlock_dbclean(void)
{
	if (dbclean_lock_fd >= 0) {
		if (0 > unlink(dbclean_lock_nm))
			dcc_error_msg("unlink(%s): %s",
				      dbclean_lock_nm, ERROR_STR());
		close(dbclean_lock_fd);
		dbclean_lock_fd = -1;
	}
}



/* This locking does only multiple-readers/single-writer */
int					/* -1=failed, 0=was not locked, 1=was */
db_lock(void)
{
	struct stat sb;

	if (DB_IS_LOCKED())
		return 1;

	if (!dcc_exlock_fd(0, db_fd, DCC_LOCK_ALL_FILE, 15*60, "", db_nm))
		return -1;
	if (0 > fstat(db_fd, &sb)) {
		db_failure(__LINE__,__FILE__, EX_IOERR, 0,
			   "stat(%s): %s", db_nm, ERROR_STR());
		return -1;
	}
	if (db_fsize != (DB_HOFF)sb.st_size) {
		if (db_fsize > (DB_HOFF)sb.st_size || !db_rdonly) {
			db_failure(__LINE__,__FILE__, EX_IOERR, 0,
				   "%s size changed from "OFF_HPAT
				   " to "OFF_HPAT,
				   db_nm, db_fsize, sb.st_size);
			return -1;
		}
		db_fsize = sb.st_size;
	}

	db_locked = db_time;
	return 0;
}



/* flush buffers to make the disk reasonably correct but not perfect
 *	This does not compensate for a lack of coherent mmap() in the system.
 *
 *	It leaves the disk only as accurate as implied by db_not_synced.
 *	This flushes buffers marked either urgent and ordinarily dirty.
 *	If db_not_synced is set, then non-urgent dirty bits are not set. */
static u_char
make_clean_flush(void)
{
	DB_BUF *b;
	u_char result;

	result = 1;
	for (b = buf_oldest; b != 0; b = b->newer) {
		if (b->buf_type == DB_BUF_TYPE_FREE)
			continue;
		if (!buf_flush(0, b, 0))
			result = 0;
	}

	return result;
}



/* push all of our database changes to the disk and try to clear the dirty bit
 *	do not necessarily unmap anything */
u_char
make_clean(u_char clean)		/* 0=leave hash marked dirty, */
{					/*	1=marked clean, 2=fsync */
	u_char need_db_fsync, result;
	struct stat sb;

	rel_db_states();

	result = 1;

	/* quit if we are giving up */
	if (db_invalidate)
		return result;

	if (db_failed_line)
		clean = 0;

	if (!make_clean_flush()) {
		clean = 0;
		result = 0;
	}

	/* simply unlock all of the buffers if they are clean
	 * and do not need to (or cannot) be synchronized with fsync() */
	if (!db_dirty
	    && (clean < 2		/* not asked to synchronize */
		|| db_rdonly		/* cannot be synchronized */
		|| !db_not_synced))	/* does not need to be synchronized */
		return result;

	need_db_fsync = (clean == 2);

	/* Send the meta-data to disk so that other processes
	 * such as dbclean can find the new length of the file
	 * on Solaris.  Otherwise the file looks broken because
	 * its contained data length can be larger than its
	 * inode size on Solaris. */
	if (!need_db_fsync && clean) {
		if (0 > fstat(db_fd, &sb)) {
			dcc_error_msg("make_clean fstat(%s): %s",
				      db_nm, ERROR_STR());
			need_db_fsync = 1;
		} else if (db_fsize != (DB_HOFF)sb.st_size) {
			if (db_debug)
				quiet_trace_msg("need fsync() because db_fsize="
						OFF_HPAT" but stat="OFF_HPAT,
						db_fsize, sb.st_size);
			need_db_fsync = 1;
		}
	}

	if (need_db_fsync
	    && db_buf_mode_db != DB_BUF_MODE_TMPFS
	    && 0 > fsync(db_fd)) {
		dcc_error_msg("make_clean fsync(%s): %s",
			      db_nm, ERROR_STR());
		clean = 0;
		result = 0;
	}

	if (clean && !map_hash_ctl(0, 0)) {
		clean = 0;
		result = 0;
	}
	if (clean == 2) {
		if (db_buf_mode_hash != DB_BUF_MODE_TMPFS
		    && 0 > fsync(db_hash_fd)) {
		    dcc_error_msg("make_clean fsync(%s): %s",
				      db_hash_nm, ERROR_STR());
			clean = 0;
			result = 0;
		} else {
			db_not_synced = 0;
			db_sts.hash_ctl.d.vals->s.flags &= ~HASH_CTL_FG_NOSYNC;
			SET_FLUSH_HCTL(1);
			if (!make_clean_flush()) {
				clean = 0;
				result = 0;
			}
		}
	}

	/* Clean the dirty flag in the hash table.
	 * With luck, this will reach the disk after everything else. */
	if (clean
	    && !(db_sts.hash_ctl.d.vals->s.flags & HASH_CTL_FG_CLEAN)) {
		db_sts.hash_ctl.d.vals->s.flags |= HASH_CTL_FG_CLEAN;
		SET_FLUSH_HCTL(0);
	}

	/* finally flush the flag in the hash table */
	rel_db_states();
	if (!make_clean_flush())
		result = 0;

	if (clean)
		db_dirty = 0;
	return result;
}



/* mark the hash file and so the database dirty */
static u_char
db_make_dirty(DCC_EMSG emsg)
{
	if (db_dirty)
		return 1;

	if (!DB_IS_LOCKED())
		dcc_logbad(EX_SOFTWARE, "dirtying unlocked database");

	if (db_rdonly)
		dcc_logbad(EX_SOFTWARE, "dirtying read-only database");

	if (!map_hash_ctl(emsg, 0))
		return 0;
	db_sts.hash_ctl.d.vals->s.flags &= ~HASH_CTL_FG_CLEAN;
#ifdef USE_MAP_NOSYNC
	if (db_buf_mode_hash == DB_BUF_MODE_MSYNC) {
		if (!(db_sts.hash_ctl.d.vals->s.flags & HASH_CTL_FG_NOSYNC)) {
			db_sts.hash_ctl.d.vals->s.synced = time(0);
			db_sts.hash_ctl.d.vals->s.flags |= HASH_CTL_FG_NOSYNC;
		}
		db_not_synced = 1;
	}
#endif

	SET_FLUSH_HCTL(1);
	if (!buf_flush_part(emsg, db_sts.hash_ctl.b, 0, 0))
		return 0;

	db_dirty = 1;
	return 1;
}



/* (start to) unlock the database */
u_char					/* 0=failed, 1=at least started */
db_unlock(void)
{
	DB_BUF *b;
	int result;

	if (!DB_IS_LOCKED())
		return 1;

	/* Clear the dirty bit in the database because we may not
	 * be able to lock the database later to clear the dirty bit.
	 * Dbclean needs to see the dirty bit clear. */
	result = make_clean(1);

	/* Release DB_BUF_FG_USE_WRITE buffers because they are not consistent
	 *	among processes
	 * Release everything if dccd wants stay out of RAM in favor
	 *	of dbclean */
	for (b = buf_oldest; b != 0; b = b->newer) {
		if (b->buf_type == DB_BUF_TYPE_FREE)
			continue;
		if (db_minimum_map
		    || (b->flags & DB_BUF_FG_USE_WRITE))
			buf_munmap(0, b);
	}

	if (!dcc_unlock_fd(0, db_fd, DCC_LOCK_ALL_FILE, "", db_nm))
		result = 0;
	db_locked.tv_sec = 0;
	return result;
}



static const char *
mbyte2str(DB_PTR val)
{
	return db_ptr2str(val*1024*1024);
}



#if defined(RLIMIT_AS) || defined(RLIMIT_RSS) || defined(RLIMIT_FSIZE)
static DB_PTR
use_rlimit(int resource, const char *rlimit_nm,
	   DB_PTR cur_val, DB_PTR min_val, const char *val_nm)
{
	struct rlimit limit_old, limit_new;
	DB_PTR new_val;

	if (0 > getrlimit(resource, &limit_old)) {
		dcc_error_msg("getrlimit(%s): %s", rlimit_nm, ERROR_STR());
		return cur_val;
	}

	if ((DB_PTR)limit_old.rlim_cur >= cur_val+DB_PAD_MBYTE*1024)
		return cur_val;

	/* assume we are root and try to increase the hard limit */
	if ((DB_PTR)limit_new.rlim_max < cur_val+DB_PAD_BYTE) {
		limit_new = limit_old;
		limit_new.rlim_max = cur_val+DB_PAD_BYTE;
		if (0 > setrlimit(resource, &limit_new)) {
			if (db_debug)
				quiet_trace_msg("setrlimit(%s, "
						L_DPAT","L_DPAT"): %s",
						rlimit_nm,
						(DB_PTR)limit_new.rlim_cur,
						(DB_PTR)limit_new.rlim_max,
						ERROR_STR());
		} else {
			if (0 > getrlimit(resource, &limit_old)) {
				dcc_error_msg("getrlimit(%s): %s",
					      rlimit_nm, ERROR_STR());
				return cur_val;
			}
		}
	}

	limit_new = limit_old;
	if ((DB_PTR)limit_new.rlim_max < min_val+DB_PAD_BYTE)
		limit_new.rlim_max = min_val + DB_PAD_BYTE;
	limit_new.rlim_cur = limit_new.rlim_max;
	if ((DB_PTR)limit_new.rlim_cur > cur_val+DB_PAD_BYTE)
		limit_new.rlim_cur = cur_val+DB_PAD_BYTE;
	if (0 > setrlimit(resource, &limit_new)) {
		dcc_error_msg("setrlimit(%s, "L_DPAT","L_DPAT"): %s",
			      rlimit_nm,
			      (DB_PTR)limit_new.rlim_cur,
			      (DB_PTR)limit_new.rlim_max,
			      ERROR_STR());
		new_val = limit_old.rlim_cur - DB_PAD_BYTE;
		if (new_val < min_val)
			new_val = min_val;
	} else {
		if (limit_old.rlim_cur < limit_new.rlim_cur
		    && db_debug)
			quiet_trace_msg("increased %s from %s to %s",
					rlimit_nm,
					db_ptr2str(limit_old.rlim_cur),
#ifdef RLIM_INFINITY
					(limit_new.rlim_cur == RLIM_INFINITY)
					? "infinity" :
#endif
					db_ptr2str(limit_new.rlim_cur));
		new_val = limit_new.rlim_cur - DB_PAD_BYTE;
	}

	if (cur_val > new_val) {
		quiet_trace_msg("%s reduced %s from %s to %s",
				rlimit_nm, val_nm,
				db_ptr2str(cur_val),
				db_ptr2str(new_val));
		return new_val;
	}

	return cur_val;
}
#endif



static void
get_db_max_rss(void)
{
	DB_PTR old_val, new_val, db_min_mbyte, db_min_byte, db_max_mbyte;
	int physmem_str_len;
	DB_PTR physmem;
	u_char complain;

	complain = db_debug;

	/* use default maximum if maximum is bogus or unset by ./configure */
	db_max_mbyte = MAX_MAX_DB_MBYTE;
#if DCC_DB_MAX_MBYTE != 0
	db_max_mbyte = DCC_DB_MAX_MBYTE;
	if (db_max_mbyte < DB_MIN_MIN_MBYTE
	    || db_max_mbyte > MAX_MAX_DB_MBYTE) {
		quiet_trace_msg("ignore bad ./configure --with-max-db-mem=%d",
				DCC_DB_MAX_MBYTE);
		db_max_mbyte = MAX_MAX_DB_MBYTE;
	} else {
		if (db_max_mbyte < DB_NEEDED_MBYTE && !grey_on)
			complain = 1;
		if (complain) {
			quiet_trace_msg("DB max=%s"
					" from ./configure --with-max-db-mem=%d",
					mbyte2str(db_max_mbyte),
					DCC_DB_MAX_MBYTE);
		}
	}
#endif
#ifndef HAVE_BIG_FILES
	/* we need big off_t for files larger than 2 GBytes */
	if (db_max_mbyte > DB_MAX_2G_MBYTE) {
		old_val = db_max_mbyte;
		db_max_mbyte= DB_MAX_2G_MBYTE;
		if (complain)
			quiet_trace_msg("32-bit off_t reduced DB max from %s"
					" to %s",
					mbyte2str(old_val),
					mbyte2str(db_max_mbyte));
	}
#endif

	/* use default if ./configure --with-db-memory=MB is bogus or unset */
#if DCC_DB_MIN_MBYTE == 0
	db_min_mbyte = min(64, db_max_mbyte);
#else
	db_min_mbyte = DCC_DB_MIN_MBYTE;
	if (db_min_mbyte < DB_MIN_MIN_MBYTE) {
		quiet_trace_msg("ignore bad ./configure --with-db-memory=%d",
				DCC_DB_MIN_MBYTE);
		db_min_mbyte = DB_DEF_MIN_MBYTE;
	} else if (db_min_mbyte > db_max_mbyte) {
		quiet_trace_msg("ignore ./configure --with-db-memory=%d"
				" > DB max=%s",
				mbyte2str(db_max_mbyte));
		db_min_mbyte = DB_DEF_MIN_MBYTE;
	} else if (complain) {
		quiet_trace_msg("use ./configure --with-db-memory=%d",
				db_min_mbyte);
	}
#endif

	db_min_byte = db_min_mbyte * (1024*1024);
	db_max_byte = db_max_mbyte * (1024*1024);

#ifdef RLIMIT_FSIZE
	db_max_mbyte = (use_rlimit(RLIMIT_FSIZE, "RLIMIT_FSIZE",
				   db_max_byte, db_min_byte, "DB max")
			/ (1024*1024));
	db_max_byte = db_max_mbyte * (1024*1024);
#endif /* RLIMIT_FSIZE */

	physmem = 0;
#ifdef HAVE_PHYSMEM_TOTAL
	/* maybe someday physmem_total() will be widely available */
	physmem = physmem_total();
	if (physmem/(1024*1024) < DB_NEEDED_MBYTE && !grey_on)
		complain = 1;
	if (complain)
		quiet_trace_msg("real=%s from physmem_total()",
				db_ptr2str(physmem));
#endif
#ifdef HAVE__SC_PHYS_PAGES
	if (physmem == 0) {
		long pages, sizepage;

		if ((pages = sysconf(_SC_PHYS_PAGES)) == -1) {
			dcc_error_msg("sysconf(_SC_PHYS_PAGES): %s",
				      ERROR_STR());
		} else if ((sizepage = sysconf(_SC_PAGESIZE)) == -1) {
			dcc_error_msg("sysconf(_SC_PAGESIZE): %s",
				      ERROR_STR());
		} else {
			physmem = (DB_PTR)pages * (DB_PTR)sizepage;
			if (physmem/(1024*1024) < DB_NEEDED_MBYTE && !grey_on)
				complain = 1;
			if (complain)
				quiet_trace_msg("real=%s"
						" from sysconf(_SC_PHYS_PAGES)"
						" and sysconf(_SC_PAGESIZE)",
						db_ptr2str(physmem));
		}
	}
#endif
#ifdef HAVE_HW_PHYSMEM
	if (physmem == 0) {
		int mib[2] = {CTL_HW, HW_PHYSMEM};
		unsigned long int hw_physmem;
		size_t hw_physmem_len;

		hw_physmem_len = sizeof(hw_physmem);
		if (0 > sysctl(mib, 2, &hw_physmem, &hw_physmem_len, 0,0)) {
			dcc_error_msg("sysctl(HW_PHYSMEM): %s", ERROR_STR());
		} else {
			physmem = hw_physmem;
			if (physmem/(1024*1024) < DB_NEEDED_MBYTE && !grey_on)
				complain = 1;
			if (complain)
				quiet_trace_msg("real=%s from sysctl(mib)",
						db_ptr2str(physmem));
		}
	}
#endif
#ifdef HAVE_PSTAT_GETSTATIC
	if (physmem == 0) {
		struct pst_static pss;

		if (0 > pstat_getstatic(&pss, sizeof pss, 1, 0)) {
			dcc_error_msg("pstat_getstatic(): %s", ERROR_STR());
		} else if (pss.physical_memory <= 0
			   || pss.page_size < 0) {
			dcc_error_msg("pstat_getstatic() says"
				      " physical_memory=%d page_size=%d",
				      pss.physical_memory, pss.page_size);
		} else {
			physmem = ((DB_PTR)pss.physical_memory
				   * (DB_PTR)pss.page_size);
			if (physmem/(1024*1024) < DB_NEEDED_MBYTE && !grey_on)
				complain = 1;
			if (complain)
				quiet_trace_msg("real=%s"
						" from pstat_getstatic()",
						db_ptr2str(physmem));
		}
	}
#endif

	physmem_str_len = 0;
	db_physmem_str[0] = '\0';
	if (physmem == 0) {
		quiet_trace_msg("failed to get real memory size");
	} else {
		physmem_str_len = snprintf(db_physmem_str,
					   sizeof(db_physmem_str),
					   "  real=%s",
					   db_ptr2str(physmem));

		/* Try to use half of physical memory
		 *	if there is less than 2 GBytes
		 * all except 512 MBytes between 2 GByte and 4 GBytes,
		 * and all but 1 GByte if there are more than 4 GBytes
		 * fix FAQ.html if this changes. */
		if (physmem/(1024*1024) < 2*1024)
			new_val = physmem/2;
		else if (physmem/(1024*1024) <= 4*1024)
			new_val = physmem - 512*(1024*1024);
		else
			new_val = physmem - 1024*(1024*1024);
		if (new_val < db_min_byte) {
			if (!grey_on)
				complain = 1;
			if (complain)
				quiet_trace_msg("real=%s would give DB max=%s"
						" smaller than minimum %s",
						db_ptr2str(physmem),
						db_ptr2str(new_val),
						mbyte2str(db_min_mbyte));
			new_val = db_min_byte;
		}
		if (db_max_byte > new_val) {
			old_val = db_max_byte;
			db_max_mbyte = new_val / (1024*1024);
			db_max_byte = db_max_mbyte * (1024*1024);
			if (db_max_byte < DB_NEEDED_MBYTE && !grey_on)
				complain = 1;
			if (complain)
				quiet_trace_msg("real=%s reduced DB max"
						" from %s to %s",
						db_ptr2str(physmem),
						db_ptr2str(old_val),
						db_ptr2str(db_max_byte));
		}
	}

	/* window need not be larger than the limit on the database size */
	db_max_rss = db_max_byte;

#ifdef RLIMIT_AS
	/* try not to break process virtual memory limit,
	 * but only if it is not ridiculously tiny */
	db_max_rss = use_rlimit(RLIMIT_AS, "RLIMIT_AS",
				db_max_rss, db_min_byte, "max RSS");
#endif /* RLIMIT_AS */
#ifdef RLIMIT_RSS
	/* try not to break process resident memory limit
	 * but only if it is not ridiculously tiny */
	db_max_rss = use_rlimit(RLIMIT_RSS, "RLIMIT_RSS",
				db_max_rss, db_min_byte, "max RSS");
#endif /* RLIMIT_RSS */

	/* limit the database to the window size */
	if (db_max_byte > db_max_rss) {
		old_val = db_max_mbyte;
		db_max_mbyte = db_max_rss / (1024*1024);
		db_max_byte = db_max_mbyte * (1024*1024);
		if (db_max_byte < DB_NEEDED_MBYTE && !grey_on)
			complain = 1;
		if (complain)
			quiet_trace_msg("max RSS reduced DB max from %s to %s",
					mbyte2str(old_val),
					mbyte2str(db_max_mbyte));
	}

#ifndef HAVE_64BIT_PTR
	/* We cannot use a window larger than 2 GBytes on most systems without
	 * big pointers.  Among the things that break is trying to mmap() more
	 * than 2 GBytes.  So limit the window on 32-bit systems to a little
	 * less than 2 GBytes and the database to not much more */
	if (db_max_rss > DB_MAX_2G_MBYTE*(1024*1024)) {
		if (complain)
			quiet_trace_msg("32-bit pointers reduced max RSS"
					" from %s to %s",
					db_ptr2str(db_max_rss),
					mbyte2str(DB_MAX_2G_MBYTE));
		db_max_rss = DB_MAX_2G_MBYTE*(1024*1024);
		new_val = db_max_rss+db_max_rss/4;
		if (db_max_byte > new_val) {
			old_val = db_max_mbyte;
			db_max_mbyte = new_val / (1024*1024);
			db_max_byte = db_max_mbyte * (1024*1024);
			if (complain)
				quiet_trace_msg("32-bit pointers reduced DB max"
						" from %s to %s",
						mbyte2str(old_val),
						mbyte2str(db_max_mbyte));
		}
	}
#endif

	snprintf(&db_physmem_str[physmem_str_len],
		 sizeof(db_physmem_str) - physmem_str_len,
		 "  max RSS=%s  DB max=%s",
		 db_ptr2str(db_max_rss), mbyte2str(db_max_mbyte));
}



/* Pick a buffer size that will hold an integral number of DB hash
 * table entries and is a multiple of system's page size.
 * The entire hash table should reside in memory
 * if the system has enough memory. */
u_int
db_get_pagesize(u_int old_pagesize,	/* 0 or required page size */
		u_int tgt_pagesize)	/* 0 or target page size */
{
	u_int min_pagesize, max_pagesize;

	/* Ask the operating system only once so we don't get differing
	 * answers and so compute a varying page size.
	 * Some systems can't keep their stories straight. */
	if (db_max_rss == 0)
		get_db_max_rss();

	sys_pagesize = getpagesize();

	/* Compute the number of DB hash table entries that fit in one
	 * and two system pages */
	hash_sys_pagesize = sys_pagesize / sizeof(HASH_ENTRY);
	hash_sys_pagesize2 = (sys_pagesize*2) / sizeof(HASH_ENTRY);

	/* Compute the least common multiple of the system page and
	 * the DB hash table entry size.
	 * This will give us the smallest page size that we can use. */
	min_pagesize = lcm(sys_pagesize, sizeof(HASH_ENTRY));

	/* The kludge to speed conversion of database addresses to page numbers
	 * and offsets on 32-bit systems depends on the page size being
	 * a multiple of 256 */
	if ((min_pagesize % (1<<DB_PTR_SHIFT)) != 0)
		dcc_logbad(EX_SOFTWARE, "page size not a multiple of 256");

	/* The DB buffer or page size must also be a multiple of the
	 * the end-of-page padding used in the main database file. */
	if (sizeof(DB_RCD) % DB_RCD_HDR_LEN != 0)
		dcc_logbad(EX_SOFTWARE,
			   "DB padding size %d"
			   " is not a divisor of DB entry size %d",
			   DB_RCD_HDR_LEN, ISZ(DB_RCD));
	if (DB_RCD_LEN_MAX % DB_RCD_HDR_LEN != 0)
		dcc_logbad(EX_SOFTWARE,
			   "DB record not a multiple of header size");
	min_pagesize = lcm(min_pagesize, DB_RCD_HDR_LEN);

	/* Use the old buffer size if available so we are not confused
	 * by padding at the ends of the old pages.
	 * Fail if it is impossible.  This should cause dbclean to
	 * rebuild the database. */
	if (old_pagesize != 0) {
		if ((old_pagesize % min_pagesize) != 0)
			return 0;
		/* adjust the number of buffers to fit our window size */
		db_buf_total = db_max_rss / old_pagesize;
		if (db_buf_total < (int)DB_BUF_MIN)
			return 0;
		if (db_buf_total > DB_BUF_MAX)
			db_buf_total = DB_BUF_MAX;
		return old_pagesize;
	}

	db_buf_total = DB_BUF_MAX;
	max_pagesize = db_max_rss / db_buf_total;
	max_pagesize -= max_pagesize % min_pagesize;

	/* If we have a target page size, try to use it instead of the
	 * maximum page size allowed by the resident set size.
	 * Normal DCC databases grow large and want pages as large as possible
	 * but greylist databases are often small.
	 * We also want a tiny page when first reading the parameters while
	 * opening. */
	if (tgt_pagesize != 0 && tgt_pagesize < max_pagesize) {
		tgt_pagesize -= tgt_pagesize % min_pagesize;
		if (tgt_pagesize < min_pagesize)
			tgt_pagesize = min_pagesize;
		return tgt_pagesize;
	} else if (max_pagesize > min_pagesize) {
		return max_pagesize;
	} else {
		return min_pagesize;
	}
}



/* (re)create the buffer pool
 * The buffers are small blocks that point to the real mmap()'ed memory.
 */
u_char
db_buf_init(u_int old_pagesize,		/* 0 or required page size */
	    u_int tgt_pagesize)		/* 0 or target page size */
{
	DB_BUF *b, *bprev, *bnext;
	int i;


	db_pagesize = db_get_pagesize(old_pagesize, tgt_pagesize);
	if (db_pagesize == 0)
		return 0;

	/* The fragments of pages must be multiples of system pages
	 * so that msync() on Solaris can be given multiples of system
	 * pages.  It's also a generally good idea. */
	db_pagesize_part = db_pagesize/DB_BUF_NUM_PARTS;
	db_pagesize_part = ((db_pagesize_part + sys_pagesize-1)
			    / sys_pagesize) * sys_pagesize;

	db_page_max = db_pagesize - DB_RCD_HDR_LEN;
	db_hash_page_len = db_pagesize/sizeof(HASH_ENTRY);

	db_max_hash_entries = (MAX_HASH_ENTRIES
			       - MAX_HASH_ENTRIES % db_hash_page_len);

	memset(db_bufs, 0, sizeof(db_bufs));
	b = db_bufs;
	buf_oldest = b;
	bprev = 0;
	for (i = db_buf_total; --i != 0; b = bnext) {
		bnext = b+1;
		b->older = bprev;
		b->newer = bnext;
		bprev = b;
	}
	b->older = bprev;
	buf_newest = b;

	memset(db_buf_hash, 0, sizeof(db_buf_hash));

	return 1;
}



static u_char
make_new_hash(DCC_EMSG emsg, DB_HADDR new_hash_len)
{
	struct stat sb;
	HASH_ENTRY *hash;
	DB_HADDR next_haddr, cur_haddr, prev_haddr;
	u_int pagenum;

	if (getuid() == 0) {
		/* if we are running as root,
		 * don't change the owner of the database */
		if (0 > fstat(db_fd, &sb)) {
			dcc_pemsg(EX_IOERR, emsg, "fstat(%s): %s",
				  db_nm, ERROR_STR());
			return 0;
		}
		if (0 > fchown(db_hash_fd, sb.st_uid, sb.st_gid)) {
			dcc_pemsg(EX_IOERR, emsg, "fchown(%s,%d,%d): %s",
				  db_hash_nm, (int)sb.st_uid, (int)sb.st_gid,
				  ERROR_STR());
			return 0;
		}
	}

	if (new_hash_len < MIN_HASH_ENTRIES)
		new_hash_len = MIN_HASH_ENTRIES;

	/* Increase the requested hash table size to a multiple of the database
	 * page size.  The page size is chosen to be a multiple of the size of
	 * a single hash table entry. */
	db_hash_fsize = (((DB_HOFF)new_hash_len)*sizeof(HASH_ENTRY)
			 + db_pagesize-1);
	db_hash_fsize -= db_hash_fsize % db_pagesize;
	new_hash_len = db_hash_fsize / sizeof(HASH_ENTRY);

	if (new_hash_len > db_max_hash_entries)
		new_hash_len = db_max_hash_entries;

	/* create the empty hash table file */
	rel_db_states();
	if (!db_unload(emsg, 0))
		return 0;
	if (0 > ftruncate(db_hash_fd, 0)) {
		dcc_pemsg(EX_IOERR, emsg, "ftruncate(%s,0): %s",
			  db_hash_nm, ERROR_STR());
		return 0;
	}

	db_hash_len = new_hash_len;
	db_hash_used_stored_hash = db_hash_used = DB_HADDR_BASE;
	db_hash_divisor = get_db_hash_divisor(db_hash_len);

	/* Clear new hash file by linking its entries into the free list */
	/* map and clear the first page */
	if (!map_hash_ctl(emsg, 1))
		return 0;

	/* create the header */
	strcpy(db_sts.hash_ctl.d.vals->s.magic, HASH_MAGIC_STR);
	db_sts.hash_ctl.d.vals->s.free_fwd = DB_HADDR_BASE;
	db_sts.hash_ctl.d.vals->s.free_bak = db_hash_len-1;
	db_sts.hash_ctl.d.vals->s.len = db_hash_len;
	db_sts.hash_ctl.d.vals->s.divisor = db_hash_divisor;
	db_sts.hash_ctl.d.vals->s.used = DB_HADDR_BASE;
	db_sts.hash_ctl.d.vals->s.synced = time(0);
	db_dirty = 1;
#ifdef USE_MAP_NOSYNC
	if (db_buf_mode_hash == DB_BUF_MODE_MSYNC) {
		db_sts.hash_ctl.d.vals->s.flags |= HASH_CTL_FG_NOSYNC;
		db_not_synced = 1;
	}
#endif

	/* Link the hash table entries in the first and following pages.
	 * The page size is chosen to be a multiple of the size of a
	 * single hash table entry. */
	prev_haddr = FREE_HADDR_END;
	cur_haddr = DB_HADDR_BASE;
	next_haddr = cur_haddr+1;
	hash = &db_sts.hash_ctl.d.vals->h[DB_HADDR_BASE];
	pagenum = 0;
	for (;;) {
		do {
			DB_HADDR_CP(hash->bak, prev_haddr);
			if (next_haddr == db_hash_len)
				DB_HADDR_CP(hash->fwd, FREE_HADDR_END);
			else
				DB_HADDR_CP(hash->fwd, next_haddr);
			++hash;
			prev_haddr = cur_haddr;
			cur_haddr = next_haddr++;
		} while (cur_haddr % db_hash_page_len != 0);

		if (++pagenum >= db_hash_fsize/db_pagesize)
			break;

		if (!map_hash(emsg, cur_haddr, &db_sts.free, 1))
			return 0;
		db_sts.free.b->flush_urgent = (DB_BUF_FM)-1;
		hash = db_sts.free.d.h;
	}

	hash_clear_pg_num = 0;

	return 1;
}



static u_char
check_old_hash(DCC_EMSG emsg)
{
	static const u_char magic[sizeof(((HASH_CTL*)0)->s.magic)
				  ] = HASH_MAGIC_STR;
	const HASH_CTL *vals;
	struct stat sb;
	u_char old_db;

	/* check the size of the existing hash file */
	if (0 > fstat(db_hash_fd, &sb)) {
		dcc_pemsg(EX_IOERR, emsg, "stat(%s): %s",
			  db_hash_nm, ERROR_STR());
		return 0;
	}
	db_hash_fsize = sb.st_size;
	if ((db_hash_fsize % sizeof(HASH_ENTRY)) != 0) {
		dcc_pemsg(EX_DATAERR, emsg, "%s has size "OFF_DPAT","
			  " not a multiple of %d",
			  db_hash_nm, db_hash_fsize,
			  ISZ(HASH_ENTRY));
		return 0;
	}

	db_hash_len = db_hash_fsize/sizeof(HASH_ENTRY);
	if (db_hash_len < MIN_HASH_ENTRIES) {
		dcc_pemsg(EX_DATAERR, emsg,
			  "%s has too few records, "OFF_DPAT" bytes",
			  db_hash_nm, db_hash_fsize);
		return 0;
	}

	/* check the magic number */
	if (!map_hash_ctl(emsg, 0))
		return 0;
	vals = db_sts.hash_ctl.d.vals;
	if (memcmp(vals->s.magic, &magic, sizeof(magic))) {
		dcc_pemsg(EX_DATAERR, emsg,
			  "%s has the wrong magic \"%s\""
			  " instead of \""HASH_MAGIC_STR"\"",
			  db_hash_nm, esc_magic(vals->s.magic,
						sizeof(HASH_ENTRY)));
		return 0;
	}

	if (!(vals->s.flags & HASH_CTL_FG_CLEAN)) {
		dcc_pemsg(EX_DATAERR, emsg, "%s was not closed cleanly",
			  db_hash_nm);
		return 0;
	}
	if (vals->s.flags & HASH_CTL_FG_NOSYNC) {
#ifdef HAVE_BOOTTIME
		int mib[2] = {CTL_KERN, KERN_BOOTTIME};
		size_t boottime_len;
#endif
		struct timeval boottime;

		boottime.tv_sec = 0x7fffffff;
#ifdef HAVE_BOOTTIME
		boottime_len = sizeof(boottime);
		if (0 > sysctl(mib, 2, &boottime, &boottime_len, 0, 0)) {
			dcc_error_msg("sysctl(KERN_BOOTTIME): %s", ERROR_STR());
		}
#endif
		if (TIME_T(vals->s.synced) <= boottime.tv_sec) {
			dcc_pemsg(EX_DATAERR, emsg, "%s was not synchronized;"
				  " synced=%d boottime=%d",
				  db_hash_nm,
				  (int)vals->s.synced, (int)boottime.tv_sec);
			return 0;
		}
		db_not_synced = 1;
	}

	if (DB_HADDR_INVALID(vals->s.free_fwd)
	    && (vals->s.free_fwd != FREE_HADDR_END
		|| vals->s.free_fwd != vals->s.free_bak)) {
		dcc_pemsg(EX_DATAERR, emsg,
			  "%s has a broken free list head of %#x",
			  db_hash_nm, vals->s.free_fwd);
		return 0;
	}
	if (DB_HADDR_INVALID(vals->s.free_bak)
	    && (vals->s.free_bak != FREE_HADDR_END
		|| vals->s.free_fwd != vals->s.free_bak)) {
		dcc_pemsg(EX_DATAERR, emsg,
			  "%s has a broken free list tail of %#x",
			  db_hash_nm, vals->s.free_bak);
		return 0;
	}

	if (db_hash_len != vals->s.len) {
		dcc_pemsg(EX_DATAERR, emsg,
			  "%s has %d entries but claims %d",
			  db_hash_nm, db_hash_len,
			  vals->s.len);
		return 0;
	}

	db_hash_divisor = vals->s.divisor;
	if (db_hash_divisor < MIN_HASH_DIVISOR
	    || db_hash_divisor >= db_hash_len) {
		dcc_pemsg(EX_DATAERR, emsg, "%s has hash divisor %d",
			  db_hash_nm, db_hash_len);
		return 0;
	}

	db_hash_used_stored_hash = db_hash_used = vals->s.used;
	if (db_hash_used < DB_HADDR_BASE) {
		dcc_pemsg(EX_DATAERR, emsg,
			  "%s contains impossible %u entries",
			  db_hash_nm, HADDR2LEN(db_hash_used));
		return 0;
	}
	if (db_hash_used >= db_hash_len) {
		if (db_hash_used > db_hash_len)
			dcc_pemsg(EX_DATAERR, emsg,
				  "%s contains only %u entries but %u used",
				  db_hash_nm,
				  HADDR2LEN(db_hash_len),
				  HADDR2LEN(db_hash_used));
		else
			dcc_pemsg(EX_DATAERR, emsg,
				  "%s is filled with %u entries",
				  db_hash_nm,
				  HADDR2LEN(db_hash_len));
		return 0;
	}

	/* old databases lack the growth values */
	old_db = 0;
	if (!db_rdonly
	    && db_parms.old_db_csize == 0
	    && db_parms.db_added == 0
	    && db_parms.hash_used == 0
	    && db_parms.old_hash_used == 0
	    && db_parms.hash_added == 0
	    && db_parms.rate_secs == 0
	    && db_parms.last_rate_sec == 0) {
		quiet_trace_msg("repair database growth measurements");
		db_parms.old_db_csize = db_parms.db_csize;
		old_db = 1;
	}

	if (db_hash_used != db_parms.hash_used
	    && db_hash_fsize != 0) {
		if (old_db) {
			quiet_trace_msg("repair db_parms.old hash_used"
					" and old_hash_used");
			db_parms.old_hash_used = db_hash_used;
			db_parms.hash_used = db_hash_used;
		} else {
			dcc_pemsg(EX_DATAERR, emsg,
				  "%s contains %d"
				  " entries instead of the %d that %s claims",
				  db_hash_nm, db_hash_used,
				  db_parms.hash_used, db_nm);
			return 0;
		}
	}

	db_csize_stored_hash = vals->s.db_csize;
	if (db_csize_stored_hash != db_csize
	    && db_hash_fsize != 0) {
		dcc_pemsg(EX_DATAERR, emsg,
			  "%s contains "L_DPAT
			  " bytes instead of the "L_DPAT" that %s claims",
			  db_nm, db_csize,
			  db_csize_stored_hash, db_hash_nm);
		return 0;
	}

	return 1;
}



/* open the files and generally get ready to work */
u_char					/* 0=failed, 1=ok */
db_open(DCC_EMSG emsg,
	int new_db_fd,			/* -1 or already open db_fd */
	const char *new_db_nm,
	const char *new_hash_nm,
	DB_HADDR new_hash_len,		/* 0 or # of entries */
	DB_OPEN_MODES db_mode)		/* DB_OPEN_* */
{
	u_int cur_pagesize;
	int hash_flags, db_open_flags;
	struct stat db_sb;
#	define OPEN_BAIL() {if (new_db_fd >= 0) db_fd = -1;		\
		db_close(-1); return 0;}

	db_close(1);
	db_failed_line = __LINE__;
	db_failed_file = __FILE__;
	db_not_synced = 0;
	db_minimum_map = 0;
	db_invalidate = 0;
	db_dirty = 0;
	db_locked.tv_sec = 0;

	db_rdonly = (db_mode & DB_OPEN_RDONLY) != 0;
	if (!db_rdonly) {
		if ((db_mode & DB_OPEN_WRITE)
		    || (db_mode & DB_OPEN_PREFER_WRITE)) {
			db_buf_mode_db = DB_BUF_MODE_WRITE;
			db_buf_mode_hash = DB_BUF_MODE_WRITE;
		} else {
			db_buf_mode_db = DB_BUF_MODE_MSYNC;
			db_buf_mode_hash = DB_BUF_MODE_MSYNC;
		}
	}

	memset(&db_stats, 0, sizeof(db_stats));

	if (!new_db_nm && db_nm[0] == '\0')
		new_db_nm = grey_on ? DB_GREY_NAME : DB_DCC_NAME;
	if (new_db_nm) {
		if (!dcc_fnm2rel(db_nm, new_db_nm, 0)) {
			dcc_pemsg(EX_DATAERR, emsg,
				  "invalid DB nm \"%s\"", new_db_nm);
			return 0;
		}
		if ((!new_hash_nm || new_hash_nm[0] == '\0')
		    && !dcc_fnm2rel(db_hash_nm, db_nm, DB_HASH_SUFFIX)) {
			dcc_pemsg(EX_DATAERR, emsg,
				  "invalid DB nm \"%s\"", new_db_nm);
			return 0;
		}
	}
	/* let dbclean use a symbolic link to put the hash table in
	 * a memory file system */
	if (new_hash_nm && new_hash_nm[0] != '\0') {
		if (!dcc_fnm2rel(db_hash_nm, new_hash_nm, 0)) {
			dcc_pemsg(EX_DATAERR, emsg,
				  "invalid DB hash nm \"%s\"", new_hash_nm);
			return 0;
		}
	}

	if (new_db_fd >= 0) {
		if (new_hash_len != 0)
			dcc_logbad(EX_SOFTWARE,
				   "extending db_open(%s) without locking",
				   db_nm);
		if (!db_rdonly)
			dcc_logbad(EX_SOFTWARE,
				   "db_open(%s) read/write without locking",
				   db_nm);
		db_open_flags = O_RDONLY;
		hash_flags = O_RDONLY;

		db_fd = new_db_fd;

	} else {
		db_open_flags = O_RDWR;
		if (new_hash_len != 0) {
			if (db_rdonly)
				dcc_logbad(EX_SOFTWARE,
					   "db_open(%s) creating read-only",
					   db_nm);
			hash_flags = O_RDWR | O_CREAT;
		} else {
			/* must open the file read/write to lock it */
			hash_flags = O_RDWR;
		}

		db_fd = dcc_lock_open(emsg, db_nm, db_open_flags,
				      (db_mode & DB_OPEN_LOCK_NOWAIT)
				      ? DCC_LOCK_OPEN_NOWAIT : 0,
				      DCC_LOCK_ALL_FILE, 0);
		if (db_fd == -1) {
			db_close(-1);
			return 0;
		}
	}
	gettimeofday(&db_time, 0);
	db_locked = db_time;
	if (0 > fstat(db_fd, &db_sb)) {
		dcc_pemsg(EX_IOERR, emsg, "stat(%s): %s", db_nm, ERROR_STR());
		OPEN_BAIL();
	}
	db_csize = db_fsize = db_sb.st_size;
	if (db_fsize < ISZ(DB_HDR)) {
		dcc_pemsg(EX_IOERR, emsg,
			  "%s with %d bytes is too small to be a DCC database",
			  db_nm, (int)db_fsize);
		OPEN_BAIL();
	}

	/* check the header of the database file by temporarily mapping it */
	db_buf_init(0, sizeof(DB_HDR));
	if (!map_db(emsg, 0, sizeof(DB_HDR), &db_sts.db_parms, 0))
		OPEN_BAIL();

	db_parms_stored = *db_sts.db_parms.d.parms;
	db_parms = *db_sts.db_parms.d.parms;

	if (memcmp(db_parms.version, db_version_buf, sizeof(db_version_buf))) {
		dcc_pemsg(EX_DATAERR, emsg,
			  "%s contains the wrong magic \"%s\""
			  " instead of \""DB_VERSION_STR"\"",
			  db_nm, esc_magic(db_parms.version,
					   sizeof(db_parms.version)));
		OPEN_BAIL();
	}
	if (!(db_parms.flags & DB_PARM_FG_GREY) != !grey_on) {
		dcc_pemsg(EX_DATAERR, emsg,
			  "%s is%s a greylist database but must%s be",
			  db_nm,
			  (db_parms.flags & DB_PARM_FG_GREY) ? "" : " not",
			  grey_on ? "" : " not");
		OPEN_BAIL();
	}

	cur_pagesize = db_parms.pagesize;

	DB_SET_NOKEEP(db_parms.nokeep_cks, DCC_CK_INVALID);
	DB_SET_NOKEEP(db_parms.nokeep_cks, DCC_CK_FLOD_PATH);
	set_db_tholds(db_parms.nokeep_cks);

	db_ck_fuzziness = grey_on ? grey_ck_fuzziness : dcc_ck_fuzziness;

	db_csize = db_parms.db_csize;
	if (db_csize < sizeof(DB_HDR)) {
		dcc_pemsg(EX_DATAERR, emsg,
			  "%s says it contains "L_DPAT" bytes"
			  " or fewer than the minimum of %d",
			  db_nm, db_csize, DB_PTR_BASE);
		/* that is a fatal error if we are not rebuilding */
		if (new_hash_len != 0)
			OPEN_BAIL();
	}
	if (db_csize > db_fsize) {
		dcc_pemsg(EX_DATAERR, emsg,
			  "%s says it contains "L_DPAT" bytes"
			  " or more than the actual size of "OFF_DPAT,
			  db_nm, db_csize, db_fsize);
		/* that is a fatal error if we are not rebuilding */
		if (new_hash_len != 0)
			OPEN_BAIL();
	}

	/* The buffer or page size we use must be the page size used to
	 * write the files.  Try to change our size to match the file */
	if (cur_pagesize != db_pagesize) {
		db_invalidate = 1;
		rel_db_states();
		if (!db_unload(emsg, 0))
			OPEN_BAIL();
		db_invalidate = 0;
		if (!db_buf_init(cur_pagesize, 0)) {
			dcc_pemsg(EX_DATAERR, emsg,
				  "%s has page size %d"
				  " incompatible with %d in %s",
				  db_nm, cur_pagesize, db_get_pagesize(0, 0),
				  dcc_path2fnm(db_hash_nm));
			OPEN_BAIL();
		}
	}

	db_csize_stored_hash = 0;
	db_hash_len = 0;
	db_hash_fd = open(db_hash_nm, hash_flags, 0666);
	if (db_hash_fd < 0) {
		dcc_pemsg(EX_IOERR, emsg, "open(%s): %s",
			  db_hash_nm, ERROR_STR());
		OPEN_BAIL();
	}
	if (0 > fcntl(db_hash_fd, F_SETFD, FD_CLOEXEC)) {
		dcc_pemsg(EX_IOERR, emsg, "fcntl(%s, FD_CLOEXEC): %s",
			  db_hash_nm, ERROR_STR());
		OPEN_BAIL();
	}

	/* Change the default write()/msync() mode if a tmpfs file system
	 * is in use.
	 * Use mmap() with implicit MAP_NOSYNC on a RAM file system
	 * without an explicit preference for write() */
	if (!db_rdonly) {
		if (istmpfs(db_fd, db_nm)) {
			if (!(db_mode & DB_OPEN_WRITE)
			    && !(db_mode & DB_OPEN_MSYNC_DBCLEAN))
				db_buf_mode_db = DB_BUF_MODE_TMPFS;
			/* tmpfs is a dubious choice for the database */
			dcc_error_msg("%s is in a memory mapped file system",
				      db_nm);
		}
		if (istmpfs(db_hash_fd, db_hash_nm)) {
			if ((db_mode & DB_OPEN_WRITE)
			    && !(db_mode & DB_OPEN_MSYNC_DBCLEAN)) {
				dcc_error_msg("cannot take advantage of memory"
					      " mapped for %s because -F used",
					      db_hash_nm);
			} else {
				db_buf_mode_hash = DB_BUF_MODE_TMPFS;
			}
		}
	}

	if (new_hash_len != 0) {
		if (!make_new_hash(emsg, new_hash_len))
			OPEN_BAIL();
	} else {
		if (!check_old_hash(emsg))
			OPEN_BAIL();
	}

	if (db_fsize % db_pagesize != 0) {
		dcc_pemsg(EX_DATAERR, emsg,
			  "%s has size "OFF_HPAT","
			  " not a multiple of its page size of %#x",
			  db_nm, db_fsize, db_pagesize);
		OPEN_BAIL();
	}
	if (db_fsize > db_csize + db_pagesize || db_csize > db_fsize) {
		dcc_pemsg(EX_DATAERR, emsg,
			  "%s has size "OFF_HPAT" but claims "L_HxPAT,
			  db_nm, db_fsize, db_csize);
		OPEN_BAIL();
	}

#ifndef USE_MAP_NOSYNC
	/* Use `dbclean -F` on systems without mmap(MAP_NOSYNC) but with
	 * lots of RAM unless explicitly overridden and unless a tmpfs file
	 * system is in use.
	 * Some Linux systems otherwise take too long to run dbclean. */
	if ((db_mode & DB_OPEN_MSYNC_DBCLEAN)
	    && db_buf_mode_hash == DB_BUF_MODE_MSYNC
	    && !(db_mode & DB_OPEN_MSYNC)) {
		const char *donot;
		if (db_max_rss < db_fsize + db_hash_fsize) {
			donot = " do not";
		} else {
			db_buf_mode_hash = DB_BUF_MODE_WRITE;
			donot = "";
		}
		if (db_debug)
			quiet_trace_msg("db_max_rss="OFF_HPAT
					" db_fsize+db_hash_fsize="OFF_HPAT
					" so%s use -F",
					db_max_rss, db_fsize+db_hash_fsize,
					donot);
	}
#endif

	db_window_size = (DB_PTR)db_pagesize * db_buf_total;
	snprintf(db_window_size_str, sizeof(db_window_size_str),
		 "window=%s%s",
		 db_ptr2str(db_window_size), db_physmem_str);
	rel_db_states();
	db_failed_line = 0;

	return 1;
#undef OPEN_BAIL
}



static u_char
buf_munmap(DCC_EMSG emsg, DB_BUF *b)
{
	u_char result;

	if (b->lock_cnt != 0)
		dcc_logbad(EX_SOFTWARE, "unmapping locked DB buffer");

	result = buf_flush(emsg, b, 1);

#ifdef DCC_MADV_FREE
	if (db_invalidate && 0 > DCC_MADV_FREE(b->buf.v))
		dcc_error_msg("madvise(FREE %s,%#x): %s",
			      buf2path(b), db_pagesize, ERROR_STR());
#endif

	if (0 > munmap(b->buf.v, db_pagesize)) {
		db_failure(__LINE__,__FILE__, EX_IOERR, emsg,
			   "munmap(%s,%d): %s",
			   buf2path(b), db_pagesize, ERROR_STR());
		result = 0;
	}
	b->buf.v = 0;
	b->pg_num = -1;
	b->buf_type = DB_BUF_TYPE_FREE;

	return result;
}



static u_char
buf_mmap(DCC_EMSG emsg, DB_BUF *b, DB_PG_NUM pg_num,
	 u_char extend)			/* add to the end of the file */
{
	int prot, flags;
	off_t offset;
	int fd;
	void *p;
	int retry;
	u_char unloaded;


	offset = (off_t)pg_num * (off_t)db_pagesize;
	fd = buf2fd(b);

	if (extend) {
		offset = 0;
		b->flags |= DB_BUF_FG_USE_WRITE;
#if defined(MAP_ANON)|| defined(MAP_ANONYMOUS)
		/* prefer to use some anonymous memory to buffer a
		 * page being added to the data */
		b->flags |= DB_BUF_FG_ANON_EXTEND;
		fd = -1;
#ifdef MAP_ANONYMOUS
		/* Linux redefines things and requires either MAP_ANON
		 * or MAP_PRIVATE; */
		flags = MAP_ANONYMOUS| MAP_PRIVATE;
#else
		flags = MAP_ANON | MAP_PRIVATE;
#endif /* MAP_ANONYMOUS */
#else /* have neither MAP_ANON nor MAP_ANONYMOUS */
		flags = MAP_PRIVATE;
#endif
	} else if (db_rdonly) {
		flags = MAP_SHARED;
	} else if (DB_BUF_MODE_B(b) == DB_BUF_MODE_WRITE && !db_minimum_map) {
		/* write() buffers instead of letting the Solaris virtual
		 * memory system do it. Solaris will bog the system down doing
		 * nothing but flushing dirty mmap() pages
		 * We cannot use this hack in two processes simultaneously,
		 * so do not use it in dccd while dbclean is running */
		b->flags |= DB_BUF_FG_USE_WRITE;
		flags = MAP_PRIVATE;
	} else {
		flags = MAP_SHARED;
#ifdef USE_MAP_NOSYNC
		if (DB_BUF_MODE_B(b) == DB_BUF_MODE_MSYNC
		    || DB_BUF_MODE_B(b) == DB_BUF_MODE_TMPFS)
			flags |= MAP_NOSYNC;
#endif
	}

	prot = db_rdonly ? PROT_READ : (PROT_READ | PROT_WRITE);
	for (retry = 1, unloaded = 2; unloaded > 1; ++retry) {
		p = mmap(0, db_pagesize, prot, flags, fd, offset);

		if (p == MAP_FAILED) {
			if (errno == EACCES
			    || errno == EBADF
			    || errno == EINVAL
			    || errno == ENODEV
			    || retry > 20) {
				dcc_pemsg(EX_IOERR, emsg,
					  "try #%d"" mmap(%s"
					  " %#x,%#x,%#x,%d,"OFF_HPAT"): %s",
					  retry,
					  buf2path(b),
					  db_pagesize, prot, flags, fd, offset,
					  ERROR_STR());
				return 0;
			}
			dcc_error_msg("try #%d mmap(%s"
				      " %#x,%#x,%#x,%d,"OFF_HPAT"): %s",
				      retry,
				      buf2path(b),
				      db_pagesize, prot, flags, fd, offset,
				      ERROR_STR());
/* #define MMAP_FAIL_DEBUG 3 */
#ifdef MMAP_FAIL_DEBUG
		} else if (((uint)random() % MMAP_FAIL_DEBUG) == 0) {
			/* pretend mmap() failed randomly */
			dcc_error_msg(" test fail #%d mmap(%s,%#x,"OFF_HPAT")",
				      retry,
				      buf2path(b), db_pagesize, offset);
			if (0 > munmap(p, db_pagesize))
				dcc_error_msg( "test munmap(): %s",
					      ERROR_STR());
#endif
		} else {
			/* It worked.
			 * Say so if it was not the first attempt. */
			if (retry != 1)
				dcc_error_msg("try #%d"
					      " mmap(%s,%#x,"OFF_HPAT") ok",
					      retry,
					      buf2path(b), db_pagesize, offset);
			break;
		}

		/* mmap() fails occassionally on some systems,
		 * so try to release something and try again */
		unloaded = db_unload(0, 1);
	}


	b->buf.v = p;
	b->flush = 0;
	b->flush_urgent = 0;

	if (extend)
		return 1;

	/* madvise() on some systems including FreeBSD uses a lot of CPU cycles,
	 * so it should not be done unless it is likely to do significant good.
	 * Get all of our buffers if there is plenty of memory
	 * and we are not trying to stay out of the way of dbclean. */
	if (DB_BUF_MODE_B(b) != DB_BUF_MODE_TMPFS) {
		if (!db_minimum_map && db_fsize <= db_max_rss) {
			/* The flat file would fit.  Tell the kernel to be
			 * aggressive if the hash table would also fit */
			if (db_fsize + db_hash_fsize <= db_max_rss
			    && 0 > DCC_MADV_WILLNEED(p))
				dcc_error_msg("madvise(WILLNEED %s,%#x): %s",
					      buf2path(b), db_pagesize,
					      ERROR_STR());
		} else {
			if (0 > DCC_MADV_RANDOM(p))
				dcc_error_msg("madvise(RANDOM %s,%#x): %s",
					      buf2path(b), db_pagesize,
					      ERROR_STR());
		}
	}

	return 1;
}



/* get a free buffer for a chunk of either the hash table or database files */
static DB_BUF *
get_free_buf(DCC_EMSG emsg, DB_BUF **bh)
{
	DB_BUF *b;

	/* Look for an unlocked buffer.
	 * We know there is one because we have more buffers than
	 * can be locked simultaneously. */
	b = buf_oldest;
	for (;;) {
		if (!b)
			dcc_logbad(EX_SOFTWARE, "broken DB buffer MRU chain");
		if (!b->lock_cnt)
			break;
		b = b->newer;
	}

	/* Found an unlocked buffer.
	 * Unlink it from its hash chain. */
	if (b->fwd)
		b->fwd->bak = b->bak;
	if (b->bak)
		b->bak->fwd = b->fwd;
	else if (b->hash)
		*b->hash = b->fwd;
	if (b->buf_type != DB_BUF_TYPE_FREE) {
		if (!buf_munmap(emsg, b))
			return 0;
	}

	b->flags = 0;

	/* put it on the new hash chain */
	b->bak = 0;
	b->hash = bh;
	b->fwd = *bh;
	*bh = b;
	if (b->fwd)
		b->fwd->bak = b;

	return b;
}



static DB_BUF *
find_buf(DCC_EMSG emsg, DB_BUF_TYPE buf_type, DB_PG_NUM pg_num)
{
	DB_BUF *b, **bh;

	bh = DB_BUF_HASH(pg_num, buf_type);
	b = *bh;
	for (;;) {
		if (!b) {
			/* we ran off the end of the buffer hash chain,
			 * so get a free buffer */
			b = get_free_buf(emsg, bh);
			if (!b)
				return 0;
			b->buf_type = buf_type;
			b->pg_num = pg_num;
			break;
		}
		if (b->buf_type == buf_type
		    && b->pg_num == pg_num)
			break;		/* found the buffer we need */

		b = b->fwd;
	}

	/* make the buffer newest */
	if (buf_newest != b) {
		/* unlink it */
		b->newer->older = b->older;
		if (b->older)
			b->older->newer = b->newer;
		else
			buf_oldest = b->newer;
		/* insert it at the head of the MRU list */
		b->newer = 0;
		b->older = buf_newest;
		buf_newest->newer = b;
		buf_newest = b;
	}

	return b;
}



static DB_BUF *
find_st_buf(DCC_EMSG emsg, DB_BUF_TYPE buf_type, DB_STATE *st,
	    DB_PG_NUM pg_num, u_char extend)
{
	DB_BUF *b;

	/* release previous buffer unless it is the right one */
	b = st->b;
	if (b) {
		if (b->pg_num == pg_num
		    && b->buf_type == buf_type)
			return b;	/* already have the target buffer */

		st->b = 0;
		st->d.v = 0;
		if (--b->lock_cnt < 0)
			dcc_logbad(EX_SOFTWARE, "bad database buffer lock");
	}

	/* look for the buffer */
	b = find_buf(emsg, buf_type, pg_num);
	if (!b)
		return 0;

	++b->lock_cnt;
	if (b->buf.v) {
		if (extend && !(b->flags & DB_BUF_FG_USE_WRITE))
			dcc_logbad(EX_SOFTWARE, "extending ordinary buffer");

	} else {
		/* map it if it was not already known */
		if (!buf_mmap(emsg, b, pg_num, extend)) {
			b->buf_type = DB_BUF_TYPE_FREE;
			b->pg_num = -1;
			if (--b->lock_cnt != 0)
				dcc_logbad(EX_SOFTWARE,
					   "stolen database buffer lock %d",
					   b->lock_cnt);
			return 0;
		}
		if (buf_type == DB_BUF_TYPE_DB)
			++db_stats.db_mmaps;
		else if (buf_type == DB_BUF_TYPE_HASH)
			++db_stats.hash_mmaps;
	}

	st->b = b;
	st->d.v = 0;
	return b;
}



static u_char
map_hash_ctl(DCC_EMSG emsg, u_char new)
{
	DB_BUF *b;

	b = find_st_buf(emsg, DB_BUF_TYPE_HASH, &db_sts.hash_ctl, 0, new);
	if (!b)
		return 0;
	db_sts.hash_ctl.s.haddr = 0;
	db_sts.hash_ctl.d.v = b->buf.v;
	return 1;
}



/* mmap() a hash table entry */
static u_char
map_hash(DCC_EMSG emsg,
	 DB_HADDR haddr,		/* this entry */
	 DB_STATE *st,			/* point this to the entry */
	 u_char new)
{
	DB_PG_NUM pg_num;
	DB_PG_OFF pg_off;
	DB_BUF *b;

	if (haddr >= db_hash_len || haddr < DB_HADDR_BASE) {
		dcc_pemsg(EX_DATAERR, emsg, "invalid hash address %#x",
			  haddr);
		return 0;
	}

	pg_num = haddr / db_hash_page_len;
	pg_off = haddr % db_hash_page_len;

	b = find_st_buf(emsg, DB_BUF_TYPE_HASH, st, pg_num, new);
	if (!b)
		return 0;
	st->s.haddr = haddr;
	st->d.h = &b->buf.h[pg_off];
	return 1;
}



/* unlink a hash table entry from the free list
 *	uses db_sts.tmp */
static u_char
unlink_free_hash(DCC_EMSG emsg,
		 DB_STATE *hash_st)	/* remove this from the free list */
{
	DB_HADDR fwd, bak;

	if (!db_make_dirty(emsg))
		return 0;

	fwd = DB_HADDR_EX(hash_st->d.h->fwd);
	bak = DB_HADDR_EX(hash_st->d.h->bak);
	if (!HE_IS_FREE(hash_st->d.h)
	    || (DB_HADDR_INVALID(fwd) && fwd != FREE_HADDR_END)
	    || (DB_HADDR_INVALID(bak) && bak != FREE_HADDR_END)
	    || DB_HPTR_EX(hash_st->d.h->rcd) != DB_PTR_NULL) {
		dcc_pemsg(EX_DATAERR, emsg,
			  "bad hash free list entry at %#x", hash_st->s.haddr);
		return 0;
	}

	if (fwd != FREE_HADDR_END) {
		if (!map_hash(emsg, fwd, &db_sts.tmp, 0))
			return 0;
		if (DB_HADDR_EX(db_sts.tmp.d.h->bak) != hash_st->s.haddr) {
			dcc_pemsg(EX_DATAERR, emsg, "free %#x --> bad-free %#x",
				  hash_st->s.haddr, fwd);
			return 0;
		}
		DB_HADDR_CP(db_sts.tmp.d.h->bak, bak);
		SET_FLUSH_HE(&db_sts.tmp);
	} else {
		if (!map_hash_ctl(emsg, 0))
			return 0;
		if (db_sts.hash_ctl.d.vals->s.free_bak != hash_st->s.haddr) {
			dcc_pemsg(EX_DATAERR, emsg, "free %#x --> bad-free %#x",
				  hash_st->s.haddr, fwd);
			return 0;
		}
		db_sts.hash_ctl.d.vals->s.free_bak = bak;
		SET_FLUSH_HCTL(0);
	}

	if (bak != FREE_HADDR_END) {
		if (!map_hash(emsg, bak, &db_sts.tmp, 0))
			return 0;
		if (DB_HADDR_EX(db_sts.tmp.d.h->fwd) != hash_st->s.haddr) {
			dcc_pemsg(EX_DATAERR, emsg, "bad free %#x <-- free %#x",
				  bak, hash_st->s.haddr);
			return 0;
		}
		DB_HADDR_CP(db_sts.tmp.d.h->fwd, fwd);
		SET_FLUSH_HE(&db_sts.tmp);
	} else {
		if (!map_hash_ctl(emsg, 0))
			return 0;
		if (db_sts.hash_ctl.d.vals->s.free_fwd != hash_st->s.haddr) {
			dcc_pemsg(EX_DATAERR, emsg, "free %#x --> bad-free %#x",
				  hash_st->s.haddr, bak);
			return 0;
		}
		db_sts.hash_ctl.d.vals->s.free_fwd = fwd;
		SET_FLUSH_HCTL(0);
	}

	memset(hash_st->d.h, 0, sizeof(HASH_ENTRY));
	SET_FLUSH_HE(hash_st);

	++db_hash_used;
	return 1;
}



/* get a free hash table entry leave db_sts.free pointing to it */
static u_char				/* 0=failed, 1=got it */
get_free_hash(DCC_EMSG emsg)
{
	DB_HADDR probe, pg_start, pg_mod, pg_free;
	DB_HOFF hoff;
	u_int r;

	if (db_hash_len <= db_hash_used) {
		dcc_pemsg(EX_OSFILE, emsg, "no free hash table entry;"
			  " %d of %d used", db_hash_used, db_hash_len);
		return 0;
	}

	/* Look near the next entry in the hash chain if possible.
	 * Otherwise look near the entry pointed to by db_sts.hash. */
	probe = DB_HADDR_EX(db_sts.hash.d.h->fwd);
	if (probe == DB_HADDR_NULL)
		probe = db_sts.hash.s.haddr;

	/* find the local free list at the end of the page */
	pg_free = probe - (probe % db_hash_page_len);
	pg_free += db_hash_page_len-1;
	if (pg_free >= db_hash_len)
		pg_free = db_hash_len-1;

	/* Look first in the current system page.
	 * So find the first entry on the system page.
	 * If the target entry straddles a page boundary, find the first entry
	 * on the first page and the last entry on the next page.
	 * We also need 1 more than the number of entries that fit within
	 * the one or two pages. */
	hoff = probe*sizeof(HASH_ENTRY);
	hoff -= hoff % sys_pagesize;
	pg_start = (hoff + sizeof(HASH_ENTRY)-1) / sizeof(HASH_ENTRY);
	probe -= pg_start;
	if (probe <= hash_sys_pagesize) {
		pg_mod = hash_sys_pagesize+1;
	} else {
		pg_mod = hash_sys_pagesize2+1;
	}
	if (pg_mod > pg_free - pg_start)
		pg_mod = pg_free - pg_start;
	for (r = 1; r <= 3*3*3*3*3*3*3*3; r *= 3) {
		DB_HADDR trial;

		probe = (probe + r) % pg_mod;
		trial = probe + pg_start;
		if (trial < DB_HADDR_BASE)
			trial = DB_HADDR_BASE;
		if (!map_hash(emsg, trial, &db_sts.free, 0))
			return 0;
		if (HE_IS_FREE(db_sts.free.d.h))
			return unlink_free_hash(emsg, &db_sts.free);
	}

	/* looking in the current system page failed,
	 * so check the local free list at the end of the page */
	if (!map_hash(emsg, pg_free, &db_sts.free, 0))
		return 0;
	if (HE_IS_FREE(db_sts.free.d.h)) {
		/* the ad hoc free list is not empty,
		 * so try to use the previous entry */
		probe = DB_HADDR_EX(db_sts.free.d.h->bak);
		if (probe != FREE_HADDR_END) {
			if (!map_hash(emsg, probe, &db_sts.free, 0))
				return 0;
		}
		return unlink_free_hash(emsg, &db_sts.free);
	}


	/* Give up and search from the start of the free list.  This happens
	 * only when the current and all preceding pages are full. */
	if (!map_hash_ctl(emsg, 0))
		return 0;
	probe = db_sts.hash_ctl.d.vals->s.free_fwd;
	if (DB_HADDR_INVALID(probe)) {
		dcc_pemsg(EX_DATAERR, emsg,
			  "broken hash free list head of %#x", probe);
		return 0;
	}
	if (!map_hash(emsg, probe, &db_sts.free, 0))
		return 0;
	return unlink_free_hash(emsg, &db_sts.free);
}



/* mmap() a database entry
 *	We assume that no database entry spans buffers,
 *	and that there are enough buffers to accomodate all possible
 *	concurrent requests. */
static u_char
map_db(DCC_EMSG emsg,
       DB_PTR rptr,			/* address of the record */
       u_int tgt_len,			/* its length */
       DB_STATE *st,			/* point this to the record */
       u_char extend)
{
	DB_PG_NUM pg_num;
	DB_PG_OFF pg_off;
	DB_BUF *b;

	if (rptr+tgt_len > db_fsize) {
		db_failure(__LINE__,__FILE__, EX_DATAERR, emsg,
			   "invalid database address "L_HxPAT" or length %d"
			   " past db_fsize "OFF_HPAT" in %s",
			   rptr, tgt_len, db_fsize, db_nm);
		return 0;
	}

	/* Try to optimize this to avoid udivdi3() and umoddi3(),
	 * because they are a major time sink here on 32-bit systems */
	pg_num = DB_PTR2PG_NUM(rptr, db_pagesize);
#ifdef HAVE_64BIT_LONG
	pg_off = rptr % db_pagesize;
#else
	pg_off = rptr - pg_num*(DB_PTR)db_pagesize;
#endif

	/* do not go past the end of a buffer */
	if (tgt_len+pg_off > db_pagesize) {
		db_failure(__LINE__,__FILE__, EX_DATAERR, emsg,
			   "invalid database address "L_HxPAT
			   " or length %#x in %s",
			   rptr, tgt_len, db_nm);
		return 0;
	}

	b = find_st_buf(emsg, DB_BUF_TYPE_DB, st, pg_num, extend);
	if (!b)
		return 0;
	st->s.rptr = rptr;
	st->d.r = (DB_RCD *)&b->buf.c[pg_off];
	return 1;
}



u_char					/* 0=failed, 1=got it */
db_map_rcd(DCC_EMSG emsg,
	   DB_STATE *rcd_st,		/* point this to the record */
	   DB_PTR rptr,			/* that is here */
	   int *rcd_lenp)		/* put its length here */
{
	u_int rcd_len;

	if (DB_PTR_IS_BAD(rptr)) {
		dcc_pemsg(EX_DATAERR, emsg,
			  "getting bogus record at "L_HxPAT", in %s",
			  rptr, db_nm);
		return 0;
	}

	if (!map_db(emsg, rptr, DB_RCD_HDR_LEN, rcd_st, 0))
		return 0;
	rcd_len = DB_RCD_LEN(rcd_st->d.r);

	if (&rcd_st->d.c[rcd_len] > &rcd_st->b->buf.c[db_pagesize]) {
		dcc_pemsg(EX_DATAERR, emsg,
			  "invalid checksum count %d at "L_HxPAT" in %s",
			  DB_NUM_CKS(rcd_st->d.r), rptr, db_nm);
		return 0;
	}

	if (rcd_lenp)
		*rcd_lenp = rcd_len;
	return 1;
}



/* write the new sizes of the files into the files */
static u_char
db_set_sizes(DCC_EMSG emsg)
{
	u_char result = 1;

	if (db_hash_fd != -1
	    && (db_csize_stored_hash != db_csize
		|| db_hash_used_stored_hash != db_hash_used)) {
		if (!map_hash_ctl(emsg, 0)) {
			result = 0;
		} else {
			db_sts.hash_ctl.d.vals->s.db_csize = db_csize;
			db_csize_stored_hash = db_csize;

			db_sts.hash_ctl.d.vals->s.used = db_hash_used;
			db_hash_used_stored_hash = db_hash_used;

			SET_FLUSH_HCTL(0);
		}
	}

	if (db_fd != -1
	    && (db_parms_stored.db_csize != db_csize
		|| db_parms_stored.hash_used != db_hash_used)) {
		if (!map_db(emsg, 0, sizeof(DB_HDR), &db_sts.db_parms, 0)) {
			result = 0;
		} else {
			db_sts.db_parms.d.parms->db_csize = db_csize;
			db_parms_stored.db_csize = db_csize;
			db_parms.db_csize = db_csize;

			db_sts.db_parms.d.parms->hash_used = db_hash_used;
			db_parms_stored.hash_used = db_hash_used;
			db_parms.hash_used = db_hash_used;

			db_sts.db_parms.d.parms->last_rate_sec = db_time.tv_sec;
			db_parms_stored.last_rate_sec = db_time.tv_sec;
			db_parms.last_rate_sec = db_time.tv_sec;

			db_set_flush(&db_sts.db_parms, 1, sizeof(DB_PARMS));
		}
	}

	return result;
}



/* write the database parameters into the magic number headers of the files */
u_char
db_flush_parms(DCC_EMSG emsg)
{
	if (!db_set_sizes(emsg))
		return 0;

	if (db_fd == -1)
		return 1;

	if (memcmp(&db_parms, &db_parms_stored, sizeof(db_parms))) {
		if (!map_db(emsg, 0, sizeof(DB_HDR), &db_sts.db_parms, 0))
			return 0;

		db_parms.pagesize = db_pagesize;

		*db_sts.db_parms.d.parms = db_parms;
		db_parms_stored = db_parms;

		db_set_flush(&db_sts.db_parms, 1, sizeof(DB_PARMS));
	}

	return 1;
}



/* find a checksum type known to be in a record */
DB_RCD_CK *				/* 0=it's not there */
db_map_rcd_ck(DCC_EMSG emsg,
	      DB_STATE *rcd_st,		/* point this to the record */
	      DB_PTR rptr,		/* that is here */
	      DCC_CK_TYPES type)	/* find this type of checksum */
{
	DB_RCD_CK *rcd_ck;
	int i;

	if (!db_map_rcd(emsg, rcd_st, rptr, 0))
		return 0;

	rcd_ck = rcd_st->d.r->cks;
	i = DB_NUM_CKS(rcd_st->d.r);
	if (i >= DCC_NUM_CKS) {
		dcc_pemsg(EX_DATAERR, emsg,
			  "impossible %d checksums in "L_HxPAT" in %s",
			  i, rptr, db_nm);
		return 0;
	}

	for (; i != 0; --i, ++rcd_ck) {
		if (DB_CK_TYPE(rcd_ck) == type)
			return rcd_ck;
	}

	dcc_pemsg(EX_DATAERR, emsg,
		  "missing \"%s\" checksum in "L_HxPAT" in %s",
		  DB_TYPE2STR(type), rptr, db_nm);
	return 0;
}



/* Get a modulus for the database hash function. */
DB_HADDR
get_db_hash_divisor(u_int32_t len)
{
	return hash_divisor(len - DB_HADDR_BASE, 1);
}



DB_HADDR
db_hash(DCC_CK_TYPES type, const DCC_SUM *sum)
{
	u_int64_t accum, wrap;
	const u_int32_t *wp;
	union {
	    DCC_SUM	sum;
	    u_int32_t	words[4];
	} buf;
	u_int  align;
	DB_HADDR haddr;

#ifdef HAVE_64BIT_PTR
	align = (u_int64_t)sum & 3;
#else
	align = (u_int32_t)sum & 3;
#endif
	if (align == 0) {
		/* We almost always take this branch because database
		 * records contain 12+N*24 bytes.  That also implies that
		 * we should not hope for better than 4 byte alignment. */
		wp = (u_int32_t *)sum;
	} else {
		buf.sum = *sum;
		wp = buf.words;
	}

	/* MD5 checksums are uniformly distributed, and so DCC_SUMs are
	 * directly useful for hashing except when they are server-IDs */
	accum = *wp++;
	accum += *wp++;
	wrap = accum >>32;
	accum <<= 32;
	accum += wrap + type;
	accum += *wp++;
	accum += *wp;

	haddr = accum % db_hash_divisor;
	haddr += DB_HADDR_BASE;

	/* do not hash into the last slot of a page, because it is the
	 * local, within the hash page free list */
	if (haddr % db_hash_page_len == db_hash_page_len-1) {
		++haddr;
		if (haddr >= db_hash_len)
			haddr = DB_HADDR_BASE;
	}
	return haddr;
}



/* look for a checksum in the hash table
 *	return with an excuse, the home slot, or the last entry on
 *	the collision chain */
DB_FOUND
db_lookup(DCC_EMSG emsg,
	  DCC_CK_TYPES type,
	  const DCC_SUM *sum,
	  DB_STATE *hash_st,		/* hash block for record or related */
	  DB_STATE *rcd_st,		/* put the record or garbage here */
	  DB_RCD_CK **prcd_ck)		/* point to cksum if found */
{
	DB_HADDR haddr, haddr_fwd, haddr_bak;
	DB_PTR db_ptr;
	DB_RCD_CK *found_ck;
	DB_HADDR failsafe;

	haddr = db_hash(type, sum);

	if (prcd_ck)
	    *prcd_ck = 0;

	if (!map_hash(emsg, haddr, hash_st, 0))
		return DB_FOUND_SYSERR;

	if (HE_IS_FREE(hash_st->d.h))
		return DB_FOUND_EMPTY;

	if (!DB_HADDR_C_NULL(hash_st->d.h->bak))
		return DB_FOUND_INTRUDER;

	/* We know that the current hash table entry is in its home slot.
	 * It might be for the key or checksum we are looking for
	 * or it might be for some other checksum with the same hash value. */
	for (failsafe = 0; failsafe <= db_hash_len; ++failsafe) {
		if (HE_CMP(hash_st->d.h, type, sum)) {
			/* This hash table entry could be for our target
			 * checksum.  Read the corresponding record so we
			 * decide whether we have a hash collision or we
			 * have found a record containing our target checksum.
			 *
			 * find right type of checksum in the record */
			db_ptr = DB_HPTR_EX(hash_st->d.h->rcd);
			found_ck = db_map_rcd_ck(emsg, rcd_st, db_ptr, type);
			if (!found_ck)
				return DB_FOUND_SYSERR;
			if (!memcmp(sum, &found_ck->sum, sizeof(*sum))) {
				if (prcd_ck)
					*prcd_ck = found_ck;
				return DB_FOUND_IT;
			}
		}

		/* This DB record was a hash collision, or for a checksum
		 * other than our target.
		 * Fail if this is the end of the hash chain */
		haddr_fwd = DB_HADDR_EX(hash_st->d.h->fwd);
		if (haddr_fwd == DB_HADDR_NULL)
			return DB_FOUND_CHAIN;

		if (DB_HADDR_INVALID(haddr_fwd)) {
			dcc_pemsg(EX_DATAERR, emsg,
				  "broken hash chain fwd-link"
				  " #%d %#x at %#x in %s",
				  failsafe, haddr_fwd, haddr, db_hash_nm);
			return DB_FOUND_SYSERR;
		}

		if (!map_hash(emsg, haddr_fwd, hash_st, 0))
			return DB_FOUND_SYSERR;

		haddr_bak = DB_HADDR_EX(hash_st->d.h->bak);
		if (haddr_bak != haddr) {
			dcc_pemsg(EX_DATAERR, emsg,
				  "broken hash chain links #%d,"
				  " %#x-->%#x but %#x<--%#x in %s",
				  failsafe,
				  haddr, haddr_fwd,
				  haddr_bak, haddr_fwd,
				  db_hash_nm);
			return DB_FOUND_SYSERR;
		}
		haddr = haddr_fwd;
	}
	dcc_pemsg(EX_DATAERR, emsg, "infinite hash chain at %#x in %s",
		  haddr, db_hash_nm);
	return DB_FOUND_SYSERR;
}



/* combine checksums */
DCC_TGTS
db_sum_ck(DCC_TGTS prev,		/* previous sum */
	  DCC_TGTS rcd_tgts,		/* from the record */
	  DCC_CK_TYPES type DCC_UNUSED)
{
	DCC_TGTS res;

	/* This arithmetic must be commutative (after handling deleted
	 * values), because inter-server flooding causes records to appear in
	 * the database out of temporal order.
	 *
	 * DCC_TGTS_TOO_MANY can be thought of as a count of plus infinity.
	 * DCC_TGTS_OK is like minus infinity.
	 * DCC_TGTS_OK2 like half of minus infinity
	 * DCC_TGTS_TOO_MANY (plus infinity) added to DCC_TGTS_OK (minus
	 *	infinity) or DCC_TGTS_OK2 yields DCC_TGTS_OK or DCC_TGTS_OK2.
	 *
	 * Reputations never reach infinity.
	 *
	 * Claims of not-spam from all clients are discarded as they arrive
	 * and before here. They can only come from the local whitelist
	 */
#define SUM_OK_DEL(p,r) {						    \
		if (rcd_tgts == DCC_TGTS_OK || prev == DCC_TGTS_OK)	    \
			return DCC_TGTS_OK;				    \
		if (rcd_tgts == DCC_TGTS_OK2 || prev == DCC_TGTS_OK2)	    \
			return DCC_TGTS_OK2;				    \
		if (rcd_tgts == DCC_TGTS_DEL)				    \
			return prev;					    \
	}

	res = prev+rcd_tgts;
	if (res <= DCC_TGTS_TOO_MANY)
		return res;

	SUM_OK_DEL(prev, rcd_tgts);
	return DCC_TGTS_TOO_MANY;
#undef SUM_OK_DEL
}



/* delete all reports that contain the given checksum */
static u_char				/* 1=done, 0=broken database */
del_ck(DCC_EMSG emsg,
       DCC_TGTS *res,			/* residual targets after deletion */
       const DB_RCD *new,		/* delete reports older than this one */
       DCC_CK_TYPES type,		/* delete this type of checksum */
       DB_RCD_CK *prev_ck,		/* starting with this one */
       DB_STATE *prev_st)		/* use this scratch state block */
{
	DB_PTR prev, loop_prev;

	*res = 0;
	loop_prev = DB_PTR_MAX+1;
	for (;;) {
		/* delete reports that are older than the delete request */
		if (ts_newer_ts(&new->ts, &prev_st->d.r->ts)
		    && DB_RCD_ID(prev_st->d.r) != DCC_ID_WHITE) {
			DB_TGTS_RCD_SET(prev_st->d.r, 0);
			DB_TGTS_CK_SET(prev_ck, 0);
			SET_FLUSH_RCD(prev_st, 1);

		} else {
			/* sum reports that are not deleted */
			*res = db_sum_ck(*res, DB_TGTS_RCD(prev_st->d.r), type);
		}

		prev = DB_PTR_EX(prev_ck->prev);
		if (prev == DB_PTR_NULL)
			return 1;
		if (prev >= loop_prev) {
			db_failure(__LINE__,__FILE__, EX_DATAERR, emsg,
				   "looping hash chain of "L_HxPAT" at "L_HxPAT,
				   prev, loop_prev);
			return 0;
		}
		loop_prev = prev;

		prev_ck = db_map_rcd_ck(emsg, prev_st, prev, type);
		if (!prev_ck)
			return 0;
	}
}



/* Mark reports made obsolete by a new spam report
 *	A new report of spam makes sufficiently old spam reports obsolete.
 *
 *	Sufficiently recent non-obsolete reports make a new report not worth
 *	keeping or flooding.
 *	"Sufficiently recent" should be defined so that this server and
 *	its downstream flooding peers always have reports of the checksums
 *	in the report.  So we want to keep (not make obsolete) at least one
 *	report per expiration duration.  We cannot know the expiration durations
 *	of our peers, but we known DB_EXPIRE_SPAMSECS_DEF_MIN which influences
 *	DCC_OLD_SPAM_SECS.
 *
 *	However, if another checksum in the new report was kept, then
 *	prefer marking old checksums obsolete.
 *
 *	db_sts.rcd points to the new record
 *	db_sts.rcd2 points the the previous record and is changed
 */
static u_char				/* 1=done, 0=broken database */
ck_obs_spam(DCC_EMSG emsg,
	    const DB_RCD *new,
	    DCC_TGTS new_tgts,
	    DB_RCD_CK *new_ck,
	    DCC_CK_TYPES type,		/* check this type of checksum */
	    DB_RCD_CK *prev_ck,		/* starting with this one */
	    DCC_TGTS prev_ck_tgts)
{
	DB_PTR prev, loop_prev;

	/* quit if the new report is already junk */
	if (DB_CK_JUNK(new_ck))
		return 1;

	loop_prev = DB_PTR_MAX+1;
	for (;;) {
		/* preceding whitelisted entries make new entries junk */
		if (DB_RCD_ID(db_sts.rcd2.d.r) == DCC_ID_WHITE) {
			new_ck->type_fgs |= DB_CK_FG_JUNK;
			SET_FLUSH_RCD(&db_sts.rcd, 0);
			return 1;
		}

		if (DB_TGTS_RCD(db_sts.rcd2.d.r) == 0) {
			/* skip deleted predecessors unless it was this
			 * checksum that was deleted */
			if (prev_ck_tgts == 0)
				return 1;

		} else if (prev_ck_tgts != DCC_TGTS_TOO_MANY) {
			/* This predecessor is obsolete because it
			 * was before the checksum became spam.
			 * We are finished if it has already been marked. */
			if (DB_CK_OSPAM(prev_ck))
				return 1;

			/* Mark it and its non-spam predecessors. */
			prev_ck->type_fgs |= (DB_CK_FG_OSPAM | DB_CK_FG_JUNK);
			SET_FLUSH_RCD(&db_sts.rcd2, 0);

		} else if ((ts2secs(&db_sts.rcd2.d.r->ts) / DCC_OLD_SPAM_SECS)
			   != (ts2secs(&new->ts) / DCC_OLD_SPAM_SECS)) {
			/* This predecessor reporting spam is much older
			 * than the new report.
			 * If the new report is not of spam, it will eventually
			 * be compressed with a preceding spam report,
			 * but not before being flooded and refreshing
			 * other servers' records of this checksum.
			 * We're finished, because all older preceding reports
			 * were marked obsolete when this older predecessor
			 * reporting spam was linked.
			 * The predecessor is not needed if the new record
			 * is for spam */
			if (new_tgts == DCC_TGTS_TOO_MANY) {
				prev_ck->type_fgs |= (DB_CK_FG_OSPAM |
						      DB_CK_FG_JUNK);
				SET_FLUSH_RCD(&db_sts.rcd2, 0);
			}
			return 1;

		} else {
			/* This predecessor reporting spam is about as new as
			 * the new record, so the new record is unneeded and
			 * would bloat other servers' databases. */
			new_ck->type_fgs |= (DB_CK_FG_OSPAM | DB_CK_FG_JUNK);
			SET_FLUSH_RCD(&db_sts.rcd, 0);
			return 1;
		}

		prev = DB_PTR_EX(prev_ck->prev);
		if (prev == DB_PTR_NULL)
			return 1;
		if (prev >= loop_prev) {
			db_failure(__LINE__,__FILE__, EX_DATAERR, emsg,
				   "looping hash chain of "L_HxPAT" at "L_HxPAT,
				   prev, loop_prev);
			return 0;
		}
		loop_prev = prev;

		prev_ck = db_map_rcd_ck(emsg, &db_sts.rcd2, prev, type);
		if (!prev_ck)
			return 0;
		prev_ck_tgts = DB_TGTS_CK(prev_ck);
	}
}



/* mark extra server-ID state declarations obsolete
 *	db_sts.rcd points to the new record
 *	db_sts.rcd2 points the the previous record and is changed */
static u_char				/* 1=done, 0=broken database */
srvr_id_ck(DCC_EMSG emsg,
	   const DB_RCD *new,
	   DB_RCD_CK *new_ck,
	   DB_RCD_CK *prev_ck)		/* starting with this one */
{
	DB_PTR prev, loop_prev;

	/* quit if already obsolete */
	if (DB_CK_JUNK(new_ck))
		return 1;

	loop_prev = DB_PTR_MAX+1;
	for (;;) {
		/* Zap the new server-ID declaration and stop
		 * if the new declaration is older than the predecessor.
		 * Keep conflicting ID assertions. */
		if (DCC_ID_SRVR_TYPE(DB_RCD_ID(new))
		    || DB_RCD_ID(new) == DB_RCD_ID(db_sts.rcd2.d.r)) {
			/* stop at a deletion */
			if (DB_TGTS_RCD(db_sts.rcd2.d.r) == 0)
				return 1;

			if (ts_newer_ts(&db_sts.rcd2.d.r->ts, &new->ts)) {
				new_ck->type_fgs |= DB_CK_FG_JUNK;
				SET_FLUSH_RCD(&db_sts.rcd, 0);
				return 1;
			}

			/* continue zapping preceding declarations */
			prev_ck->type_fgs |= DB_CK_FG_JUNK;
			SET_FLUSH_RCD(&db_sts.rcd2, 0);
		}

		prev = DB_PTR_EX(prev_ck->prev);
		if (prev == DB_PTR_NULL)
			return 1;
		if (prev >= loop_prev) {
			db_failure(__LINE__,__FILE__, EX_DATAERR, emsg,
				   "looping hash chain of "L_HxPAT" at "L_HxPAT,
				   prev, loop_prev);
			return 0;
		}
		loop_prev = prev;

		prev_ck = db_map_rcd_ck(emsg, &db_sts.rcd2,
					prev, DCC_CK_SRVR_ID);
		if (!prev_ck)
			return 0;
	}
}



/* Install pointers in the hash table for a record and fix the accumulated
 *	counts in the record pointed to by db_sts.rcd
 *	Use db_sts.rcd, db_sts.hash, db_sts.rcd2, db_sts.free, db_sts.tmp
 *	The caller must deal with db_make_dirty() */
u_char					/* 0=failed, 1=done */
db_link_rcd(DCC_EMSG emsg)
{
	DCC_TGTS res;
	DB_RCD *rcd;
	DB_RCD_CK *prev_ck;
	DB_RCD_CK *rcd_ck;
	DCC_CK_TYPES rcd_type;
	DCC_TGTS rcd_tgts, prev_ck_tgts;
	int ck_num;
	DB_HADDR haddr;

	rcd = db_sts.rcd.d.r;
	rcd_tgts = DB_TGTS_RCD_RAW(rcd);
	rcd_ck = rcd->cks;
	ck_num = DB_NUM_CKS(rcd);
	if (ck_num > DIM(rcd->cks)) {
		dcc_pemsg(EX_OSFILE, emsg,
			  "bogus checksum count %#x at "L_HxPAT" in %s",
			  rcd->fgs_num_cks, db_sts.rcd.s.rptr, db_nm);
		return 0;
	}
	for (; ck_num > 0; --ck_num, ++rcd_ck) {
		rcd_type = DB_CK_TYPE(rcd_ck);
		if (!DCC_CK_OK_DB(grey_on, rcd_type)) {
			dcc_pemsg(EX_OSFILE, emsg,
				  "invalid checksum %s at "L_HxPAT" in %s",
				  DB_TYPE2STR(rcd_type),
				  db_sts.rcd.s.rptr, db_nm);
			return 0;
		}

		rcd_ck->prev = DB_PTR_CP(DB_PTR_NULL);

		/* Do not link paths or whitelist file and line numbers */
		if (rcd_type == DCC_CK_FLOD_PATH) {
			DB_TGTS_CK_SET(rcd_ck, 0);
			continue;
		}

		/* Do not link or total some checksums unless they are
		 * whitelist entries.  If they are whitelist entries, they
		 * will eventually get set to DCC_TGTS_OK or DCC_TGTS_OK2.
		 * Blacklist entries are noticed later by server-ID
		 * or do not matter DCC_TGTS_TOO_MANY. */
		if (DB_TEST_NOKEEP(db_parms.nokeep_cks, rcd_type)
		    && DB_RCD_ID(rcd) != DCC_ID_WHITE) {
			DB_TGTS_CK_SET(rcd_ck, 1);
			continue;
		}

		res = (rcd_tgts == DCC_TGTS_DEL) ? 0 : rcd_tgts;

		switch (db_lookup(emsg, rcd_type, &rcd_ck->sum,
				  &db_sts.hash, &db_sts.rcd2, &prev_ck)) {
		case DB_FOUND_SYSERR:
			return 0;

		case DB_FOUND_IT:
			/* We found the checksum
			 * Update the hash table to point to the new record */
			DB_HPTR_CP(db_sts.hash.d.h->rcd, db_sts.rcd.s.rptr);
			SET_FLUSH_HE(&db_sts.hash);
			/* link new record to existing record */
			rcd_ck->prev = DB_PTR_CP(db_sts.rcd2.s.rptr);

			/* delete predecessors to a delete request
			 * and compute the remaining sum */
			if (rcd_tgts == DCC_TGTS_DEL) {
				if (!del_ck(emsg, &res, rcd, rcd_type,
					    prev_ck, &db_sts.rcd2))
					return 0;
				/* delete requests are obsolete if the
				 * checksum is whitelisted */
				if (res == DCC_TGTS_OK
				    || res == DCC_TGTS_OK2)
					rcd_ck->type_fgs |= DB_CK_FG_JUNK;
				break;
			}

			/* Simple checksum with a predecessor
			 * This does not do the substantial extra work
			 * to notice all delete requests that arrived early.
			 * That problem is handled by the incoming flood
			 * duplicate report detection mechanism.
			 * We must detect predecessors that were deleted because
			 * they are partial duplicates of the new record. */
			prev_ck_tgts = DB_TGTS_CK(prev_ck);
			if (DB_RCD_SUMRY(rcd))
				res = prev_ck_tgts;
			else
				res = db_sum_ck(prev_ck_tgts, res, rcd_type);
			if ((res == DCC_TGTS_OK || res == DCC_TGTS_OK2
			     || (DB_RCD_ID(db_sts.rcd2.d.r) == DCC_ID_WHITE))
			    && DB_RCD_ID(rcd) != DCC_ID_WHITE){
				/* obsolete whitelisted checksums */
				rcd_ck->type_fgs |= DB_CK_FG_JUNK;
				break;
			}
			if (res == DCC_TGTS_TOO_MANY) {
				/* mark unneeded reports of spam */
				if (!ck_obs_spam(emsg, rcd, rcd_tgts,
						 rcd_ck, rcd_type,
						 prev_ck, prev_ck_tgts))
					return 0;   /* (broken database) */
			} else if (rcd_type == DCC_CK_SRVR_ID) {
				/* mark obsolete server-ID assertions */
				if (!srvr_id_ck(emsg, rcd, rcd_ck, prev_ck))
					return 0;   /* (broken database) */
			}
			break;

		case DB_FOUND_EMPTY:
			/* We found an empty hash table slot.
			 * Update the slot to point to our new record
			 * after removing it from the free list,
			 * which marks it dirty. */
			if (!unlink_free_hash(emsg, &db_sts.hash))
				return 0;
			DB_HPTR_CP(db_sts.hash.d.h->rcd, db_sts.rcd.s.rptr);
			HE_MERGE(db_sts.hash.d.h,rcd_type, &rcd_ck->sum);
			break;

		case DB_FOUND_CHAIN:
			/* We found a hash collision, a chain of 1 or more
			 * records with the same hash value.
			 * Get a free slot, link it to the end of the
			 * existing chain, and point it to the new record.
			 * The buffer containing the free slot is marked
			 * dirty when it is removed from the free list. */
			if (!get_free_hash(emsg))
				return 0;
			DB_HADDR_CP(db_sts.free.d.h->bak, db_sts.hash.s.haddr);
			DB_HADDR_CP(db_sts.hash.d.h->fwd, db_sts.free.s.haddr);
			DB_HPTR_CP(db_sts.free.d.h->rcd, db_sts.rcd.s.rptr);
			HE_MERGE(db_sts.free.d.h,rcd_type, &rcd_ck->sum);
			SET_FLUSH_HE(&db_sts.hash);
			break;

		case DB_FOUND_INTRUDER:
			/* The home hash slot for our key contains an
			 * intruder.  Move it to a new free slot. */
			if (!get_free_hash(emsg))
				return 0;
			*db_sts.free.d.h = *db_sts.hash.d.h;
			/* re-link the neighbors of the intruder */
			haddr = DB_HADDR_EX(db_sts.free.d.h->bak);
			if (haddr == DB_HADDR_NULL) {
				dcc_pemsg(EX_DATAERR, emsg,
					  "bad hash chain reverse link at %#x"
					  " in %s",
					  haddr, db_hash_nm);
				return 0;
			}
			if (!map_hash(emsg, haddr, &db_sts.tmp, 0))
				return 0;
			DB_HADDR_CP(db_sts.tmp.d.h->fwd, db_sts.free.s.haddr);
			SET_FLUSH_HE(&db_sts.tmp);
			haddr = DB_HADDR_EX(db_sts.hash.d.h->fwd);
			if (haddr != DB_HADDR_NULL) {
				if (!map_hash(emsg, haddr, &db_sts.tmp, 0))
					return 0;
				DB_HADDR_CP(db_sts.tmp.d.h->bak,
					    db_sts.free.s.haddr);
				SET_FLUSH_HE(&db_sts.tmp);
			}
			/* install the new entry in its home slot */
			DB_HADDR_CP(db_sts.hash.d.h->fwd, DB_HADDR_NULL);
			DB_HADDR_CP(db_sts.hash.d.h->bak, DB_HADDR_NULL);
			DB_HPTR_CP(db_sts.hash.d.h->rcd, db_sts.rcd.s.rptr);
			HE_MERGE(db_sts.hash.d.h,rcd_type, &rcd_ck->sum);
			SET_FLUSH_HE(&db_sts.hash);
			break;
		}

		/* Fix the checksum's total in the record */
		DB_TGTS_CK_SET(rcd_ck, res);
		SET_FLUSH_RCD(&db_sts.rcd, 0);
	}

	return db_set_sizes(emsg);
}



/* Add a record to the database and the hash table
 *	The record must be known to be valid
 *	Use db_sts.rcd, db_sts.hash, db_sts.rcd2, db_sts.free, db_sts.tmp
 *	On exit db_sts.rcd points to the new record in the database */
DB_PTR					/* 0=failed */
db_add_rcd(DCC_EMSG emsg, const DB_RCD *new_rcd)
{
	u_int new_rcd_len, pad_len;
	DB_PTR new_db_csize, rcd_pos, new_page_num;
	DB_BUF *b;

	if (!db_make_dirty(emsg))
		return 0;

	new_rcd_len = (sizeof(*new_rcd)
		       - sizeof(new_rcd->cks)
		       + (DB_NUM_CKS(new_rcd) * sizeof(new_rcd->cks[0])));

	rcd_pos = db_csize;
	new_db_csize = rcd_pos+new_rcd_len;

	new_page_num = DB_PTR2PG_NUM(new_db_csize, db_pagesize);
	if (new_page_num == DB_PTR2PG_NUM(db_csize, db_pagesize)) {
		if (!map_db(emsg, rcd_pos, new_rcd_len, &db_sts.rcd, 0))
			return 0;

	} else {
		/* fill with zeros to get past a page boundary. */
		pad_len = new_page_num*db_pagesize - db_csize;
		pad_len = (((pad_len + DB_RCD_HDR_LEN-1) / DB_RCD_HDR_LEN)
			   * DB_RCD_HDR_LEN);
		if (pad_len != 0) {
			if (!map_db(emsg, db_csize, pad_len, &db_sts.rcd, 0))
				return 0;
			memset(db_sts.rcd.d.r, 0, pad_len);
			db_set_flush(&db_sts.rcd, 1, pad_len);
			db_csize += pad_len;

			rcd_pos = db_csize;
			new_db_csize = rcd_pos+new_rcd_len;
		}

		/* extend the file by writing a full page to it with write(),
		 * because extending by mmap() often does not work */
		db_fsize = db_csize+db_pagesize;
		if (!map_db(emsg, rcd_pos, db_pagesize, &db_sts.rcd, 1))
			return 0;
		b = db_sts.rcd.b;
		b->flush = (DB_BUF_FM)-1;

		/* push new page to disk if dblist or dbclean is running */
		if (db_minimum_map) {
			rel_db_state(&db_sts.rcd);
			if (!buf_munmap(emsg, b))
				return 0;
			if (!map_db(emsg, rcd_pos, new_rcd_len, &db_sts.rcd, 0))
				return 0;
		}
	}

	/* install the record */
	memcpy(db_sts.rcd.d.r, new_rcd, new_rcd_len);
	/* Mark its buffer to be sent to the disk to keep the database
	 * as good as possible even if we crash.  We don't need to worry
	 * about later changes to the hash links because dbclean will
	 * rebuild them if we crash */
	db_set_flush(&db_sts.rcd, 1, new_rcd_len);
	db_csize = new_db_csize;

	/* install pointers in the hash table
	 * and update the total counts in the record */
	if (!db_link_rcd(emsg))
		return 0;

	++db_stats.adds;
	return rcd_pos;
}
