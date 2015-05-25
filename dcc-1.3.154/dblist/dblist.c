/* Distributed Checksum Clearinghouse
 *
 * database lister
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
 * Rhyolite Software DCC 1.3.154-1.170 $Revision$
 */

#include "srvr_defs.h"
#include "dcc_xhdr.h"
#include "dcc_ck.h"
#include <signal.h>
#if HAVE_BOOTTIME
#include <sys/sysctl.h>
#endif

static DCC_EMSG dcc_emsg;

static int verbose;
#define VERBOSE_HASH 3
static u_char no_hash;
static u_char no_data;
static u_char matching;

static DCC_CLNT_CTXT *ctxt;
static DCC_OP_RESP aop_resp;
static DCC_SRVR_NM srvr;
static const ID_TBL *srvr_clnt_tbl;

static struct {
    DCC_CK_TYPES type;
    DCC_SUM	sum;
    u_char	type_only;
} search_cksums[16];
static int num_search_cksums;

static struct {
    DCC_TS	lo;
    DCC_TS	hi;
} search_ts[16];
static int num_search_ts;

DCC_SRVR_ID search_ids[16];
static int num_search_ids;

static DB_PTR page_offset;
static DB_PTR dbaddr;
static int max_pathlen;

static DB_HOFF hash_fsize;
static char dcc_db_nm[] = DB_DCC_NAME;
static char grey_db_nm[] = DB_GREY_NAME;
static	DCC_PATH hash_nm;
static char *def_argv[2];
static const char *homedir;

static const DB_VERSION_BUF version_buf = DB_VERSION_STR;
static const u_char hash_magic[sizeof(((HASH_CTL*)0)->s.magic)
			       ] = HASH_MAGIC_STR;

static void rel_db(void);
static void sigterm(int);
static int save_cksum(DCC_EMSG, WF *, DCC_CK_TYPES, DCC_SUM *, DCC_TGTS);
static void list_cleaned(const DB_PARMS *);
static void list_flod(const DB_PARMS *);
static int fd_hash = -1;
static int fd_db = -1;
static struct stat hash_sb, db_sb;
static void list_db(void);
static u_char open_db(void);
static void open_hash(void);
static void list_hash(void);


static void DCC_NORET
usage(void)
{
	dcc_logbad(EX_USAGE, "usage: [-vVHD] [-G on | off] [-h homedir]\n"
		   "   [-s server-ID[,server-addr][,server-port]]\n"
		   "   [-C '[type] [h1 h2 h3 h4]'] [-I server-ID] [-A dbptr]"
		   " [-L pathlen]\n"
		   "   [-P pages] [-T timestamp] [file file2 ...]");
}



int
main(int argc, char **argv)
{
	u_char print_version = 0;
	char hostname[DCC_MAXDOMAINLEN];
	int file_num;
	DCC_CK_TYPES type;
	char tbuf[80];
	const char *cp, *cp0;
	struct timeval tv1, tv2;
	int us;
	struct tm tm;
	char *p;
	u_long l;
	int i;

	dcc_syslog_init(0, argv[0], 0);

	while ((i = getopt(argc, argv, "vVHDG:h:s:C:I:A:L:P:T:")) != -1) {
		switch (i) {
		case 'v':
			++verbose;
			break;

		case 'V':
			dcc_version_print();
			print_version = 1;
			break;

		case 'G':
			if (!strcasecmp(optarg, "on")) {
				grey_on = 1;
			} else if (!strcasecmp(optarg, "off")) {
				grey_on = 0;
			} else {
				usage();
			}
			break;

		case 'h':
			homedir = optarg;
			break;

		case 's':
			l = strtoul(optarg, &p, 10);
			if ((*p != '\0' && *p != ',')
			    || !DCC_ID_SRVR_NORMAL(l))
				dcc_logbad(EX_USAGE, "invalid DCC ID \"-s %s\"",
					   optarg);
			srvr.clnt_id = l;
			if (*p != '\0') {
				++p;
				p += strspn(p, DCC_WHITESPACE);
			}
			hostname[0] = '\0';
			srvr.port = 0;
			if (*p == '\0')
				break;
			cp = dcc_parse_nm_port(dcc_emsg, p, srvr.port,
					       hostname, sizeof(hostname),
					       &srvr.port, 0, 0, 0, 0);
			if (!cp)
				dcc_logbad(EX_USAGE, "%s", dcc_emsg);
			cp += strspn(cp, DCC_WHITESPACE);
			if (*cp != '\0')
				dcc_logbad(EX_USAGE,
					   "unrecognized port number in"
					   "\"-s %s\"", optarg);
			if (hostname[0] != '\0')
				BUFCPY(srvr.hostname, hostname);
			break;

		case 'H':
			no_hash = 1;
			break;

		case 'D':
			no_data = 1;
			break;

		case 'C':
			if (num_search_cksums >= DIM(search_cksums)) {
				dcc_error_msg("too many -C checksums");
				break;
			}
			matching = 1;
			cp0 = optarg;
			/* separate checksum type and checksum in cp and tbuf */
			cp = dcc_parse_word(0, tbuf, sizeof(tbuf),
					    optarg, "checksum type", 0, 0);
			if (!cp)
				exit(1);
			if (!strcasecmp(tbuf, "hex")) {	/* ignore "hex" */
				cp0 = cp;
				cp = dcc_parse_word(0, tbuf, sizeof(tbuf),
						    cp, "checksum type",
						    0, 0);
				if (!cp)
					dcc_logbad(EX_USAGE,
						   "unrecognized checksum"
						   " \"-C %s\"", optarg);
			}
			if (*cp == '\0') {
				/* allow bare checksum type */
				type = dcc_str2type_del(tbuf, -1);
				if (type == DCC_CK_INVALID)
					dcc_logbad(EX_USAGE,
						   "unrecognized checksum type"
						   " \"-C %s\"", optarg);
				search_cksums[num_search_cksums].type = type;
				memset(&search_cksums[num_search_cksums].sum, 0,
				       sizeof(DCC_SUM));
				search_cksums[num_search_cksums].type_only = 1;
				++num_search_cksums;
				break;
			}
			/* allow missing checksum type */
			l = strtoul(tbuf, &p, 16);
			if (*p == '\0') {
				if (0 >= dcc_parse_hex_ck(dcc_emsg, 0,
							"-", DCC_CK_FLOD_PATH,
							cp0, 0, save_cksum))
					dcc_logbad(EX_USAGE, "%s", dcc_emsg);
				break;
			}
			type = dcc_str2type_del(tbuf, -1);
			if (type == DCC_CK_FLOD_PATH)
				dcc_logbad(EX_USAGE,
					   "unrecognized checksum type"
					   " \"-C %s\"", optarg);
			if (1 <= dcc_parse_hex_ck(dcc_emsg, 0,
						  tbuf, type,
						  cp, 0, save_cksum))
				break;
			/* allow strings for server-IDs */
			if (type == DCC_CK_SRVR_ID
			    && (i = strlen(cp)) <= ISZ(DCC_SUM)) {
				DCC_SUM name;
				memset(&name, 0, sizeof(name));
				memcpy(&name, cp, i);
				save_cksum(0, 0, type, &name, 0);
				break;
			}
			dcc_logbad(EX_USAGE, "%s", dcc_emsg);
			break;

		case 'I':
			if (num_search_ids >= DIM(search_ids)) {
				dcc_error_msg("too many -I IDs");
				break;
			}
			search_ids[num_search_ids] = strtoul(optarg, &p, 10);
			if (search_ids[num_search_ids] > DCC_SRVR_ID_MAX
			    || *p != '\0')
				dcc_logbad(EX_USAGE,
					   "invalid server-ID \"-I %s\"",
					   optarg);
			++num_search_ids;
			matching = 1;
			break;

		case 'A':
			dbaddr = strtoul(optarg, &p, 16);
			if (*p != '\0')
				dcc_logbad(EX_USAGE,
					   "invalid database address \"%s\"",
					   optarg);
			matching = 1;
			break;

		case 'L':
			max_pathlen = strtoul(optarg, &p, 10);
			if (*p != '\0')
				dcc_logbad(EX_USAGE,
					   "invalid path length \"%s\"",
					   optarg);
			matching = 1;
			break;

		case 'P':
			page_offset = strtoul(optarg, &p, 10);
			if (*p != '\0')
				dcc_logbad(EX_USAGE,
					   "invalid number of pages \"%s\"",
					   optarg);
			matching = 1;
			break;

		case 'T':
			if (num_search_ts >= DIM(search_ts)) {
				dcc_error_msg("too many -T timestamps");
				break;
			}
			memset(&tm, 0, sizeof(tm));
			i = sscanf(optarg, "%d/%d/%d %d:%d:%d.%d%c",
				   &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
				   &tm.tm_hour, &tm.tm_min, &tm.tm_sec,
				   &us, tbuf);
			if (i < 6 || i > 7
			    || tm.tm_mon <= 0)
				dcc_logbad(EX_USAGE,"bad timestamp \"%s\"",
					   optarg);
			--tm.tm_mon;
			tm.tm_year += 100;
			tv1.tv_sec = DCC_TIMEGM(&tm);
			if (tv1.tv_sec < 0)
				dcc_logbad(EX_USAGE, "invalid timestamp \"%s\"",
					   optarg);
			tv2.tv_sec = tv1.tv_sec;
			if (i == 7) {
				if (us >= DCC_US)
					dcc_logbad(EX_USAGE,
						   "invalid microseconds"
						   " in \"%s\"",
						   optarg);
				tv1.tv_usec = us;
				tv2.tv_usec = us;
			} else {
				tv1.tv_usec = 0;
				tv2.tv_usec = DCC_US-1;
			}
			timeval2ts(&search_ts[num_search_ts].lo, &tv1, 0);
			timeval2ts(&search_ts[num_search_ts].hi, &tv2, 0);
			++num_search_ts;
			matching = 1;
			break;

		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	def_argv[0] = grey_on ? grey_db_nm : dcc_db_nm;
	if (argc == 0) {
		if (print_version)
			exit(EX_OK);
		argv = def_argv;
		argc = 1;
	}

	dcc_clnt_unthread_init();
	if (!dcc_cdhome(dcc_emsg, homedir, 1))
		dcc_logbad(emsg_ex_code(dcc_emsg), "%s", dcc_emsg);

	flod_mmap_path_set();

	if (matching) {
		if (no_data && no_hash)
			dcc_logbad(EX_USAGE,
				   "patterns need data or hash table");
		if (!no_data && !no_hash)
			no_hash = 1;
	}

	if (dbaddr != 0 && page_offset != 0)
		dcc_logbad(EX_USAGE, "-P and -A are incompatible");

	if (srvr.clnt_id != 0) {
		if (argc != 1)
			dcc_logbad(EX_USAGE, "lock only one file");

		i = load_ids(dcc_emsg, srvr.clnt_id, &srvr_clnt_tbl,
			     1, verbose > 4);
		if (!srvr_clnt_tbl)
			dcc_logbad(emsg_ex_code(dcc_emsg), "%s", dcc_emsg);
		if (i <= 0)
			dcc_error_msg("%s", dcc_emsg);
		memcpy(srvr.passwd, srvr_clnt_tbl->cur_passwd,
		       sizeof(srvr.passwd));
		if (srvr.hostname[0] == '\0')
			BUFCPY(srvr.hostname, "127.0.0.1");
		if (srvr.port == 0)
			srvr.port = DCC_GREY2PORT(grey_on);

		i = DCC_CLNT_FG_SLOW;
		if (grey_on)
			i |= DCC_CLNT_FG_GREY;
		ctxt = dcc_tmp_clnt_init(dcc_emsg, 0, &srvr, 0, 0, i, 0);
		if (!ctxt)
			dcc_logbad(emsg_ex_code(dcc_emsg), "%s", dcc_emsg);
		if (!lock_dbclean(dcc_emsg, *argv))
			dcc_logbad(emsg_ex_code(dcc_emsg),
				   "%s: dbclean running?", dcc_emsg);

		atexit(rel_db);
		signal(SIGALRM, sigterm);
		signal(SIGHUP, sigterm);
		signal(SIGTERM, sigterm);
		signal(SIGINT, sigterm);
		if (!dcc_aop_persist(dcc_emsg, ctxt,
				     grey_on ? DCC_CLNT_FG_GREY : 0,
				     verbose != 0,
			     DCC_AOP_DB_UNLOAD, 0, 60*5, &aop_resp))
			dcc_logbad(emsg_ex_code(dcc_emsg), "%s", dcc_emsg);
	}

	for (file_num = 1; *argv != 0; ++argv, ++file_num) {
		if (fd_db >= 0)
			close(fd_db);
		if (fd_hash >= 0)
			close(fd_hash);

		BUFCPY(db_nm, *argv);
		snprintf(hash_nm, sizeof(hash_nm), "%s"DB_HASH_SUFFIX, db_nm);

		if (file_num != 1)
			fputc('\n', stdout);
		if (verbose || argc > 1)
			printf("  %s\n", db_nm);

		/* try to open the hash table and the database
		 * fail only if we cannot open the database */
		open_hash();
		if (!open_db())
			continue;

		/* print the header of the database followed by its contents */
		list_db();
		list_hash();
	}

	exit(EX_OK);
}



static void
rel_db(void)
{
	if (!ctxt)
		return;
	if (!dcc_aop_persist(dcc_emsg, ctxt, grey_on ? DCC_CLNT_FG_GREY : 0,
			     1, DCC_AOP_DB_UNLOAD, 1, 60*5, &aop_resp))
		dcc_error_msg("%s", dcc_emsg);
	unlock_dbclean();
	ctxt = 0;
}



static void
sigterm(int sig DCC_UNUSED)
{
	rel_db();
}



static int
save_cksum(DCC_EMSG emsg DCC_UNUSED, WF *wf DCC_UNUSED,
	   DCC_CK_TYPES type, DCC_SUM *sum, DCC_TGTS tgts DCC_UNUSED)
{
	search_cksums[num_search_cksums].type = type;
	search_cksums[num_search_cksums].sum = *sum;
	search_cksums[num_search_cksums].type_only = 0;
	++num_search_cksums;
	return 1;
}



#define RCD_PAT "%-27s %-8.8s %-10.10s %7s "L_HPAT"\n"
#define RCD_PAT1(s) RCD_PAT, s,  "", "", ""

static DB_HDR hdr_buf;

static enum {NO_LB,			/* no label */
	WHITE_LB,			/* whitelist section labelled */
	DATE_LB				/* normal section labelled */
} last_lb = NO_LB;
static u_char printed_rcd;
static int rcds, white_rcds, sums, white_sums;


static u_char
open_db(void)
{
	fd_db = open(db_nm, O_RDONLY, 0);
	if (fd_db < 0) {
		dcc_error_msg("open(%s): %s", db_nm, ERROR_STR());
		return 0;
	}

	if (!read_db_hdr(dcc_emsg, &hdr_buf, fd_db, db_nm)) {
		dcc_error_msg("%s", dcc_emsg);
		return 0;
	}

	if (memcmp(hdr_buf.p.version, version_buf, sizeof(hdr_buf.p.version))) {
		dcc_error_msg("     wrong magic \"%s\"\n"
			      "      instead of \""DB_VERSION_STR"\"",
			      esc_magic(hdr_buf.p.version,
					sizeof(hdr_buf.p.version)));
	}
	if (0 > fstat(fd_db, &db_sb)) {
		dcc_error_msg("stat(%s): %s", db_nm, ERROR_STR());
		return 0;
	}

	if (db_sb.st_size == sizeof(hdr_buf)) {
		dcc_error_msg("%s contains no checksums",db_nm);
		return 0;
	}

	if ((DB_PTR)db_sb.st_size < hdr_buf.p.db_csize) {
		dcc_error_msg("%s says it contains "L_DPAT
			      " bytes instead of "OFF_DPAT,
			      db_nm, hdr_buf.p.db_csize, db_sb.st_size);
	}

	db_pagesize = hdr_buf.p.pagesize;
	db_hash_page_len = db_pagesize/sizeof(HASH_ENTRY);

	return 1;
}



static void
list_db_entry(DB_PTR rcd_link, const DB_RCD *rcd)
{
	const DB_RCD_CK *rcd_ck;
	DB_PTR rcd_prev;
	DCC_TGTS tgts;
	DCC_CK_TYPES type;
	char ts_buf[40], id_buf[30];
	char tgts_buf[20];
	char ck_buf[sizeof(DCC_SUM)*3+2];
	u_char rpt_match, in_hash;
	int i;

	/* usually skip padding */
	if (rcd->fgs_num_cks == 0) {
		if (verbose > 1) {
			printf(RCD_PAT1("    page padding"), rcd_link);
			printed_rcd = 1;
		}
		return;
	}

	rpt_match = 0;

	/* skip until the desired first address */
	if (dbaddr != 0) {
		if (rcd_link < dbaddr)
			return;
		rpt_match = 1;
	}

	/* if we have target server-IDs, display only their reports */
	if (num_search_ids > 0) {
		for (i = 0; i < num_search_ids; ++i) {
			if (search_ids[i] == DB_RCD_ID(rcd)) {
				rpt_match = 1;
				goto got_id;
			}
		}
		return;
got_id:;
	}

	/* if we have target checksums, display only reports containing them */
	if (num_search_cksums > 0) {
		for (i = 0; i < num_search_cksums; ++i) {
			for (rcd_ck = rcd->cks;
			     rcd_ck < &rcd->cks[DB_NUM_CKS(rcd)];
			     ++rcd_ck) {
				type = search_cksums[i].type;
				if ((DB_CK_TYPE(rcd_ck) == type
				     || type == DCC_CK_FLOD_PATH)
				    && (search_cksums[i].type_only
					|| !memcmp(&search_cksums[i].sum,
						   &rcd_ck->sum,
						   sizeof(DCC_SUM)))) {
					rpt_match = 1;
					goto got_ck;
				}
			}
		}
		return;
got_ck:;
	}

	if (num_search_ts > 0
	    && DB_RCD_ID(rcd) != DCC_ID_WHITE) {
		for (i = 0; i < num_search_ts; ++i) {
			if (!ts_older_ts(&rcd->ts, &search_ts[i].lo)
			    && !ts_newer_ts(&rcd->ts, &search_ts[i].hi)) {
				rpt_match = 1;
				goto got_ts;
			}
		}
		return;
got_ts:;
	}

	if (max_pathlen != 0
	    && DB_RCD_ID(rcd) != DCC_ID_WHITE) {
		const DCC_FLOD_PATH_ID *id;
		DCC_SRVR_ID psrvr;
		int pathlen = 0;

		for (rcd_ck = rcd->cks;
		     rcd_ck < &rcd->cks[DB_NUM_CKS(rcd)]
		     && pathlen < max_pathlen;
		     ++rcd_ck) {
			if (DB_CK_TYPE(rcd_ck) != DCC_CK_FLOD_PATH)
				break;
			id = rcd_ck->sum.p;
			for (i = 0; i < DCC_NUM_FLOD_PATH; ++i, ++id) {
				psrvr = ((id->hi<<8) | id->lo);
				if (psrvr == DCC_ID_INVALID)
					break;
				++pathlen;
			}
		}
		if (pathlen < max_pathlen)
			return;
		rpt_match = 1;
	}

	++rcds;
	if (DB_RCD_ID(rcd) == DCC_ID_WHITE) {
		++white_rcds;
		if (last_lb != WHITE_LB) {
			last_lb = WHITE_LB;
			strcpy(ts_buf, "\n"DCC_XHDR_ID_WHITE);
		} else {
			ts_buf[0] = '\0';
		}
	} else {
		if (last_lb != DATE_LB) {
			last_lb = DATE_LB;
			if (rpt_match || verbose > 0)
				putchar('\n');
		}
		if (rpt_match || verbose > 0)
			ts2str(ts_buf, sizeof(ts_buf), &rcd->ts);
	}

	/* display separator between whitelist and ordinary entries
	 * along with the timestamp and the rest of the first line
	 * of a report */
	if (rpt_match
	    || verbose >= 2
	    || (verbose > 0 && DB_RCD_ID(rcd) != DCC_ID_WHITE)) {
		if (last_lb == DATE_LB) {
			tgts = DB_TGTS_RCD_RAW(rcd);
			printf(RCD_PAT, ts_buf,
			       (tgts == 0)
			       ? "deleted"
			       : tgts2str(tgts_buf, sizeof(tgts_buf),
					  tgts, grey_on),
			       id2str(id_buf, sizeof(id_buf), rcd->srvr_id),
			       DB_RCD_TRIMMED(rcd) ? "trimmed"
			       : DB_RCD_SUMRY(rcd) ? "summary"
			       : DB_RCD_DELAY(rcd) ? "delayed"
			       : "",
			       rcd_link);
		} else {
			printf(RCD_PAT1(ts_buf), rcd_link);
		}
		printed_rcd = 1;
	}

	/* display a report */
	for (rcd_ck = rcd->cks;
	     rcd_ck < &rcd->cks[DB_NUM_CKS(rcd)];
	     ++rcd_ck) {
		++sums;
		/* always count whitelist entries,
		 * but display only as requested */
		if (DB_RCD_ID(rcd) == DCC_ID_WHITE) {
			++white_sums;
			if (verbose < 2 && !rpt_match)
				continue;
		} else {
			if (verbose < 1 && !rpt_match)
				continue;
		}

		/* decode the special checksum that is a path */
		if (DB_CK_TYPE(rcd_ck) == DCC_CK_FLOD_PATH) {
			if (DB_RCD_ID(rcd) == DCC_ID_WHITE) {
				int lno, fno;
				memcpy(&lno, rcd_ck->sum.b, sizeof(lno));
				fno = rcd_ck->sum.b[sizeof(lno)];
				if (fno == 0) {
					printf("     line #%d\n", lno);
				} else {
					printf("     line #%d"
					       " included file #%d\n",
					       lno, fno);
				}

			} else {
				DCC_SRVR_ID psrvr;
				const DCC_FLOD_PATH_ID *path_id, *path_id_lim;
				const char *s;

				path_id = rcd_ck->sum.p;
				path_id_lim = path_id+DCC_NUM_FLOD_PATH;
				s = "     path: ";
				do {
					psrvr = ((path_id->hi<<8)
						 | path_id->lo);
					if (psrvr == DCC_ID_INVALID)
					    break;
					printf("%s%d", s, psrvr);
					s = "<-";
				} while (++path_id < path_id_lim);
				printf("%s\n", s);
			}
			continue;
		}

		in_hash = (!DB_TEST_NOKEEP(hdr_buf.p.nokeep_cks,
					   DB_CK_TYPE(rcd_ck))
			   || DB_RCD_ID(rcd) == DCC_ID_WHITE);

		/* fix if DCC_XHDR_MAX_TYPE_LEN changes from 10 */
		printf(" %c%-10.10s %-10.10s %-36s",
		       DB_CK_JUNK(rcd_ck) ? '*' : ' ',
		       DB_TYPE2STR(DB_CK_TYPE(rcd_ck)),
		       !in_hash ? "" : tgts2str(tgts_buf, sizeof(tgts_buf),
						DB_TGTS_CK(rcd_ck), grey_on),
		       ck2str(ck_buf, sizeof(ck_buf),
			      DB_CK_TYPE(rcd_ck), &rcd_ck->sum, DB_RCD_ID(rcd)));
		rcd_prev = DB_PTR_EX(rcd_ck->prev);
		if (rcd_prev == DB_PTR_NULL) {
			if (db_hash_len != 0 && in_hash)
				printf(" %8s", "");
		} else if (DB_PTR_IS_BAD(rcd_prev)) {
			printf(" bogus "L_HWPAT(8), rcd_prev);
		} else {
			printf(" "L_HWPAT(8), rcd_prev);
		}
		if (db_hash_len != 0 && in_hash)
			printf(" %x",
			       db_hash(DB_CK_TYPE(rcd_ck), &rcd_ck->sum));
		putchar('\n');
	}
}



static void
list_db(void)
{
	DB_RCD rcd;
	int rcd_len;
	DB_PTR rcd_lim, rcd_link;

	if (fd_db < 0)
		return;

	if (istmpfs(fd_db, db_nm))
		printf("     in a tmpfs file system\n");

	/* print the header of the database */
	if (verbose > 0) {
		list_cleaned(&hdr_buf.p);
		list_flod(&hdr_buf.p);
	}

	if (no_data)
		return;

	last_lb = NO_LB;
	printed_rcd = 0;
	rcds = 0;
	white_rcds = 0;
	sums = 0;
	white_sums = 0;

	/* list the records in the database */
	if (dbaddr != 0) {
		if ((DB_PTR)db_sb.st_size <= dbaddr) {
			page_offset = 0;
		} else {
			page_offset = ((db_sb.st_size - dbaddr + db_pagesize -1)
				       / db_pagesize);
		}
	}
	if (page_offset == 0) {
		rcd_link = DB_PTR_BASE;
	} else {
		rcd_link = db_sb.st_size / hdr_buf.p.pagesize;
		if (rcd_link < page_offset)
			rcd_link = 0;
		else
			rcd_link -= page_offset;
		rcd_link *= hdr_buf.p.pagesize;
		if (rcd_link < DB_PTR_BASE)
			rcd_link = DB_PTR_BASE;
	}
	rcd_lim = ((verbose > 2 && !matching)
		   ? (DB_PTR)db_sb.st_size : hdr_buf.p.db_csize);
	read_rcd_invalidate(0);
	while (rcd_link < rcd_lim) {
		rcd_len = read_rcd(dcc_emsg, &rcd, fd_db, rcd_link, db_nm);
		if (rcd_len <= 0) {
			if (rcd_len == 0)
				break;
			/* ignore fragmentary reports at the end */
			if (rcd_link > hdr_buf.p.db_csize - DB_RCD_HDR_LEN) {
				printf(RCD_PAT1("    page padding"), rcd_link);
				printed_rcd = 1;
				break;
			}
			dcc_error_msg("%s", dcc_emsg);
			read_rcd_invalidate(0);
			return;
		}


		list_db_entry(rcd_link, &rcd);
		rcd_link += rcd_len;
	}

	if (verbose || matching) {
		/* print address after the last record,
		 * but only if we printed a record */
		if (printed_rcd)
			printf(RCD_PAT1(""), rcd_link);
		putchar('\n');
	}
	if (!matching) {
		printf("%8d records containing %d checksums\n",
		       rcds, sums);
		if (!grey_on && rcds != white_rcds)
			printf("%8d non-whitelist records containing"
			       " %d checksums\n",
			       rcds-white_rcds, sums-white_sums);
	}
	read_rcd_invalidate(0);
}



static const char *
print_rate(char *buf, u_int buf_len,
	   const DB_PARMS *parms, u_char hash_or_db, u_char vers)
{
	double rate;

	rate = db_add_rate(parms, hash_or_db, vers);

	if (rate <= 0.0)
		return "?";

	return size2str(buf, buf_len, rate * (24*60*60*1.0), !hash_or_db);
}



static const char *
secs2str(char *buf, u_int buf_len, u_int32_t secs)
{
	int days, minutes, hours;

	days = secs / (24*60*60);
	secs %= (24*60*60);
	hours = secs / (60*60);
	secs %= (60*60);
	minutes = secs / 60;
	secs %= 60;

	if (hours == 0 && minutes == 0
	    && (secs == 0 || (days != 0 && secs < 15 && verbose < 3))) {
		snprintf(buf, buf_len, "%d day%s",
			 days, (days > 1) ? "s" : " ");
		return buf;
	}

	if (days == 0 && minutes == 0 && secs == 0) {
		snprintf(buf, buf_len, "%d hour%s",
			 hours, (hours > 1) ? "s" : " ");
		return buf;
	}

	if (days == 0 && hours == 0) {
		snprintf(buf, buf_len, "%02d:%02d",
			 minutes, secs);
		return buf;
	}

	if (days == 0) {
		snprintf(buf, buf_len, "%d:%02d:%02d",
			 hours, minutes, secs);
		return buf;
	}

	snprintf(buf, buf_len, "%d %d:%02d:%02d",
		 days, hours, minutes, secs);
	return buf;
}



static const char *
ex_ts2str(char *buf, u_int buf_len, const DCC_TS *ts)
{
	static DCC_TS never;

	if (!memcmp(&ts, &never, sizeof(never))) {
		STRLCPY(buf, "never    ", buf_len);
		return buf;
	}
	return ts2str(buf, buf_len, ts);
}



/* display the expiration information in the database header */
static void
list_cleaned(const DB_PARMS *parms)
{
#define CLEANED_PAT	" %12s %c %17.17s %17.17s %10s %10s"
	struct tm tm;
	char time_buf[32];
	char db_rate[10], hash_rate[10], entries_buf[10];
	DCC_CK_TYPES type;
	const char *before, *ques;
	char spam_ts_buf[18];
	char all_ts_buf[18];
	char allsecs_buf[20];
	char spamsecs_buf[20];

	if (verbose > 3)
		printf("     \"%s\"\n",
		       esc_magic(parms->version, sizeof(parms->version)));
	printf("     %s%s%spage size %#-8x  s/n %s\n",
	       (parms->flags & DB_PARM_FG_GREY) ? "greylist  " : "",
	       (parms->flags & DB_PARM_FG_CLEARED) ? "cleared  ": "",
	       (parms->flags & DB_PARM_FG_EXP_SET) ? "dbclean -e/-E used  ": "",
	       parms->pagesize, ts2str_err(&parms->sn));

	DCC_GMTIME(parms->cleared, &tm);
	strftime(time_buf, sizeof(time_buf), TS_PAT_GMT, &tm);
	if (TIME_T(parms->cleared) < time(0)
	    && parms->cleared >= 30*365*24*60*60) {
		/* valid if in the past and after 2000 */
		ques = "";
	} else {
		ques = "? ";
	}
	before = (parms->flags & DB_PARM_FG_NO_CLR) ? "before " : "";
	printf("     created %s%s%s", before, ques, time_buf);
	if (parms->cleaned == 0) {
		printf("; never cleaned\n");
	} else {
		DCC_GMTIME(parms->cleaned, &tm);
		strftime(time_buf, sizeof(time_buf), TS_PAT, &tm);
		printf("; cleaned %s\n", time_buf);
		if (parms->failsafe_cleanings != 0) {
			if (parms->cleaned_cron == 0) {
				printf("     never properly cleaned\n");
			} else {
				DCC_GMTIME(parms->cleaned_cron, &tm);
				strftime(time_buf, sizeof(time_buf),
					 TS_PAT, &tm);
				printf("     %d failsafe cleanings since %s\n",
				       parms->failsafe_cleanings, time_buf);
			}
		}
	}

	if (verbose > 3) {
		printf("     db_csize="L_DPAT"  old="L_DPAT"\n",
		       parms->db_csize, parms->old_db_csize);
		printf("     added="L_DPAT"  prev_db_added="L_DPAT"\n",
		       parms->db_added, parms->prev_db_added);
		printf("     hash_used=%d  old_hash_used=%d\n",
		       parms->hash_used, parms->old_hash_used);
		printf("     added=%d  prev_added=%d  old_kept_cks=%d\n",
		       parms->hash_added, parms->prev_hash_added,
		       parms->old_kept_cks);
	}
	printf("     added %s database bytes/day and %s hash entries/day\n",
	       print_rate(db_rate, sizeof(db_rate), parms, 0, 0),
	       print_rate(hash_rate, sizeof(hash_rate), parms, 1, 0));
	if (verbose > 3) {
		int cur_rate_secs;

		cur_rate_secs = (parms->last_rate_sec - ts2secs(&parms->sn)
				 + parms->rate_secs);

		printf("       currently %s bytes, %s entries/day"
		       " for %d seconds=%.1f days\n",
		       print_rate(db_rate, sizeof(db_rate), parms, 0, 1),
		       print_rate(hash_rate, sizeof(hash_rate), parms, 1, 1),
		       cur_rate_secs, cur_rate_secs/(24.0*3600));
		printf("       previously %s bytes, %s entries/day"
		       " for %d seconds=%.1f days\n",
		       print_rate(db_rate, sizeof(db_rate), parms, 0, 2),
		       print_rate(hash_rate, sizeof(hash_rate), parms, 1, 2),
		       parms->prev_rate_secs, parms->prev_rate_secs/(24.0*3600));
	}

	if (db_hash_len > 0
	    && parms->hash_used >= DB_HADDR_BASE)
		printf("     %.0f%% of %s hash entries used\n",
		       HADDR2LEN(parms->hash_used) * 100.0
		       / HADDR2LEN(db_hash_len),
		       size2str(entries_buf, sizeof(entries_buf),
				HADDR2LEN(db_hash_len), 0));

	if (parms->flags & DB_PARM_FG_GREY)
		printf(CLEANED_PAT,
		       "", ' ', "", "",
		       "window", "white");
	else
		printf(CLEANED_PAT,
		       "", ' ', "non-bulk expired", "bulk expired   ",
		       "non ", "bulk");
	for (type = DCC_CK_TYPE_FIRST; type <= DCC_CK_TYPE_LAST; ++type) {
		if ((type == DCC_CK_SRVR_ID
		     || DB_TEST_NOKEEP(parms->nokeep_cks, type))
		    && verbose < 3)
			continue;
		if (parms->ex_secs[type].all == DB_EXPIRE_SECS_MAX) {
			STRLCPY(allsecs_buf, "never", sizeof(allsecs_buf));
			STRLCPY(all_ts_buf, "-    ", sizeof(all_ts_buf));
		} else {
			secs2str(allsecs_buf, sizeof(allsecs_buf),
				 parms->ex_secs[type].all);
			ex_ts2str(all_ts_buf, sizeof(all_ts_buf),
				  &parms->ex_all[type]);
		}
		if (parms->ex_secs[type].spam == DB_EXPIRE_SECS_MAX) {
			STRLCPY(spamsecs_buf, "never", sizeof(spamsecs_buf));
			STRLCPY(spam_ts_buf, "-        ", sizeof(spam_ts_buf));
		} else {
			secs2str(spamsecs_buf, sizeof(spamsecs_buf),
				 parms->ex_secs[type].spam);
			ex_ts2str(spam_ts_buf, sizeof(spam_ts_buf),
				  &parms->ex_spam[type]);
		}
		printf("\n"CLEANED_PAT,
		       DB_TYPE2STR(type),
		       DB_TEST_NOKEEP(parms->nokeep_cks, type) ? '*' : ' ',
		       all_ts_buf, spam_ts_buf,
		       allsecs_buf, spamsecs_buf);
	}
#undef CLEANED_PAT
}



static void
list_flod(const DB_PARMS *parms)
{
#define POS_PAT(p1,p2) "%38s %9"p1" "p2"%s\n"
	FLOD_MMAP *mp;
	DCC_PATH path;
	char hostname[40], fg_buf[120];

	/* display the flood map only for default database */
	if (strcmp(dcc_fnm2abs_msg(path, db_nm), DB_NM2PATH_ERR(def_argv[0]))) {
		putchar('\n');
	} else if (!flod_mmap(dcc_emsg, 0, 0, 0)) {
		dcc_error_msg("\n\n%s", dcc_emsg);
	} else if (strcmp(flod_mmaps->magic, FLOD_MMAP_MAGIC)) {
		dcc_error_msg("\n\n%s contains the wrong magic \"%s\""
			      " instead of \"FLOD_MMAP_MAGIC\"",
			      flod_mmap_path,
			      esc_magic(flod_mmaps->magic,
					sizeof(flod_mmaps->magic)));
		if (!flod_unmap(dcc_emsg, 0))
			dcc_error_msg("%s", dcc_emsg);
	} else {
		fputs("\n\n  ", stdout);
		fputs(flod_mmap_path, stdout);
		printf("  s/n %s\n", ts2str_err(&flod_mmaps->sn));
		printf(POS_PAT("s","%s"),
		       "peer      ", "ID", "position", "");
		for (mp = flod_mmaps->mmaps;
		     mp <= LAST(flod_mmaps->mmaps);
		     ++mp) {
			if (mp->rem_hostname[0] == '\0')
				continue;
			printf(POS_PAT("d",L_HWPAT(8)),
			       dcc_host_portname(hostname, sizeof(hostname),
						 mp->rem_hostname,
						 mp->rem_portname),
			       mp->rem_id,
			       mp->confirm_pos,
			       flodmap_fg(fg_buf, sizeof(fg_buf), mp));
		}
		printf(POS_PAT("s",L_HWPAT(8)),
		       "minimum", "", parms->min_confirm_pos, "");
		printf(POS_PAT("s",L_HWPAT(8)),
		       "delay", "", flod_mmaps->delay_pos, "");
		printf(POS_PAT("s",L_HWPAT(8)),
		       "maximum", "", parms->db_csize, "");
		if (!flod_unmap(dcc_emsg, 0))
			dcc_error_msg("%s", dcc_emsg);
	}
#undef POS_PAT
}



static void
open_hash(void)
{
	db_hash_len = 0;
	fd_hash = open(hash_nm, O_RDONLY, 0);
	if (0 > fd_hash) {
		dcc_error_msg("open(%s): %s", hash_nm, ERROR_STR());
		return;
	}
	if (0 > fstat(fd_hash, &hash_sb)) {
		dcc_error_msg("stat(%s): %s", hash_nm, ERROR_STR());
		close(fd_hash);
		fd_hash = -1;
		return;
	}
	hash_fsize = hash_sb.st_size;
	db_hash_len = hash_fsize/sizeof(HASH_ENTRY);
	if ((hash_fsize % sizeof(HASH_ENTRY)) != 0) {
		dcc_error_msg("%s has size "L_DPAT", not a multiple of %d",
			      hash_nm, hash_fsize, ISZ(HASH_ENTRY));
		db_hash_len = 0;
		close(fd_hash);
		fd_hash = -1;
		return;
	}
	if (db_hash_len < MIN_HASH_ENTRIES) {
		dcc_error_msg("%s has too few records, "L_DPAT" bytes",
			      hash_nm, hash_fsize);
		db_hash_len = 0;
		close(fd_hash);
		fd_hash = -1;
		return;
	}

	db_hash_divisor = get_db_hash_divisor(db_hash_len);
	sys_pagesize = getpagesize();
}



#define HASH_MAP_LEN	(1024*1024)
#define HASH_MAP_NUM	16
typedef struct hash_map {
    struct hash_map *fwd, *bak;
    HASH_ENTRY	*buf;
    DB_HADDR	base;
    DB_HADDR	lim;
    DB_HOFF	offset;
    DB_HOFF	size;
} HASH_MAP;
static HASH_MAP hash_maps[HASH_MAP_NUM];
static HASH_MAP *hash_map_newest;


static u_char
hash_munmap(HASH_MAP *mp)
{
	if (!mp->buf)
		return 1;

	if (0 > munmap((void *)mp->buf, mp->size)) {
		dcc_error_msg("munmap(%s,"L_DPAT"): %s",
			      hash_nm, mp->size, ERROR_STR());
		return 0;
	}
	mp->buf = 0;
	return 1;
}



static u_char
hash_map_clear(void)
{
	HASH_MAP *mp;
	int i;

	mp = hash_maps;
	for (i = 0; i < DIM(hash_maps); ++i, ++mp) {
		if (i == DIM(hash_maps)-1)
			mp->fwd = hash_maps;
		else
			mp->fwd = mp+1;
		if (i == 0)
			mp->bak = LAST(hash_maps);
		else
			mp->bak = mp-1;
	}
	hash_map_newest = hash_maps;

	for (mp = hash_maps; mp <= LAST(hash_maps); ++mp) {
		if (!hash_munmap(mp))
			return 0;
	}

	return 1;
}



static void
hash_map_ref(HASH_MAP *mp)
{
	if (hash_map_newest != mp) {
		mp->fwd->bak = mp->bak;
		mp->bak->fwd = mp->fwd;
		mp->fwd = hash_map_newest;
		mp->bak = hash_map_newest->bak;
		mp->fwd->bak = mp;
		mp->bak->fwd = mp;
		hash_map_newest = mp;
	}
}



static const void *
haddr_mmap(DB_HADDR haddr)
{
	HASH_MAP *mp;
	void *p;
	int i;

	for (i = 0, mp = hash_map_newest;
	     i < DIM(hash_maps);
	     ++i, mp = mp->fwd) {
		if (!mp->buf)
			continue;
		if (haddr >= mp->base
		    && haddr < mp->lim) {
			hash_map_ref(mp);
			return mp->buf + (haddr - mp->base);
		}
	}

	mp = hash_map_newest->bak;
	hash_munmap(mp);

	mp->base = haddr -  haddr%HASH_MAP_LEN;
	mp->offset = mp->base*sizeof(HASH_ENTRY);
	mp->size = hash_fsize - mp->offset;
	if (mp->size > HASH_MAP_LEN*ISZ(HASH_ENTRY))
		mp->size = HASH_MAP_LEN*ISZ(HASH_ENTRY);
	mp->lim = mp->base + mp->size/sizeof(HASH_ENTRY);
	p = mmap(0, mp->size, PROT_READ, MAP_SHARED, fd_hash, mp->offset);
	if (p != MAP_FAILED) {
		mp->buf = p;
		hash_map_ref(mp);
		return mp->buf + (haddr - mp->base);
	}
	dcc_error_msg("mmap(%s,%d,%d): %s",
		      hash_nm, (int)mp->size, (int)mp->offset,
		      ERROR_STR());
	return 0;
}



static void
list_hash(void)
{
#define HEAD() (headed ? 1 : (headed = 1, printf("\n %s\n", hash_nm)))
	const HASH_ENTRY *entry;
	const HASH_CTL *ctl;
	struct tm tm;
	char time_buf[30];
	DB_HADDR collisions, long_links, very_long_links, chains, chain_lens;
	int max_chain_len, chain_len;
	DB_HADDR free_fwd, free_bak;
	DB_HADDR fwd, bak, haddr;
	DB_HOFF hoff1, hoff2;
	DB_HADDR db_hash_used_stored;
	DB_PTR rcd_link;
	DCC_CK_TYPES type;
	DB_RCD rcd;
	int rcd_len;
	u_char headed, clean;
	int i;

	if (fd_hash < 0)
		return;

	headed = 0;

	if (!hash_map_clear())
		return;

	read_rcd_invalidate(DB_RCD_LEN_MAX);

	ctl = haddr_mmap(0);
	if (!ctl)
		return;
	if (memcmp(ctl->s.magic, &hash_magic, sizeof(hash_magic))) {
		HEAD();
		dcc_error_msg("     contains the wrong magic \"%s\""
			      " instead of \""HASH_MAGIC_STR"\"",
			      esc_magic(ctl->s.magic, sizeof(ctl->s.magic)));
		return;
	}

	if (verbose > VERBOSE_HASH) {
		HEAD();
		printf("     \"%.*s\"\n",
		       ISZ(ctl->s.magic), ctl->s.magic);
	}

	if (verbose && istmpfs(fd_hash, db_hash_nm)) {
		HEAD();
			printf("     in a tmpfs file system\n");
	}
	if (srvr.clnt_id != 0) {
		clean = 0;
	} else {
		clean = (ctl->s.flags & HASH_CTL_FG_CLEAN) != 0;
		if (!clean) {
			HEAD();
			printf("     not closed\n");
		}
	}
	if (verbose && (verbose >= VERBOSE_HASH
			|| (ctl->s.flags & HASH_CTL_FG_NOSYNC))) {
		if (ctl->s.synced != 0) {
			HEAD();
			DCC_GMTIME(ctl->s.synced, &tm);
			strftime(time_buf, sizeof(time_buf), TS_PAT, &tm);
			printf("     hash table synced %s\n", time_buf);
		}
		if (ctl->s.flags & HASH_CTL_FG_NOSYNC) {
			HEAD();
			printf("     unsafe after next system reboot\n");
		}
	}

	free_fwd = ctl->s.free_fwd;
	free_bak = ctl->s.free_bak;
	if (DB_HADDR_INVALID(ctl->s.free_fwd)
	    && (ctl->s.free_fwd != FREE_HADDR_END
		|| ctl->s.free_fwd != ctl->s.free_bak)) {
		HEAD();
		dcc_error_msg("     broken free list head of %#x",
			      ctl->s.free_fwd);
	}
	if (DB_HADDR_INVALID(ctl->s.free_bak)
	    && (ctl->s.free_bak != FREE_HADDR_END
		|| ctl->s.free_fwd != ctl->s.free_bak)) {
		HEAD();
		dcc_error_msg("     broken free list tail of %#x",
			      ctl->s.free_bak);
	}
	if (verbose > VERBOSE_HASH)
		printf("     free: %x, %x\n", free_fwd, free_bak);

	if (db_hash_len != ctl->s.len
	    && (ctl->s.len != 0 || verbose >= VERBOSE_HASH)) {
		HEAD();
		dcc_error_msg("     has %d entries but claims %d",
			      HADDR2LEN(db_hash_len), HADDR2LEN(ctl->s.len));
	}
	db_hash_used_stored = ctl->s.used;
	if (ctl->s.used > db_hash_len) {
		HEAD();
		dcc_error_msg("     contains only %d entries but %d used",
			      HADDR2LEN(ctl->s.len), HADDR2LEN((ctl->s.used)));
	}
	if (ctl->s.used == db_hash_len) {
		HEAD();
		dcc_error_msg("     overflows with %d entries",
			      HADDR2LEN(db_hash_len));
	}
	if (ctl->s.db_csize != hdr_buf.p.db_csize
	    && (clean || verbose >= VERBOSE_HASH)) {
		HEAD();
		dcc_error_msg("     claims %s contains "L_DPAT
			      " bytes instead of "L_DPAT,
			      db_nm, ctl->s.db_csize, hdr_buf.p.db_csize);
	}
	if (ctl->s.divisor != get_db_hash_divisor(db_hash_len)) {
		HEAD();
		dcc_error_msg("     built with hash divisor %d instead of %d",
			      ctl->s.divisor, get_db_hash_divisor(db_hash_len));
	}
	if (verbose >= VERBOSE_HASH) {
		printf("     hash length=%#x=%d used=%#x=%d\n",
		       ctl->s.len, ctl->s.len,
		       ctl->s.used, ctl->s.used);
		printf("     db_csize="L_HxPAT"="L_DPAT"\n",
		       ctl->s.db_csize, ctl->s.db_csize);
	}

	if (no_hash) {
		hash_map_clear();
		return;
	}

	db_hash_used = DB_HADDR_BASE;
	collisions = 0;
	long_links = 0;
	very_long_links = 0;
	chains = 0;
	chain_lens = 0;
	max_chain_len = 1;
	for (haddr = DB_HADDR_BASE; haddr < db_hash_len; ++haddr) {
		entry = haddr_mmap(haddr);
		if (!entry)
			break;

		fwd = DB_HADDR_EX(entry->fwd);
		bak = DB_HADDR_EX(entry->bak);
		rcd_link = DB_HPTR_EX(entry->rcd);

		/* deal with a free entry */
		if (HE_IS_FREE(entry)) {
			if (rcd_link != DB_PTR_NULL)
				dcc_error_msg("free hash table data link at"
					      " %x to "L_HPAT,
					      haddr, rcd_link);
			if (haddr == free_fwd
			    && bak != FREE_HADDR_END)
				dcc_error_msg("bad 1st free hash bak link %x",
					      bak);
			else if (haddr != free_fwd
				 && (DB_HADDR_INVALID(bak) || bak >= haddr))
				dcc_error_msg("bad hash bak link at %x",
					      haddr);
			if (haddr == free_bak
			    && fwd != FREE_HADDR_END)
				dcc_error_msg("bad last free hash fwd link %x",
					      fwd);
			else if (haddr != free_bak
				 && (DB_HADDR_INVALID(fwd) || fwd <= haddr))
				dcc_error_msg("bad hash fwd link at %x",
					      haddr);
			if (verbose >= VERBOSE_HASH)
				printf("    %6x: %6x %6x\n", haddr, fwd, bak);
			continue;
		}

		if (haddr == free_fwd && clean)
			dcc_error_msg("start of free list at %x not free",
				      haddr);
		if (haddr == free_bak && clean)
			dcc_error_msg("end of free list at %x not free",
				      haddr);

		/* deal with a used entry */
		++db_hash_used;
		if (DB_PTR_IS_BAD(rcd_link))
			dcc_error_msg("bad hash table data link at"
				      " %x to "L_HPAT,
				      haddr, rcd_link);
		if (DB_HADDR_INVALID(fwd) && fwd != DB_HADDR_NULL) {
			dcc_error_msg("bad hash fwd link at %x to %x",
				      haddr, fwd);
			continue;
		}
		if (DB_HADDR_INVALID(bak) && bak != DB_HADDR_NULL) {
			dcc_error_msg("bad hash bak link at %x to %x",
				      haddr, bak);
			continue;
		}
		if (verbose >= VERBOSE_HASH)
			printf("    %6x: %6x %6x "L_HWPAT(8)" %s\n",
			       haddr, fwd, bak, rcd_link,
			       DB_TYPE2STR(HE_TYPE(entry)));

		if (bak != DB_HADDR_NULL) {
			++collisions;
			hoff1 = bak*sizeof(HASH_ENTRY);
			hoff2 = haddr*sizeof(HASH_ENTRY);
			if ((hoff1/sys_pagesize != hoff2/sys_pagesize)
			    && ((hoff1+sizeof(HASH_ENTRY)-1)/sys_pagesize
				!= (hoff2+sizeof(HASH_ENTRY)-1)/sys_pagesize))
				++long_links;
			if (bak / db_hash_page_len != haddr / db_hash_page_len)
				++very_long_links;
		} else {
			++chains;
			bak = haddr;
			chain_len = 1;
			while (!DB_HADDR_INVALID(fwd)) {
				if (++chain_len > 500) {
					dcc_error_msg("possible hash chain loop"
						      " starting at %x"
						      " continuing through %x",
						      haddr, fwd);
					break;
				}
				entry = haddr_mmap(fwd);
				if (!entry)
					break;
				if (HE_IS_FREE(entry)
				    || DB_HADDR_EX(entry->bak) != bak) {
					dcc_error_msg("broken hash chain"
						      " starting at %x at %x",
						      haddr, fwd);
					break;
				}
				bak = fwd;
				fwd = DB_HADDR_EX(entry->fwd);
			}
			chain_lens += chain_len;
			if (max_chain_len < chain_len)
				max_chain_len = chain_len;
		}

		if (matching) {
			if (num_search_cksums > 0) {
				for (i = 0; i < num_search_cksums; ++i) {
					type = search_cksums[i].type;
					if (type == HE_TYPE(entry)
					    || type == DCC_CK_FLOD_PATH)
					    break;
				}
				if (i >= num_search_cksums)
					continue;
			}
			rcd_len = read_rcd(dcc_emsg, &rcd,
					   fd_db, rcd_link, db_nm);
			if (rcd_len <= 0) {
				if (rcd_len == 0)
					dcc_error_msg("bogus hash table data"
						      " link at %x to "L_HPAT,
						      haddr, rcd_link);
				else
					dcc_error_msg("%s", dcc_emsg);
			} else {
				list_db_entry(rcd_link, &rcd);
			}
		}
	}

	hash_map_clear();

	if (db_hash_used_stored > db_hash_used) {
		dcc_error_msg("%s should have %d entries but has only %d",
			      hash_nm,
			      HADDR2LEN(db_hash_used_stored),
			      HADDR2LEN(db_hash_used));
	} else if (db_hash_used_stored < db_hash_used
		   && (clean || verbose >= VERBOSE_HASH)) {
		dcc_error_msg("%s should have %d filled entries but has %d",
			      hash_nm,
			      HADDR2LEN(db_hash_used_stored),
			      HADDR2LEN(db_hash_used));
	}

	if (verbose >= VERBOSE_HASH)
		putchar('\n');
	printf("%8d hash entries  %d or %.0f%% used  %d free\n"
	       "%8d modulus  %8d or %.2f%% collisions\n"
	       "%8d off system page links  %d off page links",
	       HADDR2LEN(db_hash_len),
	       HADDR2LEN(db_hash_used),
	       (HADDR2LEN(db_hash_used)*100.0) / HADDR2LEN(db_hash_len),
	       HADDR2LEN(db_hash_len) - HADDR2LEN(db_hash_used),
	       db_hash_divisor,
	       collisions, collisions*100.0/HADDR2LEN(db_hash_len),
	       long_links, very_long_links);
	if (chains != 0)
		printf("\n%8d hash chains  %d max length  %.2f average length",
		       chains, max_chain_len, chain_lens*1.0/chains);
	fputc('\n', stdout);
}
