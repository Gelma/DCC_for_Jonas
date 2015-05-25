/* Distributed Checksum Clearinghouse
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
 * Rhyolite Software DCC 1.3.158-1.29 $Revision$
 */

#include "dcc_defs.h"
#include "dcc_xhdr.h"
#include <ctype.h>


static struct tbl {
    char	nm[DCC_XHDR_MAX_TYPE_LEN_BUF];
    DCC_CK_TYPES type;
} tbl[] = {
    {DCC_XHDR_TYPE_IP,		DCC_CK_IP},
    {DCC_XHDR_TYPE_ENV_FROM,	DCC_CK_ENV_FROM},
    {DCC_XHDR_TYPE_FROM,	DCC_CK_FROM},
    {DCC_XHDR_TYPE_SUB,		DCC_CK_SUB},
    {DCC_XHDR_TYPE_MESSAGE_ID,	DCC_CK_MESSAGE_ID},
    {DCC_XHDR_TYPE_RECEIVED,	DCC_CK_RECEIVED},
    {DCC_XHDR_TYPE_BODY,	DCC_CK_BODY},
    {DCC_XHDR_TYPE_FUZ1,	DCC_CK_FUZ1},
    {DCC_XHDR_TYPE_FUZ2,	DCC_CK_FUZ2},
    {DCC_XHDR_TYPE_GREY_MSG,	DCC_CK_G_MSG_R_TOTAL},
    {DCC_XHDR_TYPE_GREY_TRIPLE,	DCC_CK_G_TRIPLE_R_BULK},
    {DCC_XHDR_TYPE_REP_TOTAL,	DCC_CK_G_MSG_R_TOTAL},
    {DCC_XHDR_TYPE_REP_BULK,	DCC_CK_G_TRIPLE_R_BULK},
    {DCC_XHDR_TYPE_ENV_TO,	DCC_CK_ENV_TO},	/* same as DCC_CK_FLOD_PATH */
    {DCC_XHDR_TYPE_FLOD_PATH,	DCC_CK_FLOD_PATH},  /* same as DCC_CK_ENV_TO */
    {DCC_XHDR_TYPE_SRVR_ID,	DCC_CK_SRVR_ID},

    {"ALL",			SET_ALL_THOLDS},
    {"CMN",			SET_CMN_THOLDS},
};



static DCC_CK_TYPES
dcc_str2type_base(const char *str,
		  int len0)		/* length or -1 */
{
	struct tbl *tp;
	const char *tgtp, *nmp;
	char tgtc, nmc, d;
	int len, i;

	/* ignore leading blanks */
	i = strspn(str, DCC_WHITESPACE);
	str += i;
	if (len0 >= 0) {
		len0 -= i;
		if (len0 <= 0)
			return DCC_CK_INVALID;
	}

	for (tp = tbl; tp <= LAST(tbl); ++tp) {
		nmp = tp->nm;
		tgtp = str;
		len = len0;
		do {
			if (len >= 0 && --len < 0)
				tgtc = '\0';
			else
				tgtc = *tgtp++;
			nmc = *nmp++;
			if (nmc == '\0') {
				/* ignore trailing blanks and colons */
				while (tgtc == ':' || tgtc == ' '
				       || tgtc == '\t' || tgtc == '\n') {
					if (len >= 0 && --len < 0)
					    tgtc = '\0';
					else
					    tgtc = *tgtp++;
				}
				if (tgtc == '\0')
					return tp->type;
				break;
			}
			d = (nmc ^ tgtc);
		} while (d == 0 || d == ('A' ^ 'a')
			 || ((nmc == '-' || nmc == '.' || nmc == '_')
			     && (tgtc == '-' || tgtc == '.' || tgtc == '_')));
	}

	return DCC_CK_INVALID;
}



/* for whiteclnt files and dccsight */
DCC_CK_TYPES
dcc_str2type_wf(const char *str,
		 int len0)		/* length or -1 */
{
	DCC_CK_TYPES type;

	type = dcc_str2type_base(str, len0);
	if (!DCC_CK_THOLD_OK(type)
	    && type != DCC_CK_ENV_TO)
		return DCC_CK_INVALID;
	return type;
}



/* types that can be deleted in database */
DCC_CK_TYPES
dcc_str2type_del(const char *str,
	     int len0)			/* length or -1 */
{
	DCC_CK_TYPES type;

	type = dcc_str2type_base(str, len0);
	if (!DCC_CK_THOLD_OK(type)
	    && type != DCC_CK_SRVR_ID)
		return DCC_CK_INVALID;
	return type;
}



/* for `dbclean -t type,...`  `dccd -K type`  `dccproc -g type` */
DCC_CK_TYPES
dcc_str2type_db(const char *str,
		 int len0)		/* length or -1 */
{
	DCC_CK_TYPES type;

	type = dcc_str2type_base(str, len0);
	if (!DCC_CK_THOLD_OK(type))
		return DCC_CK_INVALID;
	return type;
}



/* for `dbclean -t type,...` and dccm, dccifd, and dccproc thresholds */
DCC_CK_TYPES
dcc_str2type_thold(const char *str,
		   int len0)		/* length or -1 */
{
	DCC_CK_TYPES type;

	type = dcc_str2type_base(str, len0);
	if (!DCC_CK_THOLD_OK(type)
	    && type != SET_ALL_THOLDS
	    && type != SET_CMN_THOLDS)
		return DCC_CK_INVALID;
	return type;
}
