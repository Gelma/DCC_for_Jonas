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
 * Rhyolite Software DCC 1.3.158-1.28 $Revision$
 */

#include "srvr_defs.h"


/* not necessarily thread safe because gmtime_r() might be gmtime() */
char *
ts2str(char *ts_buf, u_int ts_buf_len, const DCC_TS *ts)
{
	struct timeval tv;
	struct tm tm;
	char time_buf[30];

	ts2timeval(&tv, ts);
	DCC_GMTIME(tv.tv_sec, &tm);
	strftime(time_buf, sizeof(time_buf), TS_PAT, &tm);
	snprintf(ts_buf, ts_buf_len, "%s.%06d",
		 time_buf, (int)tv.tv_usec);
	return ts_buf;
}



/* this is not thread safe but good enough for error messages */
const char *
ts2str_err(const DCC_TS *ts)
{
	static int bufno;
	static struct {
	    char    str[40];
	} bufs[4];
	char *s;

	s = bufs[bufno].str;
	bufno = (bufno+1) % DIM(bufs);

	return ts2str(s, sizeof(bufs[0].str), ts);
}
