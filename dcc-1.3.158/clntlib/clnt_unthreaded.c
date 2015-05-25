/* Distributed Checksum Clearinghouse
 *
 * unthreaded version of client locking
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
 * Rhyolite Software DCC 1.3.158-1.52 $Revision$
 */

#include "dcc_ck.h"


/* many POSIX thread implementations have unexpected side effects on
 * ordinary system calls, so don't use the threaded version unless
 * necessary */

u_char clnt_threaded = 0;


static u_char ctxts_locked;


void
dcc_ctxts_lock(void)
{
#ifdef DCC_DEBUG_CLNT_LOCK
	if (ctxts_locked)
		dcc_logbad(EX_SOFTWARE, "already have ctxts lock");
#endif
	++ctxts_locked;
}



void
dcc_ctxts_unlock(void)
{
	assert_ctxts_locked();
	--ctxts_locked;
}



#ifdef DCC_DEBUG_CLNT_LOCK
void
assert_ctxts_locked(void)
{
	if (!ctxts_locked)
		dcc_logbad(EX_SOFTWARE, "don't have ctxts lock");
}



void
assert_ctxts_unlocked(void)
{
	if (ctxts_locked)
		dcc_logbad(EX_SOFTWARE, "have ctxts lock");
}
#endif



#ifdef DCC_DEBUG_HEAP
void
dcc_malloc_lock(void)
{
}


void
dcc_malloc_unlock(void)
{
}
#endif /* DCC_DEBUG_HEAP */



#ifndef HAVE_LOCALTIME_R
void
dcc_localtime_lock(void)
{
}



void
dcc_localtime_unlock(void)
{
}
#endif /* HAVE_LOCALTIME_R */



void
dcc_clnt_unthread_init(void)
{
#ifdef DCC_WIN32
	dcc_win32_init();
#endif
}


u_char
dcc_clnt_wake_resolve(void)
{
	return 0;
}



#ifdef DCC_DEBUG_CLNT_LOCK
void
assert_cwf_locked(void)
{
}
#endif



u_char
helper_lock_init(void)
{
	return 0;
}



void
helper_lock(void)
{
}



void
helper_unlock(void)
{
}



/* dccproc and dccsight do not generate SMTP error messages */
const REPLY_TPLT *
dnsbl_parse_reply(const char *pat DCC_UNUSED)
{
	return 0;
}
