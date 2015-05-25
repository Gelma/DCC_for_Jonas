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
 * Rhyolite Software DCC 1.3.158-1.18 $Revision$
 */

#include "dcc_defs.h"
#include "dcc_xhdr.h"


const char *
id2str(char *buf, u_int buf_len, DCC_CLNT_ID id)
{
	switch (id) {
	case DCC_ID_INVALID:
		STRLCPY(buf, DCC_XHDR_ID_INVALID, buf_len);
		return buf;

	case DCC_ID_WHITE:
		*buf = '\0';
		break;
	case DCC_ID_COMP:
		STRLCPY(buf, DCC_XHDR_ID_COMP, buf_len);
		return buf;

	case DCC_ID_SRVR_SIMPLE:
		STRLCPY(buf, DCC_XHDR_ID_SIMPLE, buf_len);
		return buf;
	case DCC_ID_SRVR_REP_OK:
		STRLCPY(buf, DCC_XHDR_ID_REP_OK, buf_len);
		return buf;
	case DCC_ID_SRVR_IGNORE:
		STRLCPY(buf, DCC_XHDR_ID_IGNORE, buf_len);
		return buf;
	case DCC_ID_SRVR_ROGUE:
		STRLCPY(buf, DCC_XHDR_ID_ROGUE, buf_len);
		return buf;

	case DCC_ID_SRVR_DATE:
		STRLCPY(buf, DCC_XHDR_ID_DATE, buf_len);
		return buf;

	default:
		snprintf(buf, buf_len, "%d", id);
	}
	return buf;
}
