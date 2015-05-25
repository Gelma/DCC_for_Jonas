/* Distributed Checksum Clearinghouse
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
 * Rhyolite Software DCC 1.3.154-1.4 $Revision$
 */

#include "dcc_defs.h"
#ifdef DCC_WIN32
#include <direct.h>
#endif



/* change to the DCC home directory */
u_char					/* 0=failed 1=ok */
dcc_cdhome(DCC_EMSG emsg, const char *newdir, u_char rdonly)
{
	DCC_PATH tmp;
	u_char result;

	result = 1;
	if (!newdir)
		newdir = DCC_HOMEDIR;

	if (*newdir == '\0') {
		dcc_pemsg(EX_NOINPUT, emsg,
			  "invalid null DCC home directory");
		newdir = DCC_HOMEDIR;
		result = 0;
	}

	if (!dcc_fnm2abs(tmp, newdir, 0)) {
		dcc_pemsg(EX_NOINPUT, emsg,
			  "bad DCC home directory \"%s\"", newdir);
		result = 0;
	}
#ifdef DCC_WIN32
	if (!SetCurrentDirectory(tmp)) {
		dcc_pemsg(EX_NOINPUT, emsg, "SetCurrentDirectory(%s): %s" ,
			  tmp, ERROR_STR());
		return 0;
	}
	if (!getcwd(dcc_homedir, sizeof(dcc_homedir)))
		BUFCPY(dcc_homedir, tmp);
	dcc_homedir_len = strlen(dcc_homedir);
#else
	if (0 > chdir(tmp)) {
		dcc_pemsg(EX_NOINPUT, emsg, "chdir(%s): %s",
			  tmp, ERROR_STR());
		result = 0;
	} else {
		if (tmp[0] == '/'
		    || !getcwd(dcc_homedir, sizeof(dcc_homedir)))
			BUFCPY(dcc_homedir, tmp);
		dcc_homedir_len = strlen(dcc_homedir);
	}

	if (!rdonly && 0 > access(dcc_homedir, W_OK)) {
#ifdef HAVE_EACCESS
		if (errno == EACCES || errno == EPERM) {
			dcc_get_priv();
			if (0 > eaccess(dcc_homedir, W_OK)) {
				dcc_pemsg(EX_NOINPUT, emsg, "%s: %s",
					  tmp, ERROR_STR());
				result = 0;
			}
			dcc_rel_priv();
		} else {
#endif
			dcc_pemsg(EX_NOINPUT, emsg, "%s: %s",
				  tmp, ERROR_STR());
			result = 0;
#ifdef HAVE_EACCESS
		}
#endif
	}
#endif /* !DCC_WIN32 */

	return result;
}
