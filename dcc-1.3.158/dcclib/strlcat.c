/* compatibility hack
 *
 * Rhyolite Software DCC 1.3.158-1.3 $Revision$
 */

#include "dcc_defs.h"

int
dcc_strlcat(char *dst, const char *src, int dsize)
{
	int dlen, slen, clen;

	slen = strlen(src);
	if (--dsize < 0)
		return slen;

	dlen = strlen(dst);
	if (dlen >= dsize)
		dlen = dsize;

	clen = dsize - dlen;
	if (clen > slen)
		clen = slen;
	if (clen > 0) {
		memcpy(&dst[dlen], src, clen);
		dst[dlen+clen] = '\0';
	}

	return dlen+slen;
}
