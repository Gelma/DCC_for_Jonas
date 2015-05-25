/* compatibility hack
 *
 * Rhyolite Software DCC 1.3.158-1.2 $Revision$
 */

#include "dcc_defs.h"

int
dcc_strlcpy(char *dst, const char *src, int dsize)
{
	int slen;

	slen = strlen(src);

	if (--dsize < 0)
		return slen;

	if (dsize > slen)
		dsize = slen;
	if (dsize > 0)
		memcpy(dst, src, dsize);
	dst[dsize] = '\0';

	return slen;
}
