/* Distributed Checksum Clearinghouse
 *
 * talk to DNS resolver libraries that are not thread safe
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
 * Rhyolite Software DCC 1.3.158-1.12 $Revision$
 */

#include "dcc_defs.h"
#include "helper.h"


static DCC_EMSG dcc_emsg;

static void DCC_NORET
usage(void)
{
	dcc_logbad(EX_USAGE, "usage: [-V] -B...");
}



int
main(int argc, char **argv)
{
	u_char print_version = 0;
	int i;

	dcc_syslog_init(1, argv[0], 0);

	while ((i = getopt(argc, argv, "VB:L:")) != -1) {
		switch (i) {
		case 'V':
			dcc_version_print();
			print_version = 1;
			break;

		case 'B':
			if (!print_version
			    && !dcc_parse_dnsbl(dcc_emsg, optarg, 0))
				dcc_error_msg("%s", dcc_emsg);
			break;

		case 'L':
			dcc_parse_log_opt(optarg);
			break;

		default:
			usage();
		}
	}
	if (print_version)
		exit(EX_OK);
	usage();
}



int
thr_error_msg(void *cp DCC_UNUSED, const char *p, ...)
{
	va_list args;
	int i;

	va_start(args, p);
	i = dcc_verror_msg(p, args);
	va_end(args);
	return i;
}



void
thr_trace_msg(void *cp DCC_UNUSED, const char *p, ...)
{
	va_list args;

	va_start(args, p);
	dcc_verror_msg(p, args);
	va_end(args);
}



/* DOES append '\n', but since it is ony for errors, do not worry about it */
int
thr_log_print(void *cp DCC_UNUSED, u_char error DCC_UNUSED, const char *p, ...)
{
	va_list args;
	int i;

	va_start(args, p);
	i = dcc_verror_msg(p, args);
	va_end(args);
	return i;
}
