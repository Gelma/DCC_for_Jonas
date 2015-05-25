# Makefile for clntlib for WIN32.

#   This assumes the Borland free command line tools FreeCommandLineTools.exe
#   available in 2004 at
#	http://www.borland.com/products/downloads/download_cbuilder.html
#   and elsewhere
#   or Microsoft's SDK

# Copyright (c) 2014 by Rhyolite Software, LLC
#
# This agreement is not applicable to any entity which sells anti-spam
# solutions to others or provides an anti-spam solution as part of a
# security solution sold to other entities, or to a private network
# which employs the DCC or uses data provided by operation of the DCC
# but does not provide corresponding data to other users.
#
# Permission to use, copy, modify, and distribute this software without
# changes for any purpose with or without fee is hereby granted, provided
# that the above copyright notice and this permission notice appear in all
# copies and any distributed versions or copies are either unchanged
# or not called anything similar to "DCC" or "Distributed Checksum
# Clearinghouse".
#
# Parties not eligible to receive a license under this agreement can
# obtain a commercial license to use DCC by contacting Rhyolite Software
# at sales@rhyolite.com.
#
# A commercial license would be for Distributed Checksum and Reputation
# Clearinghouse software.  That software includes additional features.  This
# free license for Distributed ChecksumClearinghouse Software does not in any
# way grant permision to use Distributed Checksum and Reputation Clearinghouse
# software
#
# THE SOFTWARE IS PROVIDED "AS IS" AND RHYOLITE SOFTWARE, LLC DISCLAIMS ALL
# WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL RHYOLITE SOFTWARE, LLC
# BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES
# OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
# ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#
# Rhyolite Software DCC 1.3.158-1.26 $Revision$


!include "../win32.makinc1"

TARGET	=clntlib.lib

# omit daemon.c getifaddrs.c helper.c parse_log_opt.c restart.c
# add getopt.c
SRCS	=aop.c ask.c cdhome.c ck.c ck2str.c ckbody.c ckfuz1.c		\
	ckfuz2.c ckmime.c ckparse.c cktbls.c ckwhite.c			\
	clnt_init.c clnt_send.c ckmime.c ckparse.c ckwhite.c		\
	clnt_init.c clnt_send.c clnt_unthreaded.c escstr.c		\
	dnsbl.c get_id.c get_secs.c hash_divisor.c			\
	heap_debug.c id2str.c inet_pton.c load_ids.c			\
	lock_open.c md5.c mkstemp.c msg2.c op2str.c			\
	parse_passwd.c parse_whitefile.c print_info.c range.c		\
	select_poll.c sign.c str2type.c str2cnt.c tgts2str.c		\
	type2str.c udp_bind.c xhdr.c getopt.c

OBJS	=$(SRCS:.c=.obj)

$(TARGET): $(OBJS)
	-del $@
!ifndef __NMAKE__
# Borland
	TLIB /c $@ @&&|
+$(**: = &^
+)
|
!else
# Microsoft
	LIB /OUT:$@ @<<
$**
<<
!endif

!include "../win32.makinc2"
