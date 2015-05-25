/* Distributed Checksum Clearinghouse
 *
 * helper processes for DNS white- and blacklists
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
 * Rhyolite Software DCC 1.3.154-1.59 $Revision$
 */

#include "helper.h"
#include "dcc_heap_debug.h"
#include <signal.h>
#include <sys/wait.h>


#ifdef HAVE_HELPERS

#define HELPER_MAX_FAILURES 5		/* shutdown & restart these total */

#define MAX_SLOW	    2		/* 50% excess for slow DNS resolver */



/* add to the argv list for the helper processes */
void
helper_save_arg(const char *flag, const char *value)
{
	char const **new_arg;
	int i;

	if (helper.free_args <= 1) {
		/* reserve space for the argv[0] and the null terminator */
		helper.free_args += 5;
		i = (helper.argc + 2*helper.free_args) * sizeof(char *);
		new_arg = dcc_malloc(i);
		memset(new_arg, 0, i);
		if (helper.argv) {
			for (i = 0; i < helper.argc; ++i)
				new_arg[i] = helper.argv[i];
			dcc_free(helper.argv);
		} else {
			++helper.argc;
		}
		helper.argv = new_arg;
	}

	helper.argv[helper.argc] = flag;
	helper.argv[++helper.argc] = value;
	helper.argv[++helper.argc] = 0;
	--helper.free_args;
}



/* initialize things for the parent or one of the helping children */
void
helper_init(int max_helpers)
{
	helper.sn = getpid() + time(0);

	helper.pipe_write = -1;
	helper.pipe_read = -1;
	helper.su.sa.sa_family = AF_UNSPEC;
	helper.soc = INVALID_SOCKET;
	helper.req_len = sizeof(DNSBL_REQ);

	if (max_helpers) {
		/* max_helpers=0 if we are starting a child,
		 * but != 0 in the parent after parsing all args
		 *
		 * default to dccifd or dccm max_work */
		if (!helper.max_helpers)
			helper.max_helpers = max_helpers;

		helper.pids = dcc_malloc(sizeof(pid_t) * helper.max_helpers);
		memset(helper.pids, 0, sizeof(pid_t) * helper.max_helpers);
	}

	have_helpers = helper_lock_init();
}



/* collect zombies of helpers that died from boredom or otherwise */
void
reap_helpers(u_char locked)
{
	int status;
	pid_t pid;
	int pid_inx;

	if (!locked)
		helper_lock();

	for (;;) {
wait_again:;
		pid = waitpid(0, &status, WNOHANG);
		if (0 >= pid) {
			if (!locked)
				helper_unlock();
			return;
		}

		for (pid_inx = 0; ; ++pid_inx) {
			if (pid_inx >= helper.max_helpers) {
				/* not an acknowledged child */
				if (helper.debug >= 1)
					dcc_trace_msg("%d not a DNSBL"
						      " helper process reaped",
						      (int)pid);
				goto wait_again;
			}

			if (helper.pids[pid_inx] == pid)
				break;
		}

		helper.pids[pid_inx] = 0;

		/* races with dying helpers can confuse us */
		if (--helper.total_helpers < 0) {
			if (helper.debug)
				dcc_trace_msg("DNSBL total helpers=%d",
					      helper.total_helpers);
			helper.total_helpers = 0;
		}

		if (helper.slow_helpers > helper.total_helpers/MAX_SLOW)
			helper.slow_helpers = helper.total_helpers/MAX_SLOW;

		if (--helper.idle_helpers < 0) {
			/* We cannot be certain that a helper that quit was
			 * idle, but it should have been. */
			if (helper.debug)
				dcc_trace_msg("DNSBL idle helpers=%d",
					      helper.idle_helpers);
			helper.idle_helpers = 0;
		} else if (helper.idle_helpers > helper.total_helpers) {
			/* The limit on the total_helpers can let us
			 * drive idle_helpers<0
			 * which can make the previous fix wrong */
			if (helper.debug)
				dcc_trace_msg("DNSBL idle helpers=%d"
					      "  total helpers=%d",
					      helper.idle_helpers,
					      helper.total_helpers);
			helper.idle_helpers = helper.total_helpers;
		}

		/* this is called from the "totals" thread
		 * and so cannot use thr_error_msg() */

#if defined(WIFEXITED) && defined(WEXITSTATUS)
		if (WIFEXITED(status)) {
			if (WEXITSTATUS(status) == 0) {
				if (helper.debug > 1)
					dcc_trace_msg("DNSBL helper %d quit,"
						      " leaving %d helpers,"
						      " %d idle",
						      (int)pid,
						      helper.total_helpers,
						      helper.idle_helpers);
				continue;
			}
			dcc_error_msg("DNSBL helper %d quit with exit(%d),"
				      " leaving %d helpers, %d idle",
				      (int)pid, WEXITSTATUS(status),
				      helper.total_helpers,
				      helper.idle_helpers);
			continue;
		}
#endif
#if defined(WTERMSIG) && defined(WIFSIGNALED)
		if (WIFSIGNALED(status)) {
			dcc_error_msg("DNSBL helper %d quit with signal %d,"
				      " leaving %d helpers, %d idle",
				      (int)pid, WTERMSIG(status),
				      helper.total_helpers,
				      helper.idle_helpers);
			continue;
		}
#endif
		dcc_error_msg("DNSBL helper %d quit with %d,"
			      " leaving %d helpers, %d idle",
			      (int)pid, status,
			      helper.total_helpers, helper.idle_helpers);
	}
}



/* must be called with the counter mutex */
static void
terminate_helpers(void)
{
	if (helper.pipe_write != -1) {
		close(helper.pipe_write);
		helper.pipe_write = -1;
	}
	if (helper.pipe_read != -1) {
		close(helper.pipe_read);
		helper.pipe_read = -1;
	}
	if (helper.soc != INVALID_SOCKET) {
		closesocket(helper.soc);
		helper.soc = INVALID_SOCKET;
	}

	reap_helpers(1);
	++helper.gen;
	memset(helper.pids, 0, sizeof(pid_t) * helper.max_helpers);
	helper.total_helpers = 0;
	helper.idle_helpers = 0;
	helper.slow_helpers = 0;

	helper.failures = 0;
}



static void
help_finish(u_int gen, u_char ok, u_char counted, u_char locked)
{
	if (!locked)
		helper_lock();

	/* forget it if the children have been restarted */
	if (gen == helper.gen) {
		if (counted)
			++helper.idle_helpers;

		if (!ok) {
			if (++helper.failures >= HELPER_MAX_FAILURES) {
				if (helper.debug)
					dcc_trace_msg("restart DNSBL helpers");
				terminate_helpers();
			} else {
				reap_helpers(1);
			}
		}
	}

	if (!locked)
		helper_unlock();
}



/* ensure that the client context's socket is open so that we can borrow it */
static u_char
helper_soc_open(DCC_EMSG emsg, DCC_CLNT_CTXT *ctxt)
{
	u_char result;

	if (ctxt->soc[0].s != INVALID_SOCKET)
		return 1;

	dcc_ctxts_lock();
	if (!dcc_info_lock(emsg)) {
		dcc_ctxts_unlock();
		return 0;
	}
	result = dcc_clnt_soc_reopen(emsg, ctxt, &ctxt->soc[0], AF_UNSPEC);
	if (!dcc_info_unlock(emsg))
		result = 0;
	dcc_ctxts_unlock();
	return result;
}



static u_char
helper_soc_connect(DCC_EMSG emsg, DCC_CLNT_CTXT *ctxt, const DCC_SOCKU *su)
{
	u_char result;

	dcc_ctxts_lock();
	if (!dcc_info_lock(emsg)) {
		dcc_ctxts_unlock();
		return 0;
	}
	result = dcc_clnt_connect(emsg, ctxt, &ctxt->soc[0], su, AF_INET);
	dcc_clnt_soc_flush(&ctxt->soc[0]);
	if (!dcc_info_unlock(0))
		result = 0;
	dcc_ctxts_unlock();

	return result;
}



/* open the helper socket used by helper processes to receive requests
 *	must be called with the counter mutex */
static u_char
open_helper_soc(DCC_CLNT_CTXT *ctxt, void *logp)
{
	socklen_t soc_len;
	static int rcvbuf = 32*1024;
	static u_char rcvbuf_set;
	char sustr[DCC_SU2STR_SIZE];
	DCC_EMSG emsg;

	rcvbuf_set = 0;

	/* We want to create a new socket with the same choice of
	 * IPv4 or IPv6 as the DCC client context's socket.  To do that,
	 * try to ensure that the context's socket is healthy. */
	dcc_ctxts_lock();
	if (!dcc_clnt_rdy(emsg, ctxt,
			  DCC_CLNT_FG_BAD_SRVR_OK
			  | DCC_CLNT_FG_NO_MEASURE_RTTS
			  | DCC_CLNT_FG_NO_FAIL)
	    || !dcc_info_unlock(emsg))
		thr_trace_msg(logp, "DNSBL helper: %s", emsg);
	dcc_ctxts_unlock();
	dcc_mk_loop_su(&helper.su, ctxt->soc[0].loc.sa.sa_family, 0);

	dcc_clean_stdio();
	if (!udp_create(emsg, &helper.soc, &helper.su, 0)) {
		thr_error_msg(logp, "DNSBL helper bind(%s): %s",
			      dcc_su2str(sustr, sizeof(sustr), &helper.su),
			      emsg);
		terminate_helpers();
		return 0;
	}
	soc_len = sizeof(helper.su);
	if (0 > getsockname(helper.soc, &helper.su.sa, &soc_len)) {
		thr_error_msg(logp, "DNSBL helper getsockname(%d, %s): %s",
			      helper.soc, dcc_su2str(sustr, sizeof(sustr),
						     &helper.su),
			      ERROR_STR());
		terminate_helpers();
		return 0;
	}
	for (;;) {
		if (!setsockopt(helper.soc, SOL_SOCKET, SO_RCVBUF,
				&rcvbuf, sizeof(rcvbuf)))
			break;
		if (rcvbuf_set || rcvbuf <= 4096) {
			thr_error_msg(logp,
				      "DNSBL setsockopt(%s,SO_RCVBUF=%d): %s",
				      dcc_su2str(sustr, sizeof(sustr),
						 &helper.su),
				      rcvbuf, ERROR_STR());
			break;
		}
		rcvbuf -= 4096;
	}
	rcvbuf_set = 1;
	return 1;
}



/* Create the pipe used to awaken and terminate the helper processes
 *	must be called with the counter mutex */
static u_char
ready_helpers(void *logp)
{
	int fds[2];

	if (helper.pipe_write >= 0
	    && helper.pipe_read >= 0)
		return 1;

	terminate_helpers();

	/* give the helper child processes an FD that will go dead
	 * if the parent dies or otherwise closes the other end */
	dcc_clean_stdio();
	if (0 > pipe(fds)) {
		thr_error_msg(logp, "DNSBL parent helper pipe(): %s",
			      ERROR_STR());
		terminate_helpers();
		return 0;
	}
	helper.pipe_read = fds[0];
	helper.pipe_write = fds[1];
	if (0 > fcntl(helper.pipe_write, F_SETFD, FD_CLOEXEC)) {
		thr_error_msg(logp, "DNSBL helper fcntl(FD_CLOEXEC): %s",
			      ERROR_STR());
		terminate_helpers();
		return 0;
	}

	return 1;
}



/* Start a new helper process.
 *	The counter mutex must be locked */
static u_char
new_helper(DCC_CLNT_CTXT *ctxt, void *logp, const char *id)
{
	pid_t pid;
	char arg_buf[sizeof("set:")+sizeof(HELPER_PAT)+9+9+9];
	char trace_buf[200];
	char *bufp;
	DCC_SOCKET s;
	int pid_inx, buf_len, i, j;

	/* open the pipes and sockets if necessary */
	if (helper.soc == INVALID_SOCKET) {
		if (!ready_helpers(logp))
			return 0;
		if (!open_helper_soc(ctxt, logp))
			return 0;
	}

	reap_helpers(1);
	for (pid_inx = 0; ; ++pid_inx) {
		if (pid_inx >= helper.max_helpers)
			dcc_logbad(EX_SOFTWARE, "no free DNSBL pids[] entry");
		if (helper.pids[pid_inx] == 0)
			break;
	}

	fflush(stdout);
	fflush(stderr);
	pid = fork();
	if (pid < 0) {
		thr_error_msg(logp, "%s DNSBL helper fork(): %s",
			      id, ERROR_STR());
		return 0;
	}

	if (pid != 0) {
		/* this is the parent */
		helper.pids[pid_inx] = pid;
		++helper.total_helpers;
		return 1;
	}

	dcc_rel_priv();			/* no fun or games */
	dcc_clean_stdio();

	/* reset FD_CLOEXEC without affecting parent */
	s = helper.soc;
	if (s != INVALID_SOCKET) {
		s = dup(s);
		if (s == INVALID_SOCKET) {
			thr_error_msg(logp, "%s DNSBL soc dup(%d): %s",
				      id, helper.soc, ERROR_STR());
			return 0;
		}
	}

	snprintf(arg_buf, sizeof(arg_buf), "set:"HELPER_PAT,
		 s, helper.pipe_read, helper.total_helpers);
	helper_save_arg("-B", arg_buf);
	helper.argv[0] = dnsbl_progpath;
	buf_len = sizeof(trace_buf);
	bufp = trace_buf;
	for (i = 0; i < helper.argc && buf_len > 2; ++i) {
		j = snprintf(bufp, buf_len, "%s ", helper.argv[i]);
		buf_len -= j;
		bufp += j;
	}
	if (helper.debug >= 4)
		dcc_trace_msg("DNSBL helper exec %s", trace_buf);

	execv(helper.argv[0], (char * const *)helper.argv);
	/* This process should continue at helper_child() */

	dcc_logbad(EX_UNAVAILABLE, "execv(%s): %s",
		   trace_buf, ERROR_STR());
	return 0;
}



static void DCC_NORET
helper_exit(const char *reason)
{
	if (helper.debug > 1)
		dcc_trace_msg("helper process on %s %s",
			      dcc_su2str_err(&helper.su), reason);

	exit(0);
}



static u_char helper_alarm_hit;
static void
helper_alarm(int s DCC_UNUSED)
{
	helper_alarm_hit = 1;
}



/* helper processes start here via fork()/exec() in the parent  */
void DCC_NORET
helper_child(DCC_SOCKET s, int fd, int total_helpers)
{
	sigset_t sigs;
	socklen_t soc_len;
	DNSBL_REQ req;
	int req_len;
	DNSBL_RESP resp;
	DCC_SOCKU req_su;
	socklen_t su_len;
	struct timeval now;
	u_char wake_buf;
	int secs, i;

	/* this process inherits via exec() by dccm or dccifd odd signal
	 * blocking from some pthreads implementations including FreeBSD 5.* */
	signal(SIGHUP, SIG_IGN);
	signal(SIGINT, SIG_IGN);
	signal(SIGTERM, SIG_IGN);
	sigemptyset(&sigs);
	sigaddset(&sigs, SIGALRM);
	sigprocmask(SIG_UNBLOCK, &sigs, 0);

	helper_init(0);
	if (have_helpers)
		dcc_logbad(EX_SOFTWARE, "no threads for DNSBL helpers");

	helper.total_helpers = total_helpers;

	helper.pipe_read = fd;
	helper.soc = s;
	soc_len = sizeof(helper.su);
	if (0 > getsockname(helper.soc, &helper.su.sa, &soc_len))
		dcc_logbad(EX_IOERR, "DNSBL helper getsockname(%d): %s",
			   helper.soc, ERROR_STR());

	if (helper.debug > 1)
		dcc_trace_msg("DNSBL helper process starting on %s",
			      dcc_su2str_err(&helper.su));

	for (;;) {
		/* Use read() and SIGALRM to watch for a wake-up byte
		 * from the parent, the parent ending and closing the pipe,
		 * or enough idle time to require our retirement.  This
		 * tactic awakens a single child for each wake-up call
		 * from the parent.  Using select() or poll() on the main
		 * socket awakens a thundering herd of children */
		secs = HELPER_IDLE_STOP_SECS+1;
		if (helper.total_helpers > 0)
			secs /= helper.total_helpers+1;
		if (secs < 5)
			secs = 5;
		signal(SIGALRM, helper_alarm);
#ifdef HAVE_SIGINTERRUPT
		siginterrupt(SIGALRM, 1);
#endif
		helper_alarm_hit = 0;
		alarm(secs);
		for (;;) {
			su_len = sizeof(req_su);
			req_len = recvfrom(helper.soc, &req, ISZ(req), 0,
					   &req_su.sa, &su_len);

			/* sleep until awakened if no work is ready */
			if (req_len <= 0) {
				if (req_len == 0)
					dcc_logbad(EX_IOERR,
						   "DNSBL helper recvfrom()=0");
				if (!DCC_BLOCK_ERROR())
					dcc_logbad(EX_IOERR,
						   "DNSBL helper recvfrom():"
						   " %s",
						   ERROR_STR());
				if (helper_alarm_hit)
					helper_exit("idle helper exit");

				i = read(helper.pipe_read, &wake_buf, 1);

				/* The other end of the pipe can be marked
				 * non-blocking by some pthreads
				 * implementations.  That makes read() on this
				 * end fail with EAGAIN.  When that happens,
				 * fall back on select() or poll().
				 * Even on such pthread implementations,
				 * it rarely happens. */
				if (i < 0 && DCC_BLOCK_ERROR()) {
					DCC_POLLFD pollfd;
					DCC_EMSG emsg;

					pollfd.fd = helper.pipe_read;
					i = select_poll(emsg, &pollfd, 1,
							0, -1);
					if (i < 0)
					    dcc_logbad(EX_IOERR,
						       "dnsbl HELPER %s", emsg);
				}

				/* loof for work after a wake-up call */
				if (i > 0)
					continue;

				if (helper_alarm_hit)
					continue;
				if (i == 0)
					helper_exit("shutdown");
				if (i < 0) {
					dcc_logbad(EX_OSERR,
						   "DNSBL read(terminate): %s",
						   ERROR_STR());
				}
			}
			if (req_len != helper.req_len) {
				if (helper.debug)
					dcc_trace_msg("DNSBL helper"
						      " recvfrom(parent %s)=%d"
						      " instead of %d",
						      dcc_su2str_err(&req_su),
						      req_len,
						      helper.req_len);
				continue;
			}

			/* we might get stray packets because we cannot
			 * connect to a single port */
			if (!DCC_SUnP_EQ(&helper.su, &req_su)) {
				if (helper.debug)
					dcc_trace_msg("DNSBL helper"
						    " request from"
						    " %s instead of %s",
						    dcc_su2str_err(&req_su),
						    dcc_su2str_err(&helper.su));
				continue;
			}

			if (req.hdr.magic != HELPER_MAGIC_REQ
			    || req.hdr.version != HELPER_VERSION) {
				if (helper.debug)
					dcc_trace_msg("DNSBL helper"
						      " recvfrom(parent %s)"
						      " magic=%#08x",
						      dcc_su2str_err(&req_su),
						      req.hdr.magic);
				continue;
			}
			break;
		}
		gettimeofday(&now, 0);
		alarm(0);

		/* do not bother working if it is already too late to answer,
		 * perhaps because a previous helper died */
		i = tv_diff2us(&now, &req.hdr.start);
		if (i >= req.hdr.avail_us) {
			if (helper.debug > 1)
				dcc_trace_msg("%s DNSBL helper"
					      " already too late to start;"
					      " used %.1f of %.1f seconds",
					      req.hdr.id, i / (DCC_US*1.0),
					      req.hdr.avail_us / (DCC_US*1.0));
			continue;
		}

		memset(&resp, 0, sizeof(resp));
		resp.hdr.magic = HELPER_MAGIC_RESP;
		resp.hdr.version = HELPER_VERSION;
		resp.hdr.sn = req.hdr.sn;

		/* do the work and send an answer if we have one */
		if (!dnsbl_work(&req, &resp))
			continue;

		/* do not answer if it is too late */
		gettimeofday(&now, 0);
		i = tv_diff2us(&now, &req.hdr.start);
		if (i > (req.hdr.avail_us + DCC_US/2)) {
			if (helper.debug > 1)
				dcc_trace_msg("%s DNSBL helper"
					      " too late to answer;"
					      " used %.1f of %.1f seconds",
					      req.hdr.id, i / (DCC_US*1.0),
					      req.hdr.avail_us / (DCC_US*1.0));
			continue;
		}

		i = sendto(helper.soc, &resp, sizeof(resp), 0,
			   &req_su.sa, DCC_SU_LEN(&req_su));
		if (i != sizeof(resp)) {
			if (i < 0)
				dcc_error_msg("%s helper sendto(%s): %s",
					      req.hdr.id,
					      dcc_su2str_err(&req_su),
					      ERROR_STR());
			else
				dcc_error_msg("%s helper sendto(%s)=%d",
					      req.hdr.id,
					      dcc_su2str_err(&req_su), i);
		}
	}
}



/* ask a helper process to do some filtering */
u_char					/* 1=got an answer */
ask_helper(DCC_CLNT_CTXT *ctxt, void *logp,
	   time_t avail_us,		/* spend at most this much time */
	   HELPER_REQ_HDR *req,		/* request sent to helper */
	   int req_len,
	   HELPER_RESP_HDR *resp,	/* put answer here */
	   int resp_len)
{
	DCC_EMSG emsg;
	DCC_SOCKU send_su;
	socklen_t su_len;
	DCC_SOCKU recv_su;
	char sustr[DCC_SU2STR_SIZE];
	char sustr2[DCC_SU2STR_SIZE];
	u_char counted;
	u_int gen;
	struct timeval now;
	time_t us;
	DCC_POLLFD pollfd;
	int i;

	emsg[0] = '\0';

	/* We will use the client context socket to talk to the helper,
	 * so ensure that it is open */
	if (!helper_soc_open(emsg, ctxt)) {
		thr_trace_msg(logp, "DNSBL reopen %s", emsg);
		return 0;
	}

	/* keep the lock until we have sent our request and wake-up call
	 * to ensure that some other thread does not shut down all of
	 * the helpers. */
	helper_lock();
	gettimeofday(&now, 0);

	/* If it has been a long time since we used a helper, then the last
	 * of them might be about to die of boredom.  Fix that race by
	 * restarting all of them.
	 * Most dying helpers should be reaped by the totals timer thread. */
	if (helper.idle_helpers > 0
	    && DCC_IS_TIME(now.tv_sec, helper.idle_restart,
			   HELPER_IDLE_RESTART)) {
		reap_helpers(1);
		if (helper.idle_helpers > 0)
			terminate_helpers();
		gettimeofday(&now, 0);
	}

	/* Restart all helpers if the current helper socket is the wrong
	 * family.  This should happen only when the DCC client library
	 * has chosen a new server */
	if (helper.soc != INVALID_SOCKET
	    && ctxt->soc[0].loc.sa.sa_family != AF_UNSPEC
	    && helper.su.sa.sa_family != ctxt->soc[0].loc.sa.sa_family) {
		terminate_helpers();
		gettimeofday(&now, 0);
	}

	helper.idle_restart = now.tv_sec + HELPER_IDLE_RESTART;

	if (helper.idle_helpers - helper.slow_helpers > 0) {
		/* avoid taking the last idle helper because there are
		 * usually fewer truly idle helpers than we think because
		 * we don't always wait for them to finish */
		if (helper.idle_helpers > 2
		    || helper.total_helpers >= helper.max_helpers
		    || !new_helper(ctxt, logp, req->id))
			--helper.idle_helpers;
		counted = 1;
	} else if (helper.total_helpers >= helper.max_helpers) {
		if (helper.debug > 0)
			thr_trace_msg(logp, "%s DNSBL %d idle, %d slow, and"
				      " %d total DNSBL helpers", req->id,
				      helper.idle_helpers, helper.slow_helpers,
				      helper.total_helpers);
		counted = 0;
	} else {
		if (!new_helper(ctxt, logp, req->id)) {
			helper_unlock();
			return 0;
		}
		counted = 1;
	}

	 /* The resolution of the BIND timeout limits is seconds, so even on
	  * systems where the timeout limits work, the helper might delay
	  * a second or two.  To keep the count of idle helpers as accurate
	  * as possible, always wait at least 1 second for an answer
	  * and 2 seconds for an answer to reach the parent. */
	req->avail_us = avail_us;
	avail_us += DCC_US;
	req->start = now;
	req->magic = HELPER_MAGIC_REQ;
	req->version = HELPER_VERSION;

	req->sn = ++helper.sn;
	gen = helper.gen;

	/* snapshot the address in case another thread restarts the helpers */
	send_su = helper.su;

	/* If the client context socket is connected but not to the helper
	 * socket,
	 * then either disconnect it or connect to the helper's socket */
	if (ctxt->soc[0].rem.sa.sa_family != AF_UNSPEC
	    && !DCC_SU_EQ(&ctxt->soc[0].rem, &send_su)
	    && !helper_soc_connect(emsg, ctxt, &send_su)) {
		thr_trace_msg(logp, "DNSBL soc_connect(): %s", emsg);
		help_finish(gen, 0, counted, 1);
		helper_unlock();
		return 0;
	}
	if (ctxt->soc[0].rem.sa.sa_family == AF_UNSPEC) {
		i = sendto(ctxt->soc[0].s, req, req_len, 0,
			   &send_su.sa, DCC_SU_LEN(&send_su));
	} else {
		i = send(ctxt->soc[0].s, req, req_len, 0);
	}
	if (i != req_len) {
		if (i < 0)
			thr_trace_msg(logp, "%s DNSBL sendto(%s): %s",
				      req->id, dcc_su2str(sustr, sizeof(sustr),
							&send_su),
				      ERROR_STR());
		else
			thr_trace_msg(logp, "%s DNSBL sendto(%s)=%d",
				      req->id, dcc_su2str(sustr, sizeof(sustr),
							&send_su),
				      i);
		help_finish(gen, 0, counted, 1);
		helper_unlock();
		return 0;
	}

	/* awaken a helper */
	i = write(helper.pipe_write, "x", 1);
	if (i != 1) {
		if (i < 0)
			thr_trace_msg(logp, "%s DNSBL write(pipe_write=%d): %s",
				      req->id, helper.pipe_write, ERROR_STR());
		else
			thr_trace_msg(logp, "%s DNSBL write(pipe_write)=%d",
				      req->id, i);
		help_finish(gen, 0, counted, 1);
		helper_unlock();
		return 0;
	}
	helper_unlock();

	for (;;) {
		us = avail_us - tv_diff2us(&now, &req->start);
		if (us < 0)
			us = 0;
		pollfd.fd = ctxt->soc[0].s;
		i = select_poll(emsg, &pollfd, 1, 1, us);
		if (i < 0) {
			thr_error_msg(logp, "%s DNSBL %s", req->id, emsg);
			help_finish(gen, 0, counted, 0);
			return 0;
		}
		gettimeofday(&now, 0);

		if (i == 0) {
			if (helper.debug)
				thr_trace_msg(logp,
					      "%s DNSBL no helper answer after"
					      " %1.f sec", req->id,
					      tv_diff2us(&now, &req->start)
					      / (DCC_US*1.0));
			helper_lock();
			if (helper.slow_helpers<=helper.total_helpers/MAX_SLOW)
				++helper.slow_helpers;
			help_finish(gen, 0, counted, 1);
			helper_unlock();
			return 0;
		}


		su_len = sizeof(recv_su);
		i = recvfrom(ctxt->soc[0].s, resp, resp_len,
			     0, &recv_su.sa, &su_len);
		/* because we are using UDP, we might get stray packets */
		if (i != resp_len) {
			if (i < 0) {
				thr_trace_msg(logp, "%s DNSBL recvfrom(): %s",
					      req->id, ERROR_STR());
				if (DCC_BLOCK_ERROR())
					continue;
				help_finish(gen, 0, counted, 0);
				return 0;
			}
			if (helper.debug > 1)
				thr_trace_msg(logp, "%s DNSBL recvfrom(%s)=%d",
					      req->id,
					      dcc_su2str(sustr, sizeof(sustr),
							&recv_su),
					      i);
			continue;
		}
		if (!DCC_SUnP_EQ(&send_su, &recv_su)) {
			if (helper.debug != 0)
				thr_trace_msg(logp, "%s DNSBL recvfrom(%s)"
					      " instead of %s",
					      req->id,
					      dcc_su2str(sustr, sizeof(sustr),
							&recv_su),
					      dcc_su2str(sustr2, sizeof(sustr2),
							&send_su));
			continue;
		}
		if (resp->magic != HELPER_MAGIC_RESP
		    || resp->version != HELPER_VERSION
		    || resp->sn != req->sn) {
			if (helper.debug >1 )
				thr_trace_msg(logp, "%s DNSBL recvfrom(%s)"
					      " magic=%#08x sn=%d",
					      req->id,
					      dcc_su2str(sustr, sizeof(sustr),
							&recv_su),
					      resp->magic, resp->sn);
			continue;
		}

		if (helper.debug > 4)
			thr_trace_msg(logp,"%s DNSBL answer from %s",
				      req->id,
				      dcc_su2str(sustr, sizeof(sustr),
						 &recv_su));

		help_finish(gen, 1, counted, 0);
		return 1;
	}
}
#endif /* HAVE_HELPERS */
