/*-
 * Copyright (c) 2014 Semihalf
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#include <sys/types.h>
#include <sys/malloc.h>
#include <sys/protosw.h>
#include <sys/domain.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sockbuf.h>
#include <sys/uio.h>
#include <sys/proc.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <net/raw_cb.h>
#include <netinet/in.h>

#include "vr_freebsd.h"

static void
tf_abort(struct socket *so)
{

	soisdisconnected(so);
}

static void
tf_close(struct socket *so)
{

	soisdisconnected(so);
}

static int
tf_attach(struct socket *so, int proto, struct thread *td)
{
	int ret;

	ret = soreserve(so, VR_SOCK_SEND_BUFF_SIZE, VR_SOCK_RECV_BUFF_SIZE);
	if (ret) {
		vr_log(VR_ERR, "raw attach failed:%d\n", ret);
		return (ret);
	}

	so->so_fibnum = td->td_proc->p_fibnum;

	soisconnected(so);

	return (0);
}

static int
tf_connect(struct socket *so, struct sockaddr *nam, struct thread *td)
{

	return (EINVAL);
}

static void
tf_detach(struct socket *so)
{

	return;
}

static int
tf_disconnect(struct socket *so)
{

	return (EINVAL);
}

static int
tf_send(struct socket *so, int flags, struct mbuf *m,
    struct sockaddr *nam, struct mbuf *control, struct thread *td)
{

	return ((*so->so_proto->pr_output)(m, so));
}

static int
tf_shutdown(struct socket *so)
{

	socantsendmore(so);
	return (0);
}

static struct domain tf_domain;

static struct pr_usrreqs tf_usrreqs = {
	.pru_abort =		tf_abort,
	.pru_attach =		tf_attach,
	.pru_connect =		tf_connect,
	.pru_detach =		tf_detach,
	.pru_disconnect =	tf_disconnect,
	.pru_send =		tf_send,
	.pru_soreceive =	soreceive_dgram,
	.pru_sosend =		sosend_dgram,
	.pru_shutdown =		tf_shutdown,
	.pru_close =		tf_close,
};

static int
tf_output(struct mbuf *m, struct socket *so)
{
	char *buf;
	int len;
	int ret;

	KASSERT((m && so), ("Incorrect parameters:m:%p so:%p", m, so));

	len = m_length(m, NULL);
	/* If contiguous space in mbuf it can be passed directly */
	if (m->m_len == len) {
		ret = vr_transport_request(so, mtod(m, char *), len);
		if (ret) {
			vr_log(VR_ERR, "Transport request failed, ret:%d\n",
			    ret);
		}
	} else {
		/* Prepare buffer for transport layer */
		buf = malloc(len, M_VROUTER, M_NOWAIT|M_ZERO);
		if (!buf) {
			vr_log(VR_ERR, "Cannot allocate buffer\n");
			m_freem(m);
			return (-1);
		}

		m_copydata(m, 0, len, buf);

		/* Pass buffer to decoder */
		ret = vr_transport_request(so, buf, len);
		if (ret) {
			vr_log(VR_ERR, "Transport request failed, ret:%d\n",
			    ret);
		}
		free(buf, M_VROUTER);
	}

	m_freem(m);

	return (ret);
}

static struct protosw tfsw[2] = {
{
	.pr_type =		SOCK_DGRAM,
	.pr_domain =		&tf_domain,
	.pr_flags =		PR_ATOMIC,
	.pr_output =		tf_output,
	.pr_usrreqs =		&tf_usrreqs
},
{
	.pr_type =		SOCK_RAW,
	.pr_domain =		&tf_domain,
	.pr_flags =		PR_ATOMIC,
	.pr_output =		tf_output,
	.pr_usrreqs =		&tf_usrreqs
},
};

static struct domain tf_domain = {
	.dom_family =		AF_VENDOR00,
	.dom_name =		"contrail",
	.dom_protosw =		tfsw,
	.dom_protoswNPROTOSW =
	    &tfsw[sizeof(tfsw)/sizeof(tfsw[0])],
};

int
tf_socket_init(void)
{

	domain_add((void *)&tf_domain);
	return (0);
}

void
tf_socket_destroy(void)
{
	struct domain *dp, *prev = NULL;

	/* TODO: make locking/unlocking of dom_mtx public in BSD */
	for (dp = domains; dp != NULL; prev = dp, dp = dp->dom_next)
		if (dp->dom_family == AF_VENDOR00) {
			if (!prev) {
				domains = dp->dom_next;
			} else {
				prev->dom_next = dp->dom_next;
			}
		}

	return;
}
