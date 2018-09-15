/*

Copyright (C) 2003 Christian Kreibich <christian.kreibich@cl.cam.ac.uk>.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to
deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
sell copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies of the Software and its documentation and acknowledgment shall be
given in the documentation and software packages that this Software was
used.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

*/
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>

#include "honeycomb.h"
#include "hc_debug.h"
#include "hc_signature.h"


static HC_SigPrintFunc sig_print_func;
static uint16_t        sig_id;


void          
hc_sig_set_printer(HC_SigPrintFunc print_func)
{
	sig_print_func = print_func;
}


void          
hc_sig_print(const HC_Signature *sig, char *buf, u_int buflen)
{
	if (sig_print_func)
		sig_print_func(sig, buf, buflen);
	else
		*buf = '\0';
}


HC_Signature *
hc_sig_new(void)
{
	HC_Signature    *sig;

	sig = calloc(1, sizeof(HC_Signature));
	if (!sig) {
		D(("Out of memory\n"));
		return NULL;
	}

	hc_sig_init(sig);

	return sig;
}


void          
hc_sig_free(HC_Signature *sig)
{
	if (sig) {
		if (sig->comment)
			free(sig->comment);
		if (sig->content)
			free(sig->content);
		free(sig);
	}
}


int
hc_sig_contained(HC_Signature *sig1, HC_Signature *sig2)
{
	/* (Tests whether sig1 is contained in sig2 ...) */

	if (!sig1 || !sig2)
		return 0;

	if (sig1->proto != sig2->proto)
		return 0;

	/* sig2 must contain all checks sig1 contains: */
	if ((sig1->active & sig2->active) != sig1->active)
		return 0;

	if ((sig1->active & HC_SIG_IP_TOS) &&
	    (sig1->ip_tos != sig2->ip_tos))
		return 0;

	if ((sig1->active & HC_SIG_IP_ID) &&
	    (sig1->ip_id != sig2->ip_id))
		return 0;

	if ((sig1->active & HC_SIG_IP_TTL) &&
	    ((sig1->ip_ttl != sig2->ip_ttl) ||
	     (sig1->ip_ttl_comp != sig2->ip_ttl_comp)))
		return 0;

	if ((sig1->active & HC_SIG_IP_PROTO) &&
	    (sig1->ip_proto != sig2->ip_proto))
		return 0;
	
	if ((sig1->active & HC_SIG_IP_FLAGS) &&
	    ((sig1->ip_flags != sig2->ip_flags) ||
	     (sig1->ip_flags_mask != sig2->ip_flags_mask)))
		return 0;

	if ((sig1->active & HC_SIG_IP_FRAGOFF) &&
	    ((sig1->ip_fragoff != sig2->ip_fragoff) ||
	     (sig1->ip_fragoff_comp != sig2->ip_fragoff_comp)))
		return 0;

	if ((sig1->active & HC_SIG_IP_SRC) &&
	    ((sig1->ip_src != sig2->ip_src) ||
	     (sig1->ip_src_mask != sig2->ip_src_mask)))
		return 0;

	if ((sig1->active & HC_SIG_IP_DST) &&
	    ((sig1->ip_dst != sig2->ip_dst) ||
	     (sig1->ip_dst_mask != sig2->ip_dst_mask)))
		return 0;

	if ((sig1->active & HC_SIG_PORT_SRC) &&
	    ((sig1->port_src.val1  != sig2->port_src.val1)  ||
	     (sig1->port_src.comp1 != sig2->port_src.comp1) ||
	     (sig1->port_src.val2  != sig2->port_src.val2)  ||
	     (sig1->port_src.comp2 != sig2->port_src.comp2)))
		return 0;

	if ((sig1->active & HC_SIG_PORT_DST) &&
	    ((sig1->port_dst.val1  != sig2->port_dst.val1)  ||
	     (sig1->port_dst.comp1 != sig2->port_dst.comp1) ||
	     (sig1->port_dst.val2  != sig2->port_dst.val2)  ||
	     (sig1->port_dst.comp2 != sig2->port_dst.comp2)))
		return 0;

	if ((sig1->active & HC_SIG_TCP_FLAGS) &&
	    ((sig1->tcp_flags != sig2->tcp_flags) ||
	     (sig1->tcp_flags_mask != sig2->tcp_flags_mask)))
		return 0;

	if ((sig1->active & HC_SIG_TCP_SEQ) &&
	    (sig1->tcp_seq != sig2->tcp_seq))
		return 0;

	if ((sig1->active & HC_SIG_TCP_ACK) &&
	    (sig1->tcp_ack != sig2->tcp_ack))
		return 0;

	if ((sig1->active & HC_SIG_PAYLOAD) &&
	    ((sig1->payload != sig2->payload) ||
	     (sig1->payload_comp != sig2->payload_comp)))
		return 0;	

	if ((sig1->active & HC_SIG_CONTENT) &&
	    ((sig1->content_len > sig2->content_len) ||
	     (memcmp(sig1->content, sig2->content, MIN(sig1->content_len, sig2->content_len)))))
		return 0;
	
	return 1;
}


int           
hc_sig_equal(HC_Signature *sig1, HC_Signature *sig2)
{	
	if (!sig1 || !sig2) {
		D(("Input error\n"));
		return 0;
	}

	if (sig1->active != sig2->active) {
		return 0;
	}
	if (sig1->proto != sig2->proto)
		return 0;

	if ((sig1->active & HC_SIG_IP_TOS) &&
	    (sig1->ip_tos != sig2->ip_tos))
		return 0;

	if ((sig1->active & HC_SIG_IP_ID) &&
	    (sig1->ip_id != sig2->ip_id))
		return 0;

	if ((sig1->active & HC_SIG_IP_TTL) &&
	    ((sig1->ip_ttl != sig2->ip_ttl) ||
	     (sig1->ip_ttl_comp != sig2->ip_ttl_comp)))
		return 0;

	if ((sig1->active & HC_SIG_IP_PROTO) &&
	    (sig1->ip_proto != sig2->ip_proto))
		return 0;
	
	if ((sig1->active & HC_SIG_IP_FLAGS) &&
	    ((sig1->ip_flags != sig2->ip_flags) ||
	     (sig1->ip_flags_mask != sig2->ip_flags_mask)))
		return 0;

	if ((sig1->active & HC_SIG_IP_FRAGOFF) &&
	    ((sig1->ip_fragoff != sig2->ip_fragoff) ||
	     (sig1->ip_fragoff_comp != sig2->ip_fragoff_comp)))
		return 0;

	if ((sig1->active & HC_SIG_IP_SRC) &&
	    ((sig1->ip_src != sig2->ip_src) ||
	     (sig1->ip_src_mask != sig2->ip_src_mask)))
		return 0;

	if ((sig1->active & HC_SIG_IP_DST) &&
	    ((sig1->ip_dst != sig2->ip_dst) ||
	     (sig1->ip_dst_mask != sig2->ip_dst_mask)))
		return 0;

	if ((sig1->active & HC_SIG_PORT_SRC) &&
	    ((sig1->port_src.val1  != sig2->port_src.val1)  ||
	     (sig1->port_src.comp1 != sig2->port_src.comp1) ||
	     (sig1->port_src.val2  != sig2->port_src.val2)  ||
	     (sig1->port_src.comp2 != sig2->port_src.comp2)))
		return 0;

	if ((sig1->active & HC_SIG_TCP_FLAGS) &&
	    ((sig1->tcp_flags != sig2->tcp_flags) ||
	     (sig1->tcp_flags_mask != sig2->tcp_flags_mask)))
		return 0;

	if ((sig1->active & HC_SIG_TCP_SEQ) &&
	    (sig1->tcp_seq != sig2->tcp_seq))
		return 0;

	if ((sig1->active & HC_SIG_TCP_ACK) &&
	    (sig1->tcp_ack != sig2->tcp_ack))
		return 0;

	if ((sig1->active & HC_SIG_PAYLOAD) &&
	    ((sig1->payload != sig2->payload) ||
	     (sig1->payload_comp != sig2->payload_comp)))
		return 0;	

	if ((sig1->active & HC_SIG_CONTENT) &&
	    ((sig1->content_len != sig2->content_len) ||
	     (memcmp(sig1->content, sig2->content, MIN(sig1->content_len, sig2->content_len)))))
		return 0;

	/*
	if ((sig1->active & HC_SIG_PORT_DST) &&
	    ((sig1->port_dst.val1  != sig2->port_dst.val1)  ||
	     (sig1->port_dst.comp1 != sig2->port_dst.comp1) ||
	     (sig1->port_dst.val2  != sig2->port_dst.val2)  ||
	     (sig1->port_dst.comp2 != sig2->port_dst.comp2))) {

		D(("Not equal because dst port different\n"));
		return 0;		
	}
	*/

	return 1;
}


HC_Signature *
hc_sig_copy(const HC_Signature *sig)
{
	HC_Signature *copy;

	if (!sig)
		return NULL;

	if (! (copy = hc_sig_new())) {
		D(("Out of memory\n"));
		return NULL;
	}

	*copy = *sig;

	if (sig->comment) {
		copy->comment = strdup(sig->comment);
	}

	/* Content data must be allocated individually */
	if (sig->content) {

		copy->content = malloc(sizeof(u_char) * sig->content_len);
		if (!copy->content) {
			D(("Out of memory\n"));
			free(copy);
			return NULL;
		}

		memcpy(copy->content, sig->content, sig->content_len);
	}

	return copy;
}


void          
hc_sig_init(HC_Signature *sig)
{
	if (!sig)
		return;

	memset(sig, 0, sizeof(HC_Signature));

	sig->active = 0;
	sig->id     = sig_id++;
	sig->proto  = IP_PROTO_IP;

	/* The timeout event is used by the signature history */

	sig->timestamp = time(NULL);
}


void          
hc_sig_clear(HC_Signature *sig)
{
	if (!sig)
		return;

	if (sig->content) {
		free(sig->content);
		sig->content = NULL;
	}

	if (sig->comment) {
		free(sig->comment);
		sig->comment = NULL;
	}
}


void          
hc_sig_set_ip_hl(HC_Signature *sig, uint8_t hl)
{
	if (!sig)
		return;

	sig->ip_hl = hl;
	sig->active |= HC_SIG_IP_HL;
}


void          
hc_sig_set_ip_tos(HC_Signature *sig, uint8_t tos)
{
	if (!sig)
		return;

	sig->ip_tos = tos;
	sig->active |= HC_SIG_IP_TOS;
}


void          
hc_sig_set_ip_len(HC_Signature *sig, uint16_t len)
{
	if (!sig)
		return;

	sig->ip_len = len;
	sig->active |= HC_SIG_IP_LEN;
}


void          
hc_sig_set_ip_id(HC_Signature *sig, uint16_t id)
{
	if (!sig)
		return;

	sig->ip_id  = id;
	sig->active |= HC_SIG_IP_ID;
}


void          
hc_sig_set_ip_ttl(HC_Signature *sig, uint8_t ttl, HC_CheckType comp)
{
	if (!sig)
		return;

	sig->ip_ttl = ttl;
	sig->ip_ttl_comp = comp;
	sig->active |= HC_SIG_IP_TTL;
}


void          
hc_sig_set_ip_proto(HC_Signature *sig, uint8_t proto)
{
	if (!sig)
		return;

	sig->ip_proto = proto;
	sig->active |= HC_SIG_IP_PROTO;
}


void          
hc_sig_set_ip_flag(HC_Signature *sig, uint16_t bit, int state)
{
	if (!sig)
		return;

	switch (bit) {
	case IP_RF:
	case IP_DF:
	case IP_MF:
		break;

	default:
		return;
	}
	
	if (state)
		sig->ip_flags |= bit;
	else
		sig->ip_flags &= ~bit;
	
	sig->ip_flags_mask |= bit;
	sig->active |= HC_SIG_IP_FLAGS;
}


void          
hc_sig_set_ip_fragoffset(HC_Signature *sig, uint16_t offset, HC_CheckType comp)
{
	if (!sig)
		return;

	sig->ip_fragoff = offset;
	sig->ip_fragoff_comp = comp;
	sig->active |= HC_SIG_IP_FRAGOFF;
}


void          
hc_sig_set_ip_src(HC_Signature *sig, ip_addr_t addr, u_int netmask)
{
	if (!sig)
		return;

	sig->ip_src = addr;
	sig->ip_src_mask = netmask;
	sig->active |= HC_SIG_IP_SRC;
}


void          
hc_sig_set_ip_dst(HC_Signature *sig, ip_addr_t addr, u_int netmask)
{
	if (!sig)
		return;

	sig->ip_dst = addr;
	sig->ip_dst_mask = netmask;
	sig->active |= HC_SIG_IP_DST;
}


void          
hc_sig_set_proto(HC_Signature *sig, int proto)
{
	if (!sig)
		return;

	sig->proto = proto;
}


void          
hc_sig_set_src_port(HC_Signature *sig,
		    uint16_t port1, HC_CheckType check1,
		    uint16_t port2, HC_CheckType check2)
{
	if (!sig)
		return;

	sig->port_src.val1 = port1;
	sig->port_src.comp1 = check1;
	sig->port_src.val2 = port2;
	sig->port_src.comp2 = check2;
	sig->active |= HC_SIG_PORT_SRC;
}


void          
hc_sig_set_dst_port(HC_Signature *sig,
		    uint16_t port1, HC_CheckType check1,
		    uint16_t port2, HC_CheckType check2)
{
	if (!sig)
		return;

	sig->port_dst.val1 = port1;
	sig->port_dst.comp1 = check1;
	sig->port_dst.val2 = port2;
	sig->port_dst.comp2 = check2;
	sig->active |= HC_SIG_PORT_DST;
}


void          
hc_sig_set_orig_dports(HC_Signature *sig, uint16_t port1, uint16_t port2)
{
	if (!sig)
		return;

	sig->port_dst_orig1 = port1;
	sig->port_dst_orig2 = port2;
}


void          
hc_sig_set_tcp_flags(HC_Signature *sig, uint8_t bits, int state)
{
	if (!sig)
		return;
	
	if (state)
		sig->tcp_flags |= bits;
	else
		sig->tcp_flags &= ~bits;
	
	sig->tcp_flags_mask |= bits;
	sig->active |= HC_SIG_TCP_FLAGS;
}


void
hc_sig_set_tcp_seq(HC_Signature *sig, uint32_t seq)
{
	if (!sig)
		return;

	sig->tcp_seq = seq;
	sig->active |= HC_SIG_TCP_SEQ;
}


void
hc_sig_set_tcp_ack(HC_Signature *sig, uint32_t ack)
{
	if (!sig)
		return;

	sig->tcp_ack = ack;
	sig->active |= HC_SIG_TCP_ACK;
}


void          
hc_sig_set_tcp_est(HC_Signature *sig)
{
	if (!sig)
		return;

	sig->active |= HC_SIG_TCP_EST;
}


void
hc_sig_set_payload_size(HC_Signature *sig, u_int size, HC_CheckType check)
{
	if (!sig)
		return;

	sig->payload = size;
	sig->payload_comp = check;
	sig->active |= HC_SIG_PAYLOAD;
}


void          
hc_sig_set_content(HC_Signature *sig, u_char *data, u_int data_len)
{
	u_char *data_copy;

	if (!sig || !data || data_len == 0)
		return;

	if (! (data_copy = malloc(sizeof(u_char) * data_len))) {
		D(("Out of memory\n"));
		return;
	}

	if (sig->content)
		free(sig->content);

	memcpy(data_copy, data, sizeof(u_char) * data_len);
	sig->content = data_copy;
	sig->content_len = data_len;
	sig->active |= HC_SIG_CONTENT;
}


void          
hc_sig_add_comment(HC_Signature *sig, u_char *comment)
{
	if (!sig || !comment || !*comment)
		return;

	if (!sig->comment)
		sig->comment = strdup(comment);
	else {
		int old_len, new_len;
	
		old_len = strlen(sig->comment);
		new_len = strlen(comment);

		sig->comment = realloc(sig->comment, old_len + new_len + 3);
		
		sig->comment[old_len] = ';';
		sig->comment[old_len + 1] = ' ';
		memcpy(&sig->comment[old_len + 2], comment, new_len);
		sig->comment[old_len + new_len + 2] = '\0';
	}	
}

