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

#include <sys/types.h>
#include <honeyd/hooks.h>
#include "honeycomb.h"
#include "hc_debug.h"
#include "hc_config.h"
#include "hc_string_alg.h"
#include "hc_ip.h"
#include "hc_tcp_conn.h"
#include "hc_signature_hist.h"
#include "hc_tcp.h"


#define HC_TCP_ALLFLAGS     (TH_FIN|TH_SYN|TH_RST|TH_PUSH|TH_ACK|TH_URG)

typedef struct hc_tcp_cb_data
{
	HC_TCPConn      *conn;
	struct ip_hdr   *iphdr;
	char             first_packet;

} HC_TCP_CBData;

static HC_Bitmap        *tcp_mask_map;
static struct tcp_hdr   *tcp_mask;

static int       
tcp_analyze_headers(const struct ip_hdr *iphdr,
		    const struct ip_hdr *iphdr_old,
		    HC_Signature *sig,
		    int first_packet)
{
	struct tcp_hdr *tcphdr, *tcphdr_old;
	int result, payload_len;
	
	tcphdr = (struct tcp_hdr *) ((u_char*) iphdr + (iphdr->ip_hl << 2));
	payload_len = ntohs(iphdr->ip_len) - ((tcphdr->th_off + iphdr->ip_hl) << 2);

	/* Do IP header checks/matchings first: */
	result = hc_ip_analyze(iphdr, iphdr_old, sig);

	hc_sig_set_proto(sig, IP_PROTO_TCP);
	
	/* Now also look at TCP header: */
	if ((tcphdr->th_flags & TH_SYN) != 0) {

		/* Can't have SYN and RST set -- report! */
		if ((tcphdr->th_flags & TH_RST) != 0) {

			D(("TCP SYN & RST\n"));
			hc_sig_set_tcp_flags(sig, TH_SYN|TH_RST, 1);
			result++;
		}

		/* SYN and FIN is at least quite weird ... */
		if ((tcphdr->th_flags & TH_FIN) != 0) {

			D(("TCP SYN & FIN\n"));
			hc_sig_set_tcp_flags(sig, TH_SYN|TH_FIN, 1);
			result++;
		}

		/* If SYN is set and we have payload that's weird as well. */
		if (payload_len > 0) {

			D(("TCP SYN & payload\n"));
			hc_sig_set_tcp_flags(sig, TH_SYN, 1);
			hc_sig_set_payload_size(sig, 0, HC_COMP_GT);
			result++;
		}
	}
	
	/* FIN and RST are illegal: */
	if ((tcphdr->th_flags & TH_FIN) != 0 &&
	    (tcphdr->th_flags & TH_RST) != 0) {

		D(("TCP FIN & RST\n"));
		hc_sig_set_tcp_flags(sig, TH_SYN|TH_RST, 1);
		result++;
	}

	/* Can't have a PUSH with no data: */
	if ((tcphdr->th_flags & TH_PUSH) != 0 &&
	    payload_len == 0                  &&
	    (tcphdr->th_flags & TH_FIN)  == 0 &&
	    (tcphdr->th_flags & TH_RST)  == 0) {

		D(("TCP PUSH & no data\n"));
		hc_sig_set_tcp_flags(sig, TH_PUSH, 1);
		hc_sig_set_payload_size(sig, 0, HC_COMP_GT);
		result++;
	}

	/* All common flags cleared or set: */
	if ((tcphdr->th_flags & HC_TCP_ALLFLAGS) == 0) {

		D(("TCP flags cleared\n"));
		hc_sig_set_tcp_flags(sig, HC_TCP_ALLFLAGS, 0);
		result++;
	}
	if ((tcphdr->th_flags & HC_TCP_ALLFLAGS) == HC_TCP_ALLFLAGS) {

		D(("TCP flags all set\n"));
		hc_sig_set_tcp_flags(sig, HC_TCP_ALLFLAGS, 1);
		result++;
	}
	
	/* Oh this is cool. Since we're inside Honeyd we *know* that we see the
	 * beginning of all TCP connections, in contrast to the cold
	 * start issues that you have when starting TCP-statekeeping applications
	 * on an already running system. So we know that if no SYN is on our
	 * initial packet, things are not as they should be.
	 */
	if (first_packet) {

		if ((tcphdr->th_flags & TH_SYN) == 0) { 

			D(("TCP no SYN on first packet\n"));
			hc_sig_set_tcp_flags(sig, TH_SYN, 0);
			result++;

			if ((tcphdr->th_flags & TH_FIN)) {
				hc_sig_set_tcp_flags(sig, TH_FIN, 1);
				result++;
			} 
			if ((tcphdr->th_flags & TH_RST)) {
				hc_sig_set_tcp_flags(sig, TH_RST, 1);
				result++;
			} 
		}

		if (tcphdr->th_ack != 0) {

			D(("TCP ack value not zero on first packet\n"));
			hc_sig_set_tcp_ack(sig, ntohl(tcphdr->th_ack));
			result++;
		}		
	} else {
		
		hc_sig_set_tcp_est(sig);

		/* We must have an ACK on everything except the first packet. */
		if ((tcphdr->th_flags & TH_ACK) == 0) {

			D(("TCP no ack on nonfirst packet\n"));
			hc_sig_set_tcp_flags(sig, TH_ACK, 0);
			result++;
		}
	}

	/* Now, we also want to do pattern checks on appropriate header
	 * fields if we are given two headers we can compare.
	 */
	if (! iphdr_old)
		return result;

	tcphdr_old = (struct tcp_hdr *) ((u_char*) iphdr_old + (iphdr_old->ip_hl << 2));
	
	hc_blob_get_mask((u_char*) tcphdr_old, tcphdr_old->th_off << 2,
			 (u_char*) tcphdr, tcphdr->th_off << 2,
			 (u_char*) tcp_mask, TCP_HDR_LEN_MAX);
	
	/* See what TCP header flags match, and signal accordingly: */
	if ((tcp_mask->th_flags & TH_SYN)) {
		hc_sig_set_tcp_flags(sig, TH_SYN, (tcphdr->th_flags & TH_SYN));
	}
	if ((tcp_mask->th_flags & TH_ACK)) {
		hc_sig_set_tcp_flags(sig, TH_ACK, (tcphdr->th_flags & TH_ACK));
	}
	if ((tcp_mask->th_flags & TH_FIN)) {
		hc_sig_set_tcp_flags(sig, TH_FIN, (tcphdr->th_flags & TH_FIN));
	}
	if ((tcp_mask->th_flags & TH_PUSH)) {
		hc_sig_set_tcp_flags(sig, TH_PUSH, (tcphdr->th_flags & TH_PUSH));
	}
	if ((tcp_mask->th_flags & TH_RST)) {
		hc_sig_set_tcp_flags(sig, TH_RST, (tcphdr->th_flags & TH_RST));
	}
	if ((tcp_mask->th_flags & TH_ECE)) {
		hc_sig_set_tcp_flags(sig, TH_ECE, (tcphdr->th_flags & TH_ECE));
	}
	if ((tcp_mask->th_flags & TH_CWR)) {
		hc_sig_set_tcp_flags(sig, TH_CWR, (tcphdr->th_flags & TH_CWR));
	}
	if ((tcp_mask->th_flags & TH_URG)) {
		hc_sig_set_tcp_flags(sig, TH_URG, (tcphdr->th_flags & TH_URG));
	}
	
	
	/* We detect matching destination ports as we want to know what is being
	 * connected to. We also want to know when dst port is 0.
	 */
	/*
	if (tcp_mask->th_dport == USHRT_MAX || tcphdr->th_dport == 0) {

		D(("TCP dst port match found (%i), or 0\n",
		   (tcp_mask->th_dport == USHRT_MAX ? ntohs(tcphdr->th_dport) : -1)));
		hc_sig_set_dst_port(sig,
				    ntohs(tcphdr->th_dport), HC_COMP_EQ,
				    0, HC_COMP_NA);
		result++;
	}
	*/

	/* Remember the destination ports of the two connections in any case,
	 * so we can potentially do portscan analysis.
	 */
	hc_sig_set_orig_dports(sig,
			       ntohs(tcphdr->th_dport),
			       ntohs(tcphdr_old->th_dport));

	/* We also register source port 0, and the source port if there's a
	 * match and it's not ephemeral. More could be done here, look at the same
	 * spot in hc_udp.c.
	 */
	if (((tcp_mask->th_sport == USHRT_MAX) && (ntohs(tcphdr->th_sport) < 1024)) ||
	    (tcphdr->th_sport == 0)) {

		D(("TCP src port match found, or not ephemeral\n"));
		hc_sig_set_src_port(sig,
				    ntohs(tcphdr->th_sport), HC_COMP_EQ,
				    0, HC_COMP_NA);		
		result++;
	}


	/* Currently no TCP sequence number matching */

	if (tcp_mask->th_ack == UINT_MAX && tcphdr->th_ack != 0) {

		D(("TCP ack# match found and ack# != 0\n"));
		hc_sig_set_tcp_ack(sig, ntohl(tcphdr->th_ack));
		result++;
	}

	return result;
}


static int
tcp_conn_headercheck_cb(HC_Conn *conn, HC_TCP_CBData *cb_data)
{
	HC_Signature sig;

	D(("--- TCP header check\n"));	
	hc_sig_init(&sig);

	if (tcp_analyze_headers(cb_data->iphdr,
				(struct ip_hdr*) &conn->hdr,
				&sig, cb_data->first_packet) > 0) {
		
		hc_sighist_insert(&sig);
	}

	hc_sig_clear(&sig);
	return 0;
}



static int
tcp_conn_fullcheck_cb(HC_TCPConn *conn_old, HC_TCP_CBData *cb_data)
{
	HC_Blob *blob_old, *blob_new;
	HC_Signature sig;
	struct ip_hdr *iphdr, *iphdr_old;
	u_int message_num;
	LST_String *pattern;
		
	if (conn_old->conn.key == cb_data->conn->conn.key)
		return 0;

	if (conn_old->conn.id.dst_port != cb_data->conn->conn.id.dst_port)
		return 0;

 	D(("--- Thorough check against old TCP connection\n"));

	iphdr = (struct ip_hdr *) &cb_data->conn->conn.hdr;
			
	/* Find out the message number the new data represents. */
	if ( (message_num = hc_conn_get_num_messages((HC_Conn *) cb_data->conn)) == 0) {
		D(("No messages in old connection, aborting.\n"));
		return 0;
	}
	     
	blob_old = hc_conn_get_nth_message((HC_Conn *) conn_old, message_num - 1);
	
	if (!blob_old) {
		
		/* The connection we're checking against doesn't have
		 * enough exchanged messages, so we don't do anything.
		 */
		D(("Not enough messages in old connection, aborting.\n"));
		return 0;
	}

	iphdr_old = hc_conn_get_nth_message_header((HC_Conn *) conn_old, message_num - 1);
	D_ASSERT_PTR(iphdr_old);
	
	blob_new = hc_conn_get_nth_message((HC_Conn *) cb_data->conn, message_num - 1);
	D_ASSERT_PTR(blob_new);

	D(("Attempting pattern match on TCP stream message %u\n", message_num));
	hc_sig_init(&sig);
	
	/* Now look for a match within those messages: */		
	if ( (pattern = hc_string_alg_lcs(blob_old->data, blob_old->data_used,
					  blob_new->data, blob_new->data_used,
					  hc_config.tcp_pattern_minlen))) {

		D(("TCP substring found: '%s'\n", lst_string_print(pattern)));
		hc_sig_set_content(&sig, pattern->data,
				   lst_string_get_length(pattern));
		lst_string_free(pattern);
		
		/* Just compare IP addresses and ports for now, we
		 * could do better here ... FIXME.
		 */
		tcp_analyze_headers(cb_data->iphdr, iphdr_old, &sig, 0);
		hc_sighist_insert(&sig);
	}

	hc_sig_clear(&sig);

	if (hc_blob_is_full(cb_data->conn->inbound_buffer))
		return 0;

	D(("Attempting pattern match on TCP inbound buffers.\n"));
	hc_sig_init(&sig);
	
	if ( (pattern = hc_string_alg_lcs(cb_data->conn->inbound_buffer->data,
					  cb_data->conn->inbound_buffer->data_used,
					  conn_old->inbound_buffer->data,
					  conn_old->inbound_buffer->data_used,
					  hc_config.tcp_pattern_minlen))) {
		
		D(("TCP substring found: '%s'\n", lst_string_print(pattern)));
		hc_sig_set_content(&sig, pattern->data,
				   lst_string_get_length(pattern));
		lst_string_free(pattern);
		
		/* Just compare IP addresses and ports for now, we
		 * could do better here ... FIXME.
		 */
		tcp_analyze_headers(cb_data->iphdr, iphdr_old, &sig, 0);
		hc_sighist_insert(&sig);
		
	}

	hc_sig_clear(&sig);
	return 0;
}


void
tcp_hook(u_char *packet_data, u_int packet_len, void *user_data)
{
	HC_TCPConn *conn;
	struct ip_hdr  *iphdr;
	struct tcp_hdr *tcphdr;
	HC_TCP_CBData cb_data;

	D(("TCP packet -------------------------------------------\n"));

	iphdr  = (struct ip_hdr *) packet_data;
	tcphdr = (struct tcp_hdr *) (packet_data + (iphdr->ip_hl << 2));

	memset(&cb_data, 0, sizeof(HC_TCP_CBData));
	cb_data.iphdr = iphdr;
	cb_data.first_packet = 1;
	cb_data.conn = NULL;
		
	if (! (conn = hc_tcp_conn_find(iphdr->ip_src, tcphdr->th_sport,
				       iphdr->ip_dst, tcphdr->th_dport))) {

		//if (user_data == (void*) HD_OUTGOING)
		//	return;

		/* We have a new connection. For the first packet in
		 * a connection we do our header field analysis consisting
		 * of sanity checks and matchings with the first packets
		 * of the  other connections we currently keep state for.
		 */
		hc_tcp_conn_foreach((HC_ConnCB) tcp_conn_headercheck_cb, &cb_data);

		/* If the packet doesn't contain a RST, create new state
		 * for the connection:
		 */
		if ((tcphdr->th_flags & TH_RST) == 0) {
			
			if ( (conn = hc_tcp_conn_add(iphdr, tcphdr)))
				hc_tcp_conn_update_state(conn, iphdr);	
		}
		
	} else {

		/* For existing connections we first check if we've seen data going
		 * in both directions. If not, we only do header matching as these
		 * are likely to be handshakes or weird probe packets. Otherwise,
		 * we do sanity checks in the  headers and pattern detection in the
		 * payloads, matching up messages across different flows.
		 * If and only if we spot a pattern, we also do header matching to
		 * potentially get a better signature. Phew, complicated.
		 */
		
		hc_tcp_conn_update_state(conn, iphdr);

		//if (user_data == (void*) HD_OUTGOING)
		//	return;

		if (! conn->conn.answered) {

			hc_tcp_conn_foreach((HC_ConnCB) tcp_conn_headercheck_cb, &cb_data);

		} else if (ntohs(iphdr->ip_len) - ((tcphdr->th_off + iphdr->ip_hl) << 2) > 0) {
			
			/* In all memorized TCP flows, try to find the corresponding
			 * message and analyze:
			 */
			cb_data.conn = conn;
			cb_data.iphdr = iphdr;
			hc_tcp_conn_foreach((HC_ConnCB) tcp_conn_fullcheck_cb, &cb_data);
		}		
	}		
}


void
hc_tcp_init(void)
{
	tcp_mask_map = hc_bitmap_new(TCP_HDR_LEN_MAX);
	tcp_mask = (struct tcp_hdr *) tcp_mask_map->blobs.tqh_first->data;

//	hooks_add_packet_hook(IP_PROTO_TCP, HD_INCOMING, tcp_hook, (void*) HD_INCOMING);

	/* We also look at outgoing traffic for connection state tracking */
//	hooks_add_packet_hook(IP_PROTO_TCP, HD_OUTGOING, tcp_hook, (void*) HD_OUTGOING);
}


int       
hc_tcp_equivalent(const struct ip_hdr *iphdr1,
		  const struct ip_hdr *iphdr2)
{
	struct tcp_hdr *tcphdr1, *tcphdr2;

	if (!iphdr1 || !iphdr2)
		return 0;

	if (iphdr1->ip_p != IP_PROTO_TCP || 
	    iphdr2->ip_p != IP_PROTO_TCP)
		return 0;

	if (! hc_ip_equivalent(iphdr1, iphdr2)) {
		D(("Not equivalent at IP level\n"));
		return 0;
	}

	tcphdr1 = (struct tcp_hdr *) ((u_char*) iphdr1 + (iphdr1->ip_hl << 2));
	tcphdr2 = (struct tcp_hdr *) ((u_char*) iphdr2 + (iphdr2->ip_hl << 2));

	if (tcphdr1->th_off != tcphdr2->th_off)
		return 0;
	if (tcphdr1->th_x2 != tcphdr2->th_x2)
		return 0;
	if (tcphdr1->th_flags != tcphdr2->th_flags)
		return 0;

	D(("TCP header equivalence\n"));

	return 1;
}

