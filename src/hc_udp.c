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
#include "hc_signature_hist.h"
#include "hc_string_alg.h"
#include "hc_ip.h"
#include "hc_udp.h"
#include "hc_udp_conn.h"

typedef struct hc_udp_cb_data
{
	HC_Conn         *conn;
	struct ip_hdr   *iphdr;

} HC_UDP_CBData;

static HC_Bitmap        *udp_mask_map;
static struct udp_hdr   *udp_mask;


static int
udp_analyze_headers(const struct ip_hdr *iphdr_old,
		    const struct ip_hdr *iphdr_new,
		    HC_Signature *sig)
{
	struct udp_hdr *udphdr_old, *udphdr_new;
	int result;

	udphdr_old = (struct udp_hdr*) ((u_char *) iphdr_old + (iphdr_old->ip_hl << 2));
	udphdr_new = (struct udp_hdr*) ((u_char *) iphdr_new + (iphdr_new->ip_hl << 2));
	
	result = hc_ip_analyze(iphdr_new, iphdr_old, sig);

	hc_sig_set_proto(sig, IP_PROTO_UDP);

	hc_blob_get_mask((u_char*) udphdr_old, UDP_HDR_LEN,
			 (u_char*) udphdr_new, UDP_HDR_LEN,
			 (u_char*) udp_mask, UDP_HDR_LEN);	
	
	/* We detect matching destination ports as we want to know what is being
	 * connected to. We also want to know when dst port is 0.
	 */
	/*
	if (udp_mask->uh_dport == USHRT_MAX || udphdr_new->uh_dport == 0) {

		D(("UDP dst port match found, or 0\n"));
		hc_sig_set_dst_port(sig,
				    ntohs(udphdr_new->uh_dport), HC_COMP_EQ,
				    0, HC_COMP_NA);
		result++;
	}
	*/

	/* Remember the destination ports of the two connections in any case,
	 * so we can potentially do portscan analysis.
	 */
	hc_sig_set_orig_dports(sig,
			       ntohs(udphdr_new->uh_dport),
			       ntohs(udphdr_old->uh_dport));

	/* We also register source port 0, and the source port if there's a
	 * match and it's not ephemeral. Other things would be feasible, like
	 * always register src port when there's a match, but only if the
	 * destination port is a match as well ... mhm.
	 */
	if (((udp_mask->uh_sport == USHRT_MAX) && (ntohs(udphdr_new->uh_sport) < 1024)) ||
	    (udphdr_new->uh_sport == 0)) {

		D(("UDP src port match found, or not ephemeral\n"));
		hc_sig_set_src_port(sig,
				    ntohs(udphdr_new->uh_sport), HC_COMP_EQ,
				    0, HC_COMP_NA);		
		result++;
	}
	
	return result;
}


static int
udp_conn_headercheck_cb(HC_Conn *conn_old, HC_UDP_CBData *cb_data)
{
	HC_Signature sig;

	D(("--- UDP header check\n"));	

	hc_sig_init(&sig);

	if (udp_analyze_headers(cb_data->iphdr, (struct ip_hdr *) &conn_old->hdr, &sig) > 0)
		hc_sighist_insert(&sig);
	
	hc_sig_clear(&sig);
	return 0;
}


static int
udp_conn_fullcheck_cb(HC_Conn *conn_old, HC_UDP_CBData *cb_data)
{
	HC_Blob *message_old, *message_new;
	HC_Signature sig;
	struct ip_hdr *iphdr, *iphdr_old;
	u_int message_num;
	LST_String *pattern;

	if (conn_old->key == cb_data->conn->key)
		return 0;

	if (conn_old->id.dst_port != cb_data->conn->id.dst_port)
		return 0;

 	D(("--- Thorough check against old UDP connection\n"));

	iphdr = (struct ip_hdr *) &cb_data->conn->hdr;

	/* Find out the message number the new data represents. */
	if ( (message_num = hc_conn_get_num_messages((HC_Conn *) cb_data->conn)) == 0) {
		D(("No messages in old connection, aborting.\n"));
		return 0;
	}

	message_old = hc_conn_get_nth_message(conn_old, message_num - 1);
	
	if (!message_old) {
		
		/* The connection we're checking against doesn't have
		 * enough exchanged messages, so we don't do anything.
		 */
		D(("Not enough messages in old connection, aborting.\n"));
		return 0;
	}
	
	iphdr_old = hc_conn_get_nth_message_header(conn_old, message_num - 1);
	D_ASSERT_PTR(iphdr_old);
	
	message_new = hc_conn_get_nth_message(cb_data->conn, message_num - 1);
	D_ASSERT_PTR(message_new);

	D(("Attempting pattern match on UDP stream message %u\n", message_num));
	hc_sig_init(&sig);

	/* Now look for a match within those messages: */		
	if ( (pattern = hc_string_alg_lcs(message_old->data, message_old->data_used,
					  message_new->data, message_new->data_used,
					  hc_config.udp_pattern_minlen))) {

		D(("UDP substring found: '%s'\n", lst_string_print(pattern)));
		hc_sig_set_content(&sig, pattern->data,
				   lst_string_get_length(pattern));
		lst_string_free(pattern);
		
		udp_analyze_headers(cb_data->iphdr, iphdr_old, &sig);
		hc_sighist_insert(&sig);
	}

	hc_sig_clear(&sig);
	return 0;
}


void udp_hook(u_char *packet_data, u_int packet_len, void *user_data)
{
	HC_Conn        *conn;
	struct ip_hdr  *iphdr;
	struct udp_hdr *udphdr;
	HC_UDP_CBData   cb_data;

	D(("UDP packet inspection ------------------------\n"));

	iphdr  = (struct ip_hdr *) packet_data;
	udphdr = (struct udp_hdr *) (packet_data + (iphdr->ip_hl << 2));

	memset(&cb_data, 0, sizeof(HC_UDP_CBData));
	cb_data.iphdr = iphdr;
	cb_data.conn  = NULL;

	if (! (conn = hc_udp_conn_find(iphdr->ip_src, udphdr->uh_sport,
				       iphdr->ip_dst, udphdr->uh_dport))) {

		//if (user_data == (void*) HD_OUTGOING)
		//	return;

		/* We have a new connection. For the first packet in
		 * a connection we do our header field analysis consisting
		 * of sanity checks and matchings with the first packets
		 * of the  other connections we currently keep state for.
		 */
		hc_udp_conn_foreach((HC_ConnCB) udp_conn_headercheck_cb, &cb_data);

		if ( (conn = hc_udp_conn_add(iphdr, udphdr)))
			hc_udp_conn_update_state(conn, iphdr);	
	} else {

		hc_udp_conn_update_state(conn, iphdr);

		//if (user_data == (void*) HD_OUTGOING)
		//	return;

		if (conn->bytes_seen == 0 && conn->bytes_seen_reversed == 0) {

			hc_udp_conn_foreach((HC_ConnCB) udp_conn_headercheck_cb, &cb_data);

		} else if (ntohs(udphdr->uh_ulen) - UDP_HDR_LEN > 0) {
			
			/* For each current UDP connections, try to find the
			 * corresponding message and analyze:
			 */
			cb_data.conn = conn;
			cb_data.iphdr = iphdr;
			hc_udp_conn_foreach((HC_ConnCB) udp_conn_fullcheck_cb, &cb_data);
		}				
	}
}


void
hc_udp_init(void)
{
	udp_mask_map = hc_bitmap_new(UDP_HDR_LEN);
	udp_mask = (struct udp_hdr *) udp_mask_map->blobs.tqh_first->data;
		
//	hooks_add_packet_hook(IP_PROTO_UDP, HD_INCOMING, udp_hook, (void *) HD_INCOMING);

	/* We also look at outgoing traffic for connection state tracking */
//	hooks_add_packet_hook(IP_PROTO_UDP, HD_OUTGOING, udp_hook, (void *) HD_OUTGOING);
}
