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

#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <event.h>

#include "honeycomb.h"
#include "hc_debug.h"
#include "hc_config.h"
#include "hc_bitmaps.h"
#include "hc_udp.h"
#include "hc_udp_conn.h"


/* We use two connection hashtables: udp_conns is for UDP connections
 * that are unanswered, udp_conns_data for UDP connections that have
 * seen UDP packets going in both directions. As soon as an incoming
 * UDP packet is answered with an outgoing one, a connection is moved
 * from udp_conns to udp_conns_data.
 */
HC_ConnTable         *udp_conns, *udp_conns_data;


static void
udp_conn_move_to_data_table(HC_Conn *conn)
{
	if (!conn)
		return;
	
	if (!hc_conn_table_remove(udp_conns, conn)) {
		D(("Logic error -- connection to move not part of unacked table!\n"));
		return;
	}

	hc_conn_table_insert(udp_conns_data, conn);
}


/* -- Public API, wrapping around both hashtables ---------------------- */

void          
hc_udp_conn_init(void)
{	
	if (udp_conns)
		return;
	udp_conns = hc_conn_table_new(hc_config.conns_hash_slots,
				      hc_config.udp_conns_max,
				      hc_config.conns_hash_cleanup_interval);

	udp_conns_data = hc_conn_table_new(hc_config.conns_hash_slots,
					   hc_config.udp_dataconns_max,
					   hc_config.conns_hash_cleanup_interval);
}


HC_Conn *
hc_udp_conn_find(ip_addr_t src_addr, uint16_t src_port,
		 ip_addr_t dst_addr, uint16_t dst_port)
{	
	HC_Conn *conn;

	if ( (conn = hc_conn_table_find(udp_conns,
					src_addr, src_port,
					dst_addr, dst_port))) {

		D(("Connection found in unacked table\n"));
		return conn;
	}

	if ( (conn = hc_conn_table_find(udp_conns_data,
					src_addr, src_port,
					dst_addr, dst_port))) {
		
		D(("Connection found in acked table\n"));
		return conn;
	}

	return NULL;
}


HC_Conn *
hc_udp_conn_add(struct ip_hdr *iphdr, struct udp_hdr *udphdr)
{
	HC_ConnID    id;
	HC_Conn     *conn;

	/* No need to ntohs() ports, we only hash on them. */ 
	id.src_addr = iphdr->ip_src; id.dst_addr = iphdr->ip_dst;
	id.src_port = udphdr->uh_sport; id.dst_port = udphdr->uh_dport;
	
	if ( (conn = hc_udp_conn_find(id.src_addr, id.src_port,
				      id.dst_addr, id.dst_port))) {
		D(("Not creating new UDP connection state, already there\n"));
		return conn;
	}

	/* Connection not found, create new one, add it, and return it.
	 * UDP connections are just default HC_Conns.
	 */	
	if (! (conn = hc_conn_new(iphdr, (iphdr->ip_hl << 2) + UDP_HDR_LEN,
				  id.src_port, id.dst_port,
				  hc_config.udp_max_msg_size,
				  hc_config.udp_max_bytes))) {

		D(("UDP connection creation failed.\n"));
		return NULL;
	}

	hc_conn_table_insert(udp_conns, conn);
	D(("Creating state for new UDP connection, new connections now %i\n",
	   hc_conn_table_get_size(udp_conns)));
	
	return conn;
}


void         
hc_udp_conn_foreach(HC_ConnCB callback, void *user_data)
{
	if (!callback)
		return;
	
	if (hc_conn_table_foreach(udp_conns, callback, user_data))
		return;
	
	hc_conn_table_foreach(udp_conns_data, callback, user_data);	
}


void          
hc_udp_conn_update_state(HC_Conn *conn, struct ip_hdr *iphdr)
{
	HC_ConnID       id;
	struct udp_hdr *udphdr;
	u_char         *data;
	int             forward_match, header_len, data_len;
	int             answered;
	
	if (!conn || !iphdr)
		return;		

	udphdr = (struct udp_hdr *) ((u_char *) iphdr + (iphdr->ip_hl << 2));
	
	/* UDP connection states consists of two things:
	 * - normal connection state (answered, data seen)
	 * - message buffering
	 */

	answered = conn->answered;
	hc_conn_update_state(conn, iphdr, udphdr->uh_sport, udphdr->uh_dport);

	if (!answered && conn->answered) {
		D(("UDP connection answered, moving to data hashtable\n"));
		udp_conn_move_to_data_table(conn);
	}
	
	header_len = (iphdr->ip_hl << 2) + UDP_HDR_LEN;     
	data_len = ntohs(udphdr->uh_ulen) - UDP_HDR_LEN;
	data = (u_char *) iphdr + header_len;

	if (data_len == 0)
		return;
	
	id.src_addr = iphdr->ip_src; id.src_port = udphdr->uh_sport;
	id.dst_addr = iphdr->ip_dst; id.dst_port = udphdr->uh_dport;
	forward_match = hc_conn_id_direct_match(&conn->id, &id);
	
	hc_conn_add_data(conn, forward_match, iphdr, header_len, data, data_len);
}
