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
#include "hc_tcp.h"
#include "hc_tcp_conn.h"


HC_ConnTable         *tcp_conns, *tcp_conns_data;


static HC_TCPConn *
tcp_conn_new(struct ip_hdr *iphdr, struct tcp_hdr *tcphdr)
{
	HC_TCPConn *conn;
	
	if (!tcphdr)
		return NULL;

	if (! (conn = calloc(1, sizeof(HC_TCPConn)))) {
		D(("Out of memory\n"));
		return NULL;
	}
	
	if (! hc_conn_init((HC_Conn *) conn,
			   iphdr, (iphdr->ip_hl + tcphdr->th_off) << 2,
			   tcphdr->th_sport, tcphdr->th_dport,
			   hc_config.tcp_max_msg_size,
			   hc_config.tcp_max_bytes)) {

		D(("Error in connection initialization\n"));
		free(conn);
		return NULL;
	}

	/* Create our inbound data buffer: */
	conn->inbound_buffer = hc_blob_new(NULL, hc_config.tcp_max_buffering_in);
	
	return conn;
}


static void
tcp_conn_free(HC_TCPConn *conn)
{
	if (!conn)
		return;

	hc_conn_cleanup((HC_Conn *) conn);
	hc_blob_free(conn->inbound_buffer);	
	free(conn);
}


static HC_ConnTable *
tcp_conn_get_table(HC_TCPConn *conn)
{
	if (!conn)
		return NULL;

	if (hc_conn_get_bytes_exchanged((HC_Conn *) conn) > 0)
		return tcp_conns_data;

	return tcp_conns;
}


static void
tcp_conn_move_to_data_table(HC_TCPConn *conn)
{
	if (!conn)
		return;
	
	if (!hc_conn_table_remove(tcp_conns, (HC_Conn *) conn)) {
		D(("Logic error -- connection to move not part of unacked table!\n"));
		return;
	}

	hc_conn_table_insert(tcp_conns_data, (HC_Conn *) conn);
}


static int
tcp_conn_drop_check_cb(HC_Conn *conn_orig, void *user_data)
{
	HC_TCPConn *conn      = (HC_TCPConn *) conn_orig;
	HC_TCPConn *conn_test = (HC_TCPConn *) user_data;

	if (conn == conn_test)
		return 0;
	
	if (hc_tcp_equivalent((struct ip_hdr *) &conn->conn.hdr,
			      (struct ip_hdr *) &conn_test->conn.hdr)) {

		D(("Found equivalent connection, marking tested one doomed\n"));
		((HC_Conn *) conn_test)->doomed = 1;
		return 1;
	}
	
	return 0;
}

static void
tcp_conn_drop_if_duplicate(HC_TCPConn *conn)
{
	HC_ConnTable *table = tcp_conn_get_table(conn);
	
	if (!table || table == tcp_conns_data)
		return;
	
	hc_conn_table_foreach(table, tcp_conn_drop_check_cb, conn);
}


/* -- Public API, wrapping around both hashtables ---------------------- */

void          
hc_tcp_conn_init(void)
{	
	if (tcp_conns)
		return;
	
	tcp_conns = hc_conn_table_new(hc_config.conns_hash_slots,
				      hc_config.tcp_conns_max,
				      hc_config.conns_hash_cleanup_interval);
	hc_conn_table_set_free_func(tcp_conns, (HC_ConnFreeFunc) tcp_conn_free);

	tcp_conns_data = hc_conn_table_new(hc_config.conns_hash_slots,
					   hc_config.tcp_dataconns_max,
					   hc_config.conns_hash_cleanup_interval);
	hc_conn_table_set_free_func(tcp_conns_data, (HC_ConnFreeFunc) tcp_conn_free);
}


HC_TCPConn *
hc_tcp_conn_find(ip_addr_t src_addr, uint16_t src_port,
		 ip_addr_t dst_addr, uint16_t dst_port)
{	
	HC_Conn *conn;

	if ( (conn = hc_conn_table_find(tcp_conns,
					src_addr, src_port,
					dst_addr, dst_port))) {

		D(("Connection found in unacked table\n"));
		return (HC_TCPConn *) conn;
	}

	if ( (conn = hc_conn_table_find(tcp_conns_data,
					src_addr, src_port,
					dst_addr, dst_port))) {
		
		D(("Connection found in acked table\n"));
		return (HC_TCPConn *) conn;
	}

	return NULL;
}


HC_TCPConn *
hc_tcp_conn_add(struct ip_hdr *iphdr, struct tcp_hdr *tcphdr)
{
	HC_ConnID    id;
	HC_TCPConn  *conn;

	/* No need to ntohs() ports, we only hash on them. */ 
	id.src_addr = iphdr->ip_src; id.dst_addr = iphdr->ip_dst;
	id.src_port = tcphdr->th_sport; id.dst_port = tcphdr->th_dport;
	
	if ( (conn = hc_tcp_conn_find(id.src_addr, id.src_port,
				      id.dst_addr, id.dst_port))) {
		D(("Not creating new TCP connection state, already there\n"));
		return conn;
	}

	/* Connection not found, create new one, add it, and return it! */	
	if (! (conn = tcp_conn_new(iphdr, tcphdr)))
		return NULL;

	hc_conn_table_insert(tcp_conns, (HC_Conn *) conn);
	D(("Creating state for new TCP connection, new connections now %i\n",
	   hc_conn_table_get_size(tcp_conns)));
	
	return conn;
}


void         
hc_tcp_conn_foreach(HC_ConnCB callback, void *user_data)
{
	if (!callback)
		return;
	
	if (hc_conn_table_foreach(tcp_conns, callback, user_data))
		return;
	
	hc_conn_table_foreach(tcp_conns_data, callback, user_data);	
}


void          
hc_tcp_conn_update_state(HC_TCPConn *conn, struct ip_hdr *iphdr)
{
	HC_ConnID       id;
	struct tcp_hdr *tcphdr;
	u_char         *data;
	int             forward_match, header_len, data_len;
	
	if (!conn || !iphdr)
		return;		

	tcphdr = (struct tcp_hdr *) ((u_char *) iphdr + (iphdr->ip_hl << 2));

	hc_conn_update_state((HC_Conn *) conn, iphdr, tcphdr->th_sport, tcphdr->th_dport);

	header_len = (tcphdr->th_off + iphdr->ip_hl) << 2;     
	data_len = ntohs(iphdr->ip_len) - ((tcphdr->th_off + iphdr->ip_hl) << 2);
	data = (u_char *) iphdr + header_len;

	id.src_addr = iphdr->ip_src; id.src_port = tcphdr->th_sport;
	id.dst_addr = iphdr->ip_dst; id.dst_port = tcphdr->th_dport;
	forward_match = hc_conn_id_direct_match(&conn->conn.id, &id);
	
	D(("TCP packet inspection (%s, %s, %s%s%s%s)\n",
	   forward_match ? "->" : "<-", conn->conn.answered ? "acked": "new",
	   tcphdr->th_flags & TH_SYN ? "S" : "", tcphdr->th_flags & TH_ACK ? "A" : "",
	   tcphdr->th_flags & TH_FIN ? "F" : "", tcphdr->th_flags & TH_RST ? "R" : ""));

	if (data_len > 0 && hc_conn_get_bytes_exchanged((HC_Conn *) conn) == 0) {
		D(("First payload transferred, moving TCP connection to data hashtable\n"));
		tcp_conn_move_to_data_table(conn);
	}

	/* If we see a FIN, track orderly connection teardown. */
	if (tcphdr->th_flags & TH_FIN) {

		if (forward_match) {
			conn->fin = ntohl(tcphdr->th_seq) + 1;
		} else {
			conn->fin_back = ntohl(tcphdr->th_seq) + 1;
		}
	}     
	
	if (conn->fin && ! forward_match &&
	    ntohl(tcphdr->th_ack) >= conn->fin &&
	    !conn->fin_acked) {

		/* --> FIN was seen with seq x, now we see
		 * <-- ACK with ack x + 1, thus the source side shutdown
		 * is complete.
		 */
		
		D(("FIN --> acked.\n"));
		conn->fin_acked = 1;
	}
	
	if (conn->fin_back && forward_match &&
	    ntohl(tcphdr->th_ack) >= conn->fin_back &&
	    !conn->fin_back_acked) {

		/* <-- FIN was seen with seq x, now we see
		 * --> ACK with ack x + 1, thus the dest side shutdown
 		 * is complete.
		 */
		D(("FIN <-- acked.\n"));
		conn->fin_back_acked = 1;
	}

	/* Drop this connection once we see a reset or if we've completed
	 * the shutdown procedure:
	 */
	if ((tcphdr->th_flags & TH_RST) ||
	    (conn->fin_acked && conn->fin_back_acked)) {

		D(("Connection terminated.\n"));
		conn->conn.terminated = 1;
		tcp_conn_drop_if_duplicate(conn);
	}	

	if (forward_match) {
		/* We've got inbound data -- add to our inbound buffer */
		hc_blob_add_data(conn->inbound_buffer, data, data_len);
	}

	hc_conn_add_data((HC_Conn *) conn, forward_match, iphdr,
			 header_len, data, data_len);
}
