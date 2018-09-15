
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
#ifndef __hc_tcp_conn_h
#define __hc_tcp_conn_h

#include "honeycomb.h"
#include "hc_conn.h"


/* HC_TCP_Conn structures maintain the state for a single TCP
 * connection, reassembling exchanged messages up to a limited
 * depth.
 */
typedef struct hc_tcp_conn
{
	/* Basic connection functionality: */
	HC_Conn          conn;

	/* Connection termination progress */
	uint32_t         fin;
	uint32_t         fin_back;
	char             fin_acked;
	char             fin_back_acked;

	/* We concatenate all the inbound data up to a
	 * certain limit, without caring what data got sent
	 * the other way (for pattern matching in interactive
	 * sessions).
	 */
	HC_Blob         *inbound_buffer;

} HC_TCPConn;


/**
 * hc_tcp_conn_init - initializes TCP state management.
 */
void          hc_tcp_conn_init(void);


/**
 * hc_tcp_conn_find - looks up an existing connection.
 * @src_addr: IP source address.
 * @src_port: TCP source port.
 * @dst_addr: IP source address.
 * @dst_port: TCP destination port.
 *
 * The function tries to find the connection identified through the
 * input parameters and returns it.
 * 
 * Returns: found connection or %NULL if it doesn't exist (anymore).
 */
HC_TCPConn   *hc_tcp_conn_find(ip_addr_t src_addr, uint16_t src_port,
			       ip_addr_t dst_addr, uint16_t dst_port);


/**
 * hc_tcp_conn_add - adds new connection.
 * @iphdr: IP header data.
 * @tcphdr: TCP input data.
 *
 * The function adds state for the connection defined through @iphdr
 * and @tcphdr to the connection tables, and returns a new connection.
 * If the connection already exists, nothing is done and the function
 * returns %NULL.
 *
 * Returns: new connection or %NULL if already existant.
 */
HC_TCPConn   *hc_tcp_conn_add(struct ip_hdr *iphdr, struct tcp_hdr *tcphdr);


/**
 * hc_tcp_conn_foreach - applies a callback to each TCP connection currently known.
 * @callback: callback to call.
 * @user_data: data passed to @callback.
 *
 * The function calls @callback with each TCP connection we're currently keeping
 * state for. The iteration is stopped as soon as @callback returns a value
 * greater than zero.
 */
void          hc_tcp_conn_foreach(HC_ConnCB callback, void *user_data);


/**
 * hc_tcp_conn_update_state - updates the state of a connection.
 * @conn: connection to update.
 * @iphdr: packet data to use.
 *
 * The function updates the state in @conn based on the information in
 * @iphdr (and the following TCP header), including stream reassembly etc.
 */
void          hc_tcp_conn_update_state(HC_TCPConn *conn, struct ip_hdr *iphdr);

#endif
