
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
#ifndef __hc_conn_h
#define __hc_conn_h

#include "honeycomb.h"
#include "hc_bitmaps.h"


/* This structure identifies a network connection through IP src
 * and dst addresses and port pairs.
 */
typedef struct hc_conn_id
{
	ip_addr_t        src_addr;
	uint16_t         src_port;
	
	ip_addr_t        dst_addr;
	uint16_t         dst_port;
	
} HC_ConnID;


typedef struct hc_conn_table HC_ConnTable;


/* HC_Conn structures identify a connection and reassemble
 * exchanged data up to a limited depth.
 */
typedef struct hc_conn
{
	TAILQ_ENTRY(hc_conn) conns;

	/* The table this connection is stored in */
	HC_ConnTable    *table;

	/* Connection identifier */
	HC_ConnID        id;

	/* Each connection gets a unique key
	 * assigned when created:
	 */
	int              key;

	/* We remember the header of the first packet in a connection 
	 */
	char             hdr[IP_HDR_LEN_MAX + TCP_HDR_LEN_MAX];

	/* Is connection terminated? */
	char             terminated;

	/* Is connection about to be dropped? */
	char             doomed;

	/* Have packets been exchanged in both directions? */
	char             answered;

	/* Reassembled stream data. We use one bitmap
	 * for real stream data, where each blob consists
	 * of data flowing in one direction without real data
	 * flowing the other way (other than acks).
	 *
	 * We separately keep the headers of the first
	 * chunk of new messages around, for pattern matching
	 * in those header fields.
	 */
	HC_Bitmap       *stream;
	HC_Bitmap       *stream_headers;
	int              stream_reversed;
	
	u_int            bytes_seen;
	u_int            bytes_seen_reversed;
	u_int            bytes_max;

	/* Largest individual message size allowed */
	u_int            max_msg_size;
	
	/* Arbitrary other data, for example used by TCP connections
	 * for state management.
	 */
	void            *user_data;

} HC_Conn;


typedef int  (*HC_ConnCB) (HC_Conn *conn, void *user_data);
typedef void (*HC_ConnFreeFunc) (HC_Conn *conn);

/* -- Connection Identifiers ------------------------------------------- */

/**
 * hc_conn_id_direct_match - checks for identical connection identifiers.
 * @id1: first connection.
 * @id2: second connection.
 *
 * The function checks whether the connection identifiers match directly
 * (i.e. have the same source IP + port and destination IP + port).
 *
 * Returns: value > 0 if identifiers match, 0 otherwise.
 */
int hc_conn_id_direct_match(HC_ConnID *id1, HC_ConnID *id2);


/**
 * hc_conn_id_reverse_match - checks for reversely-matching connection identifiers.
 * @id1: first_connection.
 * @id2: second connection.
 *
 * The function checks whether the connections match reversely
 * (i.e. source IP + port of one identifier are destination IP + port
 * of the other, and vice versa).
 *
 * Returns: value > 0 if identifiers match, 0 otherwise.
 */
int hc_conn_id_reverse_match(HC_ConnID *id1, HC_ConnID *id2);


/**
 * hc_conn_id_equal - check whether two connection identifiers represent the same connection.
 * @id1: first_connection.
 * @id2: second connection.
 *
 * The function checks whether @id1 and @id2 represent the same connection
 * (i.e. whether they match either directly or reversely).
 *
 * Returns: value > 0 if identifiers represent same connection, otherwise.
 */
int hc_conn_id_equal(HC_ConnID *id1, HC_ConnID *id2);



/* -- Connection Hashtables -------------------------------------------- */


/**
 * hc_conn_table_new - creates a new connection hashtable.
 * @num_slots: number of slots in table.
 * @max_conns: maximum number of connections stored in table.
 * @cleanup_interval: number of seconds between checks for dead connections.
 *
 * The function allocates and returns a new connection with @num_slots
 * overflow chains and @max_conns maximum entries that gets scanned every
 * @cleanup_interval seconds for dead connections.
 *
 * Returns: new table, or %NULL when an error occurred.
 */
HC_ConnTable *hc_conn_table_new(u_int num_slots, u_int max_conns, u_int cleanup_interval);


/**
 * hc_conn_table_set_free_func - sets new connection destructor.
 * @table: connection hashtable.
 * @free_func: connection destructor.
 *
 * Wannabe-OO'R'Us :) You can replace the default connection destructor with
 * another one using this function. See hc_tcp_conn.h for a case where this
 * makes sense.
 */
void hc_conn_table_set_free_func(HC_ConnTable *table, HC_ConnFreeFunc free_func);


/**
 * hc_conn_table_insert - inserts a connection into the table.
 * @table: hashtable to insert into.
 * @conn: connection to insert.
 *
 * The function inserts @conn into @table without checking whether it
 * is already contained. If the maximum number of connections for
 * the table is exceeded, an older one gets dropped and deallocated.
 */
void hc_conn_table_insert(HC_ConnTable *table, HC_Conn *conn);


/**
 * hc_conn_table_find - hashtable lookup.
 * @table: table to look up connection in.
 * @src_addr: IP source address
 * @src_port: source port.
 * @dst_addr: IP destination address.
 * @dst_port: destination port.
 *
 * The function tries to find a connection in the table that matches
 * the given connection either directly or reversely.
 *
 * Returns: found function, or %NULL if the connection doesn't exist.
 */
HC_Conn *hc_conn_table_find(HC_ConnTable *table,
			    ip_addr_t src_addr, uint16_t src_port,
			    ip_addr_t dst_addr, uint16_t dst_port);


/**
 * hc_conn_table_remove - removes a connection from a table.
 * @table: table to remove from.
 * @conn: connection to remove.
 *
 * The function removes @conn from @table if it contains it, without
 * deallocating @conn -- it is just removed from the table.
 *
 * Returns: value > 0 if the operation was successful, 0 otherwise.
 */
int hc_conn_table_remove(HC_ConnTable *table, HC_Conn *conn);


/**
 * hc_conn_table_foreach - connection iterator.
 * @table: table to iterate over.
 * @callback: callback to call for each connection.
 * @user_data: user data passed through to the callback.
 *
 * The function iterates over the connections stored in the hashtable
 * and calls @callback with each connection, passing along @user_data.
 */
int hc_conn_table_foreach(HC_ConnTable *table, HC_ConnCB callback, void *user_data);


/**
 * hc_conn_table_cleanup - hashtable garbage collection.
 * @table: table to clean up.
 *
 * The function iterates over all connections in the table and
 * destroys all connections marked as doomed (conn->doomed == 1).
 */
void hc_conn_table_cleanup(HC_ConnTable *table);


/**
 * hc_conn_table_get_size - returns number of connections in table.
 * @table: table to query.
 * 
 * Returns: the number of connections currently stored in @table.
 */
int  hc_conn_table_get_size(HC_ConnTable *table);



/* -- Connections ------------------------------------------------------ */

/**
 * hc_conn_new - allocates and initializes a new connection.
 * @iphdr: IP header defining source and destination addresses.
 * @header_len: length of packet headers before actual payload starts.
 * @src_port: source port.
 * @dst_port: destination port.
 * @max_msg_size: maximum number of bytes stored for a single message.
 * @bytes_max: maximum number of bytes we store for this connection.
 *
 * The function allocates a new connection that is able to collect
 * exchanged messages in the packet payloads.
 *
 * Returns: new connection, or %NULL when an error occurred.
 */
HC_Conn *hc_conn_new(struct ip_hdr *iphdr, u_int header_len,
		     uint16_t src_port, uint16_t dst_port,
		     u_int max_msg_size, u_int bytes_max);

/**
 * hc_conn_init - initializes an existing connection.
 * 
 * Like hc_conn_new(), but for an already allocated connection.
 *
 * Returns: value > 0 if initialization was successful, 0 otherwise.
 */
int  hc_conn_init(HC_Conn *conn,
		  struct ip_hdr *iphdr, u_int header_len,
		  uint16_t src_port, uint16_t dst_port,
		  u_int max_msg_size, u_int bytes_max);


/**
 * hc_conn_free - cleans up and deallocates a connection.
 * @conn: connection to free.
 *
 * The function cleans up all memory occupied by conn, including
 * the connection itself.
 */
void hc_conn_free(HC_Conn *conn);


/**
 * hc_conn_cleanup - cleans up connection without deallocating connection itself.
 * @conn: connection to clean up.
 *
 * Like hc_conn_free(), but @conn itself is not freed.
 */
void hc_conn_cleanup(HC_Conn *conn);


/**
 * hc_conn_drop - marks a connection as ready to be deleted.
 * @conn: connection to mark.
 * 
 * The function marks @conn as deletable, so that a future call to
 * hc_conn_table_cleanup will destroy @conn.
 */
void hc_conn_drop(HC_Conn *conn);


/**
 * hc_conn_update_state - updates the state of a connection.
 * @conn: connection to update.
 * @iphdr: IP header of packet to use for the update.
 * @src_port: source port.
 * @dst_port: destination port.
 *
 * The function updates the state of the connection as far as HC_Conns are
 * aware of them; see the definition of HC_Conn to see what fields can
 * be updated.
 */
void hc_conn_update_state(HC_Conn *conn, struct ip_hdr *iphdr,
			  uint16_t src_port, uint16_t dst_port);


/**
 * hc_conn_add_data - adds message data to a connection.
 * @conn: connection to update.
 * @forward_dir: direction of the update -- forward (1) or reverse (0).
 * @iphdr: IP hdr of packet containing new payload.
 * @header_len: length of packet headers before payload starts.
 * @data: payload pointer.
 * @data_len: length of payload in bytes.
 *
 * The function either adds the payload data to the most recent message
 * in @conn if the packet is going into the same direction, or ends
 * the last message and begins a new one going into the opposite direction.
 */
void hc_conn_add_data(HC_Conn *conn, int forward_dir,
		      struct ip_hdr *iphdr, u_int header_len,
		      u_char *data, u_int data_len);


/**
 * hc_conn_get_bytes_exchanged - returns number of payload bytes exchanged.
 * @conn: conn to query.
 * 
 * Returns: The number of payload bytes exchanged in @conn. 
 */
u_int         hc_conn_get_bytes_exchanged(HC_Conn *conn);


/**
 * hc_conn_get_num_messages - returns number of messages sent back and forth.
 * @conn: conn to query.
 * 
 * The function returns the number of messages currently seen in the connection's
 * lifetime. A message is a chunk of data sent without real data being sent in
 * response (i.e. at most ACK packets).
 *
 * Returns: number of messages.
 */
u_int         hc_conn_get_num_messages(HC_Conn *conn);


/**
 * hc_conn_get_nth_message - returns nth message's data.
 * @conn: connection to query.
 * @num: message to look up.
 *
 * Returns: data sent in message @num in connection @conn,
 * or %NULL if @num messages haven't been sent yet.
 */
HC_Blob       *hc_conn_get_nth_message(HC_Conn *conn, u_int num);


/**
 * hc_conn_get_nth_message - returns nth message's data.
 * @conn: connection to query.
 * @num: message header to look up.
 *
 * Returns: packet headers that started message @num in connection @conn,
 * or %NULL if @num messages haven't been sent yet.
 */
struct ip_hdr *hc_conn_get_nth_message_header(HC_Conn *conn, u_int num);


#endif
