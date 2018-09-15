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
#include <string.h>
#include "event.h"
#include "honeycomb.h"
#include "hc_debug.h"
#include "hc_config.h"
#include "hc_bitmaps.h"
#include "hc_conn.h"


typedef TAILQ_HEAD(hc_conn_list, hc_conn) HC_ConnList;

struct hc_conn_table {

	HC_ConnList         *conns;

	u_int                num_slots;
	u_int                max_conns;
	u_int                cur_conns;

	u_int                cleanup_interval;
	struct event         cleanup_timeout_ev;

	/* Destructor callback when connections really get cleaned up: */
	HC_ConnFreeFunc      free_func;
};


static int                   conns_key_counter;

/* -- Connection Identifiers ------------------------------------------- */

static u_int
conn_id_hash(HC_ConnID *id)
{
	return ((id->src_port ^ id->src_addr) ^
		(id->dst_port ^ id->dst_addr));
}


int
hc_conn_id_direct_match(HC_ConnID *id1, HC_ConnID *id2)
{
	if (id1->src_addr == id2->src_addr &&
	    id1->src_port == id2->src_port &&
	    id1->dst_addr == id2->dst_addr &&
	    id1->dst_port == id2->dst_port)
		return 1;
	
	return 0;
}


int
hc_conn_id_reverse_match(HC_ConnID *id1, HC_ConnID *id2)
{
	if (id1->src_addr == id2->dst_addr &&
	    id1->src_port == id2->dst_port &&
	    id1->dst_addr == id2->src_addr &&
	    id1->dst_port == id2->src_port)
		return 1;

	return 0;
}

int
hc_conn_id_equal(HC_ConnID *id1, HC_ConnID *id2)
{
	if (hc_conn_id_direct_match(id1, id2) ||
	    hc_conn_id_reverse_match(id1, id2)) {
		return 1;
	}
	
	return 0;
}


/* -- Connection Hashtables -------------------------------------------- */

static void
conn_table_cleanup_cb(int fd, short which, void *arg)
{
	HC_ConnTable *table = (HC_ConnTable *) arg;
	struct timeval  tv;

	hc_conn_table_cleanup(table);

	tv.tv_sec  = table->cleanup_interval;
	tv.tv_usec = 0;
	timeout_add(&table->cleanup_timeout_ev, &tv);

	return;
	fd = which = 0;
}


HC_ConnTable *
hc_conn_table_new(u_int num_slots, u_int max_conns, u_int cleanup_interval)
{
	HC_ConnTable *table;
	u_int i;
	struct timeval tv;
	if (! (table = calloc(1, sizeof(HC_ConnTable))))
		return NULL;
	
	if (! (table->conns = malloc(num_slots * sizeof(HC_ConnList)))) {
		D(("Out of memory.\n"));
		return NULL;
	}
	
	table->num_slots = num_slots;
	table->max_conns = max_conns;
	table->cur_conns = 0;
	
	for (i = 0; i < num_slots; i++)
		TAILQ_INIT(&table->conns[i]);	

	/* The default destructor is the one for simple connections. */
	table->free_func = hc_conn_free;

	/* We periodically scan the hashtables and drop all connections
	 * marked accordingly (with conn->doom == 1). Set up a timer for
	 * that.
	 */
	timeout_set(&table->cleanup_timeout_ev, conn_table_cleanup_cb, table);
	table->cleanup_interval = cleanup_interval;
	tv.tv_sec  = cleanup_interval;
	tv.tv_usec = 0;
	table->cleanup_timeout_ev.ev_base=calloc(1,sizeof(table->cleanup_timeout_ev.ev_base));
	timeout_add(&table->cleanup_timeout_ev, &tv);

	return table;
}


void 
hc_conn_table_set_free_func(HC_ConnTable *table, HC_ConnFreeFunc free_func)
{
	if (!table || !free_func)
		return;

	table->free_func = free_func;
}


void
hc_conn_table_insert(HC_ConnTable *table, HC_Conn *conn)
{
	HC_ConnList *oldest_list = NULL;
	HC_Conn     *oldest_conn = NULL, *cur_conn;
	int          oldest_key  = conns_key_counter;
	u_int        i;
	HC_ConnList *list;	
	
	if (!table || !conn)
		return;

	list = &table->conns[conn_id_hash(&conn->id) % table->num_slots];
	TAILQ_INSERT_TAIL(list, conn, conns);
	table->cur_conns++;

	D(("Connections in table %p now: %i\n", table, table->cur_conns));

	if (table->cur_conns <= table->max_conns)
		return;

	for (i = 0; i < table->num_slots; i++) {
		
		if (! (cur_conn = table->conns[i].tqh_first))
			continue;

		if (cur_conn->key < oldest_key) {
			
			oldest_list = &table->conns[i];
			oldest_key  = cur_conn->key;
			oldest_conn = cur_conn;
		}
	}
		
	D_ASSERT_PTR(oldest_conn);
	TAILQ_REMOVE(oldest_list, oldest_conn, conns);
	hc_conn_free(oldest_conn);
	table->cur_conns--;
}


HC_Conn *
hc_conn_table_find(HC_ConnTable *table,
		   ip_addr_t src_addr, uint16_t src_port,
		   ip_addr_t dst_addr, uint16_t dst_port)
{
	HC_ConnID id;
	HC_Conn *conn;
	HC_ConnList *list;	
	u_int hash;

	id.src_addr = src_addr; id.src_port = src_port;
	id.dst_addr = dst_addr; id.dst_port = dst_port;
	
	hash = conn_id_hash(&id) % table->num_slots;
	list = &table->conns[hash]; 

	for (conn = list->tqh_first; conn; conn = conn->conns.tqe_next) {
		
		/* Skip old connections, they're not here to be actively
		 * looked up but only for pattern detection!
		 */
		if (conn->terminated || conn->doomed)
			continue;
		
		if (hc_conn_id_equal(&id, &conn->id))
			return conn;		
	}

	return NULL;
}


int
hc_conn_table_remove(HC_ConnTable *table, HC_Conn *conn)
{
	HC_ConnList *list;	
	HC_Conn     *conn_old;

	if (!table || !conn)
		return 0;
	
	list = &table->conns[conn_id_hash(&conn->id) %
			     table->num_slots];
	
	for (conn_old = list->tqh_first; conn_old; conn_old = conn_old->conns.tqe_next) {
		
		if (hc_conn_id_equal(&conn_old->id, &conn->id)) {
			
			TAILQ_REMOVE(list, conn, conns);
			table->cur_conns--;
			D(("Connections in table %p now: %i\n", table, table->cur_conns));
			return 1;
		}
	}

	return 0;
}


int
hc_conn_table_foreach(HC_ConnTable *table, HC_ConnCB callback, void *user_data)
{
	HC_Conn *conn;
	u_int i;

	if (!callback)
		return 0;

	for (i = 0; i < table->num_slots; i++) {
		
		for (conn = table->conns[i].tqh_first; conn; conn = conn->conns.tqe_next) {
	
			/* We skip the ones that are dead */
			if (conn->doomed)
				continue;

			if (callback(conn, user_data))
				return 1;
		}
	}

	return 0;
}


void
hc_conn_table_cleanup(HC_ConnTable *table)
{
	HC_Conn *conn, *conn_nuke;
	u_int i, nuked;

	if (!table)
		return;

	for (i = 0, nuked = 0; i < table->num_slots; i++) {
		
		conn = table->conns[i].tqh_first;
		while (conn) {
			
			conn_nuke = conn;
			conn = conn->conns.tqe_next;
			
			if (conn_nuke->doomed) {
				TAILQ_REMOVE(&table->conns[i], conn_nuke, conns);

				table->free_func(conn_nuke);
				table->cur_conns--;
				nuked++;
			}
		}
	}

#ifdef HONEYD_DEBUG
	if (nuked > 0) {
		D(("Hashtable cleanup: nuked %i connections.\n", nuked));
	}
#endif
}


int  
hc_conn_table_get_size(HC_ConnTable *table)
{
	if (!table)
		return 0;

	return table->cur_conns;
}



/* -- Connections ------------------------------------------------------ */

HC_Conn *
hc_conn_new(struct ip_hdr *iphdr, u_int header_len,
	    uint16_t src_port, uint16_t dst_port,
	    u_int max_msg_size, u_int bytes_max)
{
	HC_Conn *conn;

	if (!iphdr) {
		D(("Input error\n"));
		return NULL;
	}

	if (! (conn = calloc(1, sizeof(HC_Conn)))) {
		D(("Out of memory\n"));
		return NULL;
	}

	if (! hc_conn_init(conn, iphdr, header_len,
			   src_port, dst_port,
			   max_msg_size, bytes_max)) {
		
		D(("Error in connection initialization\n"));
		free(conn);
		return NULL;
	}
	
	return conn;
}



int
hc_conn_init(HC_Conn *conn,
	     struct ip_hdr *iphdr, u_int header_len,
	     uint16_t src_port, uint16_t dst_port,
	     u_int max_msg_size, u_int bytes_max)
{
	if (! conn || !iphdr || max_msg_size == 0 || bytes_max == 0) {
		D(("Input error\n"));
		return 0;
	}

	memset(conn, 0, sizeof(HC_Conn));

	if (! (conn->stream = hc_bitmap_new(max_msg_size))) {
		D(("Out of memory -- bitmap not created\n"));
		free(conn);
		return 0;
	}

	if (! (conn->stream_headers = hc_bitmap_new(IP_HDR_LEN_MAX + TCP_HDR_LEN_MAX))) {
		D(("Out of memory -- header bitmap not created\n"));
		hc_bitmap_free(conn->stream);
		free(conn);
		return 0;
	}

	/* Store connection identifier; the byte order doesn't
	 * matter as we only do checks for equality.
	 */
	conn->id.src_addr = iphdr->ip_src;
	conn->id.src_port = src_port;
	conn->id.dst_addr = iphdr->ip_dst;
	conn->id.dst_port = dst_port;
	
	/* Copy TCP and IP header into connection structure: */
	memcpy(conn->hdr, iphdr, MIN(IP_HDR_LEN_MAX + TCP_HDR_LEN_MAX, header_len));

	conn->key = conns_key_counter++;
	
	/* Mark stream direction as "no data seen yet". */
	conn->stream_reversed = -1; 
	conn->bytes_max = bytes_max;
	conn->max_msg_size = max_msg_size;

	return 1;
}


void
hc_conn_free(HC_Conn *conn)
{
	if (!conn)
		return;
	
	hc_conn_cleanup(conn);
	free(conn);
}


void
hc_conn_cleanup(HC_Conn *conn)
{
	if (!conn)
		return;

	hc_bitmap_free(conn->stream);
	hc_bitmap_free(conn->stream_headers);
	conn->stream = NULL;
	conn->stream_headers = NULL;	       
}


void          
hc_conn_drop(HC_Conn *conn)
{
	if (!conn)
		return;
	
	conn->doomed = 1;
}


void          
hc_conn_update_state(HC_Conn *conn, struct ip_hdr *iphdr,
		     uint16_t src_port, uint16_t dst_port)
{
	HC_ConnID id;
	int forward_match;

	if (!conn || !iphdr)
		return;

	id.src_addr = iphdr->ip_src; id.src_port = src_port;
	id.dst_addr = iphdr->ip_dst; id.dst_port = dst_port;

	forward_match = hc_conn_id_direct_match(&conn->id, &id);
	
	if (! forward_match && conn->answered == 0) {

		D(("Connection has been answered\n"));
		conn->answered = 1;
	}
}


void 
hc_conn_add_data(HC_Conn *conn, int forward_dir,
		 struct ip_hdr *iphdr, u_int header_len,
		 u_char *data, u_int data_len)
{
	HC_Blob   *blob;
	
	/* Don't do anything on invalid input or if this connection
	 * has already exchanged too many messages and we've lost interest.
	 */
	if (!conn || !iphdr || data_len == 0 ||
	    conn->bytes_seen > conn->bytes_max)
		return;
	
	D(("Adding %i bytes to connection\n", data_len));
	header_len = MIN(header_len, IP_HDR_LEN_MAX + TCP_HDR_LEN_MAX);

	/* Okay, we have data. Now figure out what direction it is and
	 * what was the last direction we've seen data flow in. If it
	 * changed, add a new blob to the stream, otherwise add as much
	 * data of this packet to the last blob as possible/necessary.
	 */
	if (conn->stream_reversed < 0) {

		blob = conn->stream->blobs.tqh_first;
		hc_blob_add_data(blob, data, data_len);
		D(("First blob now %u %u\n", blob->data_used, blob->data_len));

		blob = conn->stream_headers->blobs.tqh_first;
		hc_blob_add_data(blob, (u_char*) iphdr, header_len);
		
		if (forward_dir) {
			
			conn->bytes_seen = data_len;
			conn->stream_reversed = 0;
		} else {

			conn->bytes_seen_reversed = data_len;
			conn->stream_reversed = 1;
		}

		return;
	}

	blob = hc_bitmap_get_last_blob(conn->stream);
	D_ASSERT_PTR(blob);

	if (forward_dir) {
		
		if (conn->stream_reversed) {
			hc_blob_crop(blob);

			conn->bytes_seen_reversed += data_len;
			hc_bitmap_add_blob(conn->stream_headers, (u_char *) iphdr, header_len,
					   IP_HDR_LEN_MAX + TCP_HDR_LEN_MAX);
			hc_bitmap_add_blob(conn->stream, data, data_len,
					   conn->max_msg_size);
		} else {
			
			conn->bytes_seen += data_len;
			hc_blob_add_data(blob, data, data_len);
		}
		
		conn->stream_reversed = 0;

	} else {
		
		if (conn->stream_reversed) {

			conn->bytes_seen_reversed += data_len;
			hc_blob_add_data(blob, data, data_len);
		} else {
			
			hc_blob_crop(blob);
			
			conn->bytes_seen += data_len;
			hc_bitmap_add_blob(conn->stream_headers, (u_char *) iphdr, header_len,
					   IP_HDR_LEN_MAX + TCP_HDR_LEN_MAX);
			hc_bitmap_add_blob(conn->stream, data, data_len,
					   conn->max_msg_size);
		}
		
		conn->stream_reversed = 1;
	}
}


u_int         
hc_conn_get_bytes_exchanged(HC_Conn *conn)
{
	if (!conn)
		return 0;
	
	return conn->stream->blobs_size;
}


u_int           
hc_conn_get_num_messages(HC_Conn *conn)
{
	if (!conn)
		return 0;
	
	return conn->stream->num_blobs;
}


HC_Blob *
hc_conn_get_nth_message(HC_Conn *conn, u_int num)
{
	HC_Blob *blob;
	u_int i = 0;
	
	D(("Requesting %uth blob from %u present\n", num, conn->stream->num_blobs));

	if (num > conn->stream->num_blobs)
		return NULL;

	for (blob = conn->stream->blobs.tqh_first; blob; blob = blob->items.tqe_next) {
		
		if (i == num)
			return blob;
		
		i++;
	}
	
	return NULL;
}


struct ip_hdr *
hc_conn_get_nth_message_header(HC_Conn *conn, u_int num)
{
	HC_Blob *blob;
	u_int i = 0;
	
	if (num > conn->stream_headers->num_blobs)
		return NULL;
	
	for (blob = conn->stream_headers->blobs.tqh_first; blob; blob = blob->items.tqe_next) {
		
		if (i == num)
			return (struct ip_hdr *) blob->data;
		
		i++;
	}
	
	return NULL;
}
