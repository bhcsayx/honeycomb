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

#include <string.h>
#include <sys/queue.h>
#include "event.h"

#include "hc_debug.h"
#include "hc_config.h"
#include "hc_signature_hist.h"

typedef struct hc_sighist_item
{
	TAILQ_ENTRY(hc_sighist_item)           items;
	HC_Signature                          *sig;

	/* Bitmap in which each 1 bit represents a seen port: */
	u_char                                 portmap[PORTS_BITMAP_SIZE];
	
} HC_SigHistItem;

TAILQ_HEAD(hc_sighist_tqh, hc_sighist_item);

static struct hc_sighist_tqh  sig_hist;
static HC_SigHistReportCB     sig_report_cb;
static void                  *sig_report_cb_data;
static u_int                  sig_max_size;
static u_int                  sig_cur_size;
static char                   sig_hist_dirty;

/* The detected signatures are reported periodically, using a timeout
 * contained in this libevent structure. Every signature has a timeout
 * that needs to expire before a new signature gets reported.
 *
 * This provides some time to improve upon existing signatures to avoid
 * reporting premature signatures (e.g. during thorough portscans).
 */
static struct event           report_timeout_ev;



static void sighist_item_mark_destport(HC_SigHistItem *item, uint16_t port);

static HC_SigHistItem *
sighist_item_new(HC_Signature *sig)
{
	HC_Signature   *sig_copy;
	HC_SigHistItem *item;

	if (! (sig_copy = hc_sig_copy(sig))) {
		D(("Out of memory\n"));
		return NULL;
	}

	if (! (item = calloc(1, sizeof(HC_SigHistItem)))) {
		D(("Out of memory\n"));
		return NULL;
	}
	
	item->sig = sig_copy;
	memset(&item->portmap, 0, PORTS_BITMAP_SIZE);
	
	sighist_item_mark_destport(item, sig->port_dst_orig1);
	sighist_item_mark_destport(item, sig->port_dst_orig2);

	return item;
}


static void
sighist_item_free(HC_SigHistItem *item)
{
	if (!item)
		return;

	TAILQ_REMOVE(&sig_hist, item, items);
	sig_cur_size--;	

	if (item->sig)
		hc_sig_free(item->sig);

	free(item);
	sig_hist_dirty = 1;
}


static void
sighist_drop_one(void)
{
	sighist_item_free(sig_hist.tqh_first);
}


static void
sighist_item_mark_destport(HC_SigHistItem *item, uint16_t port)
{
	int index;
	u_char bit;

	if (!item)
		return;

	index = port / 8;
	bit   = port % 8;
	item->portmap[index] |= (1 << bit);
	sig_hist_dirty = 1;
}


static void
sighist_timeout_cb(int fd, short which, void *arg)
{
	struct timeval  tv;

	if (sig_report_cb && sig_hist_dirty) {
		sig_report_cb(sig_report_cb_data);
		sig_hist_dirty = 0;
	}

	tv.tv_sec  = hc_config.sighist_interval;
	tv.tv_usec = 0;
	timeout_add(&report_timeout_ev, &tv);
	
	return;
	fd = which = 0; arg = 0;
}


void          
hc_sighist_init(void)
{
	struct timeval  tv;
	TAILQ_INIT(&sig_hist);
	sig_max_size = hc_config.sighist_max_size;

	timeout_set(&report_timeout_ev, sighist_timeout_cb, NULL);
	tv.tv_sec  = hc_config.sighist_interval;
	tv.tv_usec = 0;
	report_timeout_ev.ev_base=calloc(1,sizeof(report_timeout_ev.ev_base));
	timeout_add(&report_timeout_ev, &tv);
}


void          
hc_sighist_set_max_size(u_int max_size)
{
	if (max_size >= sig_max_size) {
		sig_max_size = max_size;
		return;
	}
	
	sig_max_size = max_size;
	
	while (sig_cur_size > sig_max_size)		
		sighist_drop_one();
}


void          
hc_sighist_set_report_callback(HC_SigHistReportCB callback,
			       void *user_data)
{
	if (!callback)
		return;
	
	sig_report_cb = callback;
	sig_report_cb_data = user_data;
}


int
hc_sighist_insert(HC_Signature *sig)
{
	u_int16_t       sig_id;
	HC_SigHistItem *item;

	if (!sig)
		return 0;
	
	for (item = sig_hist.tqh_first; item; item = item->items.tqe_next) {
		
		if (hc_sig_equal(item->sig, sig)) {

			item->sig->duplicates++;
			D(("Signature duplicate -- throwing away. (%i)\n",
			   sig_cur_size));
			
			sighist_item_mark_destport(item, sig->port_dst_orig1); 
			sighist_item_mark_destport(item, sig->port_dst_orig2);				

			return 0;
		}

		if (hc_sig_contained(item->sig, sig)) {
			
			D(("Replacing weaker signature with better one (%i)\n",
			   sig_cur_size));

			/* Put the old signature's ID into the new one,
			 * so that the new one keeps the ID same ID.
			 * Helps to keep track of signatures throughout
			 * updates.
			 */
			sig->id = item->sig->id;
			sighist_item_free(item);
			break;
			
		}

		/*
		if (hc_sig_contained(sig, item->sig)) {

			item->sig->duplicates++;
			D(("Dropping weak signature, keeping better one. (%i)\n",
			   sig_cur_size));
			return 0;
			
		}
		*/
	}

	/* This creates a history item with a *copy* of the signature --
	 * do *not* use sig below, use item->sig!
	 */
	if (! (item = sighist_item_new(sig)))
		return 0;

	TAILQ_INSERT_TAIL(&sig_hist, item, items);
	sig_cur_size++;
	sig_hist_dirty = 1;

	D(("Adding new signature, history size now %i\n", sig_cur_size));

	if (sig_cur_size > sig_max_size)
		sighist_drop_one();

	return 1;
}


void          
hc_sighist_foreach(HC_SignatureCB callback, void *user_data)
{
	HC_SigHistItem *item;
	
	if (!callback)
		return;

	for (item = sig_hist.tqh_first; item; item = item->items.tqe_next) {
		
		item->sig->portmap = item->portmap;
		callback(item->sig, user_data);
		item->sig->portmap = NULL;
	}
}
