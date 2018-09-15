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
#ifndef __hc_signature_hist_h
#define __hc_signature_hist_h

#include "honeycomb.h"
#include "hc_signature.h"

/* Every signature stored in the history has a map of destination ports
 * for which a signature matched, except for the destination port. We use
 * one bit per port so the size of that bitmap is 8K.
 */
#define   PORTS_BITMAP_SIZE             8192


/**
 * HC_SigHistReportCB - signature of callbacks that trigger signatures are reported.
 * @user_data: arbitrary user data.
 *
 * Currently stored signatures are reported periodically by calling a
 * registered callback of this signature.
 */
typedef void (*HC_SigHistReportCB) (void *user_data);

/**
 * HC_SignatureCB - signature of callbacks for hc_sighist_foreach().
 * @sig: current signature.
 * @user_data: arbitrary user data.
 *
 * hc_sighist_foreach() iterates over all currently stored signatures,
 * calling a function of this signature passing it the currently iterated
 * signature and arbitrary user data.
 */
typedef void (*HC_SignatureCB) (const HC_Signature *sig, void *user_data);


/**
 * hc_sighist_init - initializes signature history.
 */
void          hc_sighist_init(void);


/**
 * hc_sighist_set_max_size - sets the maximum number of signatures remembered.
 * @max_size: new maximum size of signature memory.
 *
 * The function set the size of our memory to @max_size. If this is
 * smaller than a previously set value, the oldest signatures are dropped.
 */
void          hc_sighist_set_max_size(u_int max_size);


/**
 * hc_sighist_set_report_callback - sets callback for signature reports.
 * @callback: callback to call.
 * @user_data: data to pass to @callback.
 *
 * This sets the new callback used for each signature when the current set
 * of signatures is reported.
 */
void          hc_sighist_set_report_callback(HC_SigHistReportCB callback,
					     void *user_data);

/**
 * hc_sighist_insert - inserts a signature into memory.
 * @sig: signature to put into memory.
 *
 * The function first checks if we already know a signature that
 * matches @sig, and if not, inserts it and calls the insertion handler
 * defined using hc_sighist_set_insert_callback().
 */
int           hc_sighist_insert(HC_Signature *sig);


/**
 * hc_sighist_foreach - calls a callback with each registered signature.
 * @callback: callback to call.
 * @user_data: arbitrary data passed to the callback.
 *
 * The function iterates over all currently registered signatures and
 * calls @callback for each one, passing to @callback that signature
 * and @user_data.
 */
void          hc_sighist_foreach(HC_SignatureCB callback, void *user_data);


#endif
