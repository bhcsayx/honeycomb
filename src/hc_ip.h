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
#ifndef __hc_ip_h
#define __hc_ip_h

#include "honeycomb.h"
#include "hc_signature.h"
#include "hc_bitmaps.h"

/**
 * hc_ip_init - initializes IP packet handling.
 *
 * The function creates data structures necessary for UDP packet
 * handling and hooks the appropriate callbacks into Honeyd.
 */
void          hc_ip_init(void);


/**
 * hc_ip_analyze - analyzes two IP packets for similarities.
 * @iphdr_old: IP header input.
 * @iphdr_new: IP header input.
 * @sig: signature to report findings in.
 *
 * The function analyzes the given IP headers for similarities
 * and oddities in the various header fields. It updates @sig as
 * new results are found.
 *
 * Returns: the number of similarities or oddities found.
 */
int           hc_ip_analyze(const struct ip_hdr *iphdr_old,
			    const struct ip_hdr *iphdr_new,
			    HC_Signature *sig);


/**
 * hc_ip_equivalent - test wether two IP headers are equivalent.
 * @iphdr1: IP header input.
 * @iphdr2: IP header input.
 *
 * The function tests whether the given IP headers are equivalent
 * as far as interesting features are concerned. Features that
 * may deviate currently are:
 *
 *   - IP ID
 *   - Checksum
 *   - TTL (nmap for example varies this one in scans)
 *
 * Returns: value > 0 if equivalent, 0 otherwise.
 */
int           hc_ip_equivalent(const struct ip_hdr *iphdr1,
			       const struct ip_hdr *iphdr2);


#endif
