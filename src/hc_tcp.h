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
#ifndef __hc_tcp_h
#define __hc_tcp_h


/**
 * hc_tcp_init - Initializes TCP connection handling.
 *
 * The function creates data structures necessary for TCP flow management
 * and hooks the appropriate callbacks into Honeyd.
 */
void      hc_tcp_init(void);


/**
 * hc_tcp_equivalent - test wether two IP + TCP headers are equivalent.
 * @iphdr1: IP header input.
 * @iphdr2: IP header input.
 *
 * The function tests whether the given IP and TCP headers are equivalent
 * as far as interesting features are concerned. Features that
 * may deviate currently are the ones as defined by hc_ip_equivalent()
 * for IP, and the following TCP fields:
 *
 * - source AND destination port
 * - sequence and acknowledgement number
 * - checksum
 * - congestion window
 *
 * Returns: value > 0 if equivalent, 0 otherwise (or if an IP header
 * doesn't contain TCP).
 */
int       hc_tcp_equivalent(const struct ip_hdr *iphdr1,
			    const struct ip_hdr *iphdr2);
void tcp_hook(u_char *packet_data, u_int packet_len, void *user_data);
#endif
