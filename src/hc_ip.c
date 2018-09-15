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
#include "hc_util.h"
#include "hc_signature_hist.h"
#include "hc_ip.h"

static HC_Bitmap        *ip_mask_map;
static struct ip_hdr    *ip_mask;

static HC_BitmapQueue   *in_queue;

int
hc_ip_analyze(const struct ip_hdr *iphdr_new,
	      const struct ip_hdr *iphdr_old,
	      HC_Signature *sig)
{
	u_char topbyte;
	uint32_t addrmask, src_addr, dst_addr;
	uint16_t shortval;
	int result = 0, src_addr_result = 0, dst_addr_result = 0, addr_matches = 0;
	
	if (!iphdr_new || !sig)
		return 0;

	D(("Analyzing IP headers %p %p\n", iphdr_new, iphdr_old));

	if (iphdr_old) {
		
		hc_blob_get_mask((u_char*) iphdr_old, iphdr_old->ip_hl << 2,
				 (u_char*) iphdr_new, iphdr_new->ip_hl << 2,
				 (u_char*) ip_mask, IP_HDR_LEN_MAX);
	}

	/* We now can check the IP mask to see if there are any overlaps.
	 * If there are (ideally this should be amply configurable), we
	 * generate a signature. We walk every header field to see if
	 * what matches we have, and if they're suspicious.
	 */
	
	/* We skip the IP version, obviously it'll match for almost
	 * everything IP. We're interested in the IP header length if it
	 * is different from the "usual" value of 5 32-byte words, no options.
	 */
	if ((iphdr_old && ip_mask->ip_hl == UNIBBLE_MAX && iphdr_new->ip_hl != 5) ||
	    iphdr_new->ip_hl < 5) {
		
		D(("IP header length too short\n"));
		hc_sig_set_ip_hl(sig, iphdr_new->ip_hl);
		result++;
	}
	
	/* TOS value only if it's funky and a full match -- this is
	 * probably too loose to be useful.
	 */
	if (iphdr_old && ip_mask->ip_tos == UCHAR_MAX && iphdr_new->ip_tos > 32) {
		
		D(("IP TOS matched\n"));
		hc_sig_set_ip_tos(sig, iphdr_new->ip_tos);
		result++;
	}
	
	/* IP packet size is suspicious without direct matches if
	 * it's a bogus size.
	 */
	if (ntohs(iphdr_new->ip_len) < (iphdr_new->ip_hl << 2)) {
		
		D(("IP len too short\n"));
		hc_sig_set_ip_len(sig, ntohs(iphdr_new->ip_len));
		result++;
	}
	    
	/* IP ID by itself is not suspicious -- we need higher level
	 * details (like only in first TCP packet, or in ICMP etc to
	 * make this meaningful.
	 */

	/* NOTE: Honeyd does fragment reassembly, but I've added these
	 * checks in any case ...
	 */

	/* Fragmentation offset is suspicious when the offset
	 * plus the packet length > 65535.
	 */
	shortval = (ntohs(iphdr_new->ip_off) & IP_OFFMASK) << 3;

	if (shortval + ntohs(iphdr_new->ip_len) > IP_LEN_MAX) {

		D(("IP fragmentation offset too large\n"));
		hc_sig_set_ip_fragoffset(sig, shortval, HC_COMP_EQ);
		result++;
	}

	/* Also, be suspicious when we have a match in the fragmentation
	 * bits and the values are not obvious (for now that means the
	 * reserved flag is set) ...
	 */
	shortval = ntohs(iphdr_new->ip_off);

	if (iphdr_old && (shortval & IP_RF)) {
		
		hc_sig_set_ip_flag(sig, IP_RF, 1);
		hc_sig_set_ip_flag(sig, IP_DF, (shortval & IP_DF));
		hc_sig_set_ip_flag(sig, IP_MF, (shortval & IP_MF));
		result++;
	}
	
	/* The IP payload protocol is suspicious if it's not entirely
	 * obvious -- yet another item that should be easily configurable
	 */
	if (iphdr_new->ip_p != IP_PROTO_TCP  &&
	    iphdr_new->ip_p != IP_PROTO_UDP  &&
	    iphdr_new->ip_p != IP_PROTO_ICMP &&
	    iphdr_new->ip_p != IP_PROTO_IGMP) {

		D(("IP payload protocol %u found\n", iphdr_new->ip_p));
		hc_sig_set_ip_proto(sig, iphdr_new->ip_p);
		result++;
	}
	
	/* Mhmmm we could sanity-check the IP checksum here ... but
	 * what would we do with it? Would need a signature that allows
	 * checksum results -- probably rather unrealistic? */

	/* IP source and destination addresses are logged when they
	 * are weird, identical or at least share network addresses:
	 */
	src_addr = ntohl(iphdr_new->ip_src);
	dst_addr = ntohl(iphdr_new->ip_dst);
	addr_matches = 0;

	do { /* one-shot loop to break out of once source is handled */

		/* Check for 255.255.255.255 */
		if (src_addr == 0xFFFFFFFF) {

			D(("IP src 255.255.255 found\n"));
			hc_sig_set_ip_src(sig, src_addr, 32);
			src_addr_result = 1;
			break;
		}
		
		/* Check for topbyte marsians */
		topbyte = (src_addr & 0xff000000) >> 24;
		if ((topbyte > 223) || (topbyte == 127) || (topbyte == 0)) {

			D(("IP src marsian\n"));
			hc_sig_set_ip_src(sig, (src_addr & 0xFF000000), 8);
			src_addr_result = 1;
			addr_matches = 1;
		}

		/* Shouldn't come from 192.168 ... */
		if ((src_addr & 0xFFFF0000) == 0xC0A80000) {

			D(("IP src 192.168 found\n"));
			hc_sig_set_ip_src(sig, (src_addr & 0xFFFF0000), 16);
			src_addr_result = 1;
			addr_matches = 2;
		}


		/* Check for matches with previous packet */

		if (iphdr_old) {
			addrmask = ntohl(ip_mask->ip_src);
			if (addrmask == UINT_MAX) {
				D(("IP src match found, 32bit\n"));
				hc_sig_set_ip_src(sig, src_addr, 32);
				src_addr_result = 1;
			} else if ((addrmask & 0xFFFFFF00) == 0xFFFFFF00 && addr_matches <= 2) {
				D(("IP src match found, 24bit\n"));
				hc_sig_set_ip_src(sig, (src_addr & 0xFFFFFF00), 24);
				src_addr_result = 1;
			} else if ((addrmask & 0xFFFF0000) == 0xFFFF0000 && addr_matches <= 1) {
				D(("IP src match found, 16bit\n"));
				hc_sig_set_ip_src(sig, (src_addr & 0xFFFF0000), 16);
				src_addr_result = 1;
			} else if ((addrmask & 0xFF000000) == 0xFF000000) {
				D(("IP src match found, 8bit\n"));
				hc_sig_set_ip_src(sig, (src_addr & 0xFF000000), 8);
				src_addr_result = 1;
			}
		}
		
	} while (0);

	addr_matches = 0;

	do { /* one-shot loop to break out of once dest is handled */

		if (dst_addr == 0xFFFFFFFF) {
			D(("IP dst 255.255.255 found\n"));
			hc_sig_set_ip_dst(sig, dst_addr, 32);
			dst_addr_result = 1;
			break;
		}


		if ((dst_addr & 0x000000FF) == 0) {
			D(("IP dst ends in .0\n"));
			hc_sig_set_ip_dst(sig, dst_addr, 32);
			dst_addr_result = 1;
			addr_matches = 1;
		}

		/* Check for marsians */
		topbyte = (dst_addr & 0xff000000) >> 24;
		if ((topbyte > 223) || (topbyte == 127) || (topbyte == 0)) {
			D(("IP dst marsian\n"));
			hc_sig_set_ip_dst(sig, (dst_addr & 0xFF000000), 8);
			dst_addr_result = 1;
			addr_matches = 1;
		}
	
		/* Check for matches with previous packet */
		if (iphdr_old) {
			addrmask = ntohl(ip_mask->ip_dst);
			if (addrmask == UINT_MAX) {
				D(("IP dst match found, 32bit\n"));
				hc_sig_set_ip_dst(sig, dst_addr, 32);
				dst_addr_result = 1;
			} else if ((addrmask & 0xFFFFFF00) == 0xFFFFFF00 && addr_matches <= 2) {
				D(("IP dst match found, 24bit\n"));
				hc_sig_set_ip_dst(sig, (dst_addr & 0xFFFFFF00), 24);
				dst_addr_result = 1;
			} else if ((addrmask & 0xFFFF0000) == 0xFFFF0000 && addr_matches <= 1) {
				D(("IP dst match found, 16bit\n"));
				hc_sig_set_ip_dst(sig, (dst_addr & 0xFFFF0000), 16);
				dst_addr_result = 1;
			} else if ((addrmask & 0xFF000000) == 0xFF000000) {
				D(("IP dst match found, 8bit\n"));
				hc_sig_set_ip_dst(sig, (dst_addr & 0xFF000000), 8);
				dst_addr_result = 1;
			}
			
		}
	} while (0);
	
	result += (src_addr_result + dst_addr_result);
	
	return result;
}


static void
ip_match(HC_Bitmap *map, HC_Bitmap *new_map)
{
	HC_Signature sig;
	HC_Blob     *blob1, *blob2;

	blob1 = map->blobs.tqh_first;
	blob2 = new_map->blobs.tqh_first;
	
	hc_sig_init(&sig);
	
	if (hc_ip_analyze((struct ip_hdr *) blob2->data,
			  (struct ip_hdr *) blob1->data, &sig) > 0)
		hc_sighist_insert(&sig);
}

 
void
hc_ip_hook(u_char *packet_data, u_int packet_len, void *user_data)
{
	struct ip_hdr *iphdr;
	HC_Bitmap *map;
	
	D(("IP packet inspection ------------------------\n"));

	/* Here we only keep the IP header around as we currently
	 * don't look beyond it in this handler (is that a FIXME?)
	 */
	iphdr = (struct ip_hdr *) packet_data;
	map = hc_bitmap_new_with_data(packet_data, iphdr->ip_hl << 2);
	if(!map) return;
	hc_bitmap_queue_foreach(in_queue, (HC_BitmapCB) ip_match, map);
	hc_bitmap_queue_add(in_queue, map);

	return;
	packet_len = 0; user_data = 0;
}


void
hc_ip_init(void)
{
	ip_mask_map = hc_bitmap_new(IP_HDR_LEN_MAX);
	ip_mask = (struct ip_hdr *) ip_mask_map->blobs.tqh_first->data;

	in_queue = hc_bitmap_queue_new(hc_config.ip_backlog);

	/* We currently only check incoming IP packets. I'm currently
	 * unsure about what to look for in outgoing ones, especially
	 * since it would also require a higher-interaction honeypot.
	 *
	 * By passing IP_PROTO_RAW we make sure we end up in the list
	 * for "other" IP traffic, i.e. not the hooks for the big
	 * protocols like TCP, UDP etc.
	 */
//	hooks_add_packet_hook(IP_PROTO_RAW, HD_INCOMING, hc_ip_hook, NULL);
}


int           
hc_ip_equivalent(const struct ip_hdr *iphdr1,
		 const struct ip_hdr *iphdr2)
{
	if (!iphdr1 || !iphdr2)
		return 0;

	if (iphdr1->ip_v != iphdr2->ip_v) {
		return 0;
	}
	if (iphdr1->ip_hl != iphdr2->ip_hl) {
		return 0;
	}
	if (iphdr1->ip_tos != iphdr2->ip_tos) {
		return 0;
	}
	if (iphdr1->ip_len != iphdr2->ip_len) {
		return 0;
	}
	if (iphdr1->ip_off != iphdr2->ip_off) {
		return 0;
	}
	if (iphdr1->ip_p != iphdr2->ip_p) {
		return 0;
	}
	if (iphdr1->ip_src != iphdr2->ip_src) {
		return 0;
	}
	if (iphdr1->ip_dst != iphdr2->ip_dst) {
		return 0;
	}

	return 1;
}

