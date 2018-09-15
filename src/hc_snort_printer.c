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
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <time.h>

#include "honeycomb.h"
#include "hc_debug.h"
#include "hc_config.h"
#include "hc_signature_hist.h"
#include "hc_snort_printer.h"


/* Little helper macro that advances the string pointer
 * we use below and checks whether we're still in legal
 * range -- makes the output code much cleaner.
 */
#define ADVANCE_POINTER_SAFELY \
        len = strlen(bufptr);   \
        bufptr += len;          \
        remaining -= len;       \
                                \
	if (remaining <= 0)     \
		return result;


static int
sig_print_portranges(u_char *portmap, char *bufptr, int remaining)
{
	int len, i, j, blockstart, blockend, port_found, firstblock = 1, result = 0;

	for (i = 0; i < PORTS_BITMAP_SIZE; i++) {

		if (portmap[i] == 0)
			continue;

		for (j = 0; j < 8; j++) {
			
			if (! (portmap[i] & (1 << j)))
				continue;

			blockstart = blockend = (i << 3) + j;
			port_found = 0;
			
			do {
				port_found = 0;
				if (++j == 8) {
					j = 0;
					i++;
					
					if (i == PORTS_BITMAP_SIZE)
						break;
				}
				
				if (portmap[i] & (1 << j)) {
					blockend++;
					port_found = 1;
				}
			} while (port_found);
			
			if (!firstblock) {
				snprintf(bufptr, remaining, ",");
				ADVANCE_POINTER_SAFELY;
			}

			if (blockstart == blockend)
				snprintf(bufptr, remaining, "%i", blockstart);
			else
				snprintf(bufptr, remaining, "%i:%i", blockstart, blockend);

			ADVANCE_POINTER_SAFELY;
			firstblock = 0;
			result = 1;
		}
	}

	snprintf(bufptr, remaining, " ");
	ADVANCE_POINTER_SAFELY;

	return result;
}


static int
sig_print_ports(const HC_Signature *sig,
		const HC_SignaturePort *port,
		char *bufptr, int remaining)
{
	switch (port->comp1) {
	case HC_COMP_EQ:
		snprintf(bufptr, remaining, "%u ", port->val1);
		break;
	case HC_COMP_ST:
		snprintf(bufptr, remaining, ":%u ", port->val1 + 1);
		break;
	case HC_COMP_STE:
		snprintf(bufptr, remaining, ":%u ", port->val1);
		break;
	case HC_COMP_GT:
		switch (port->comp2) {
		case HC_COMP_ST:
			snprintf(bufptr, remaining, "%u:%u ",
				 port->val1 - 1, port->val2 + 1);
			break;
		case HC_COMP_STE:
			snprintf(bufptr, remaining, "%u:%u ",
				 port->val1 - 1, port->val2);
			break;
		default:
			snprintf(bufptr, remaining, "%u: ", port->val1 - 1);
		}
		break;
	case HC_COMP_GTE:
		switch (port->comp2) {
		case HC_COMP_ST:
			snprintf(bufptr, remaining, "%u:%u ",
				 port->val1, port->val2 + 1);
			break;
		case HC_COMP_STE:
			snprintf(bufptr, remaining, "%u:%u ",
				 port->val1, port->val2);
			break;
		default:
			snprintf(bufptr, remaining, "%u: ", port->val1);
		}
		break;
	default:
		return 0;
	}
	
	return 1;
}

int     
hc_sig_print_snort(const HC_Signature *sig, char *buf, u_int buflen)
{
	struct in_addr addr;
	char *bufptr, *timestr;
	int remaining;
	int len, result = 0;
	
	if (!sig || !buf || buflen == 0)
		return 0;
	
	bufptr = buf;
	remaining = (int) buflen;
	
	/* Print the rule header, declaring it as rule type "honeyd".
	 * We can assume that people who use this plugin will want to
	 * pay special attention to the rules generated, and thus can
	 * set up special output handling for them.
	 */

	snprintf(bufptr, remaining, "%s ", hc_config.snort_alert_class);
	ADVANCE_POINTER_SAFELY;

	switch (sig->proto) {
	case IP_PROTO_IP:
		snprintf(bufptr, remaining, "ip ");
		break;
	case IP_PROTO_TCP:
		snprintf(bufptr, remaining, "tcp ");
		break;
	case IP_PROTO_UDP:
		snprintf(bufptr, remaining, "udp ");
		break;
	case IP_PROTO_ICMP:
		snprintf(bufptr, remaining, "icmp ");
		break;
	default:
		return 0;
	}
	ADVANCE_POINTER_SAFELY;


	if (sig->active & HC_SIG_IP_SRC) {
		addr.s_addr = htonl(sig->ip_src);
		snprintf(bufptr, remaining, "%s/%i ",
			 inet_ntoa(addr),
			 sig->ip_src_mask);
	} else {
		snprintf(bufptr, remaining, "any ");
	}
	ADVANCE_POINTER_SAFELY;

	
	if (sig->active & HC_SIG_PORT_SRC) {
		if (! sig_print_ports(sig, &sig->port_src, bufptr, remaining))
			return 0;
	} else {
		snprintf(bufptr, remaining, "any ");
	}
	ADVANCE_POINTER_SAFELY;

	snprintf(bufptr, remaining, "-> ");
	ADVANCE_POINTER_SAFELY;

	if (sig->active & HC_SIG_IP_DST) {
		addr.s_addr = htonl(sig->ip_dst);
		snprintf(bufptr, remaining, "%s/%i ",
			 inet_ntoa(addr),
			 sig->ip_dst_mask);
	} else {
		snprintf(bufptr, remaining, "any ");
	}
	ADVANCE_POINTER_SAFELY;
	
	if (! sig_print_portranges(sig->portmap, bufptr, remaining))
		snprintf(bufptr, remaining, "any ");
	/*
	if (sig->active & HC_SIG_PORT_DST) {
		if (! sig_print_ports(sig, &sig->port_dst, bufptr, remaining))
			return 0;
	} else {
		snprintf(bufptr, remaining, "any ");
	}
	*/	
	ADVANCE_POINTER_SAFELY;

	snprintf(bufptr, remaining, "(");
	ADVANCE_POINTER_SAFELY;
	
        /* Create signature title: */
	timestr = ctime(&sig->timestamp);
	timestr[strlen(timestr) - 1] = '\0'; /* Kill the newline */

	/* I'm not exactly a fan of snort's hand-written parser -- within
	 * a msg string any ':'s will make snort reject the rule :(
	 * As a workaround, change timestamp strings as follows:
	 * 
	 * "Wed Jun 30 21:49:08 1993" --> Wed Jun 30 21h49m08 1993"
	 */
	timestr[13] = 'h';
	timestr[16] = 'm';

	snprintf(bufptr, remaining, "msg: \"Honeycomb %s %s%s\"; ",
		 timestr, (sig->comment ? ": " : ""), (sig->comment ? sig->comment : ""));	
	ADVANCE_POINTER_SAFELY;

	/* Now print rule options depending on what we could find. */
	if (sig->active & HC_SIG_IP_TOS) {
		snprintf(bufptr, remaining, "tos: \"%u\"; ", sig->ip_tos);
		ADVANCE_POINTER_SAFELY;
	}

	if (sig->active & HC_SIG_IP_ID) {
		snprintf(bufptr, remaining, "id: \"%u\"; ", sig->ip_id);
		ADVANCE_POINTER_SAFELY;
	}

	if (sig->active & HC_SIG_IP_TTL) {
		switch (sig->ip_ttl_comp) {
		case HC_COMP_ST:
			snprintf(bufptr, remaining, "ttl: <%u; ", sig->ip_ttl);
			break;
		case HC_COMP_STE:
			snprintf(bufptr, remaining, "ttl: <%u; ", sig->ip_ttl + 1);
			break;
		case HC_COMP_GT:
			snprintf(bufptr, remaining, "ttl: >%u; ", sig->ip_ttl);
			break;
		case HC_COMP_GTE:
			snprintf(bufptr, remaining, "ttl: >%u; ", sig->ip_ttl - 1);
			break;
		default:
			snprintf(bufptr, remaining, "ttl: %u; ", sig->ip_ttl);
		}
		ADVANCE_POINTER_SAFELY;
	}
	
	if (sig->active & HC_SIG_IP_PROTO) {
		switch (sig->ip_proto) {
		case IP_PROTO_TCP:
			snprintf(bufptr, remaining, "ip_proto: \"tcp\"; ");
			break;
		case IP_PROTO_UDP:
			snprintf(bufptr, remaining, "ip_proto: \"udp\"; ");
			break;
		case IP_PROTO_ICMP:
			snprintf(bufptr, remaining, "ip_proto: \"icmp\"; ");
			break;
		case IP_PROTO_IGMP:
			snprintf(bufptr, remaining, "ip_proto: \"igmp\"; ");
			break;
		case IP_PROTO_IP:
			snprintf(bufptr, remaining, "ip_proto: \"ip\"; ");
			break;
		default:
			snprintf(bufptr, remaining, "ip_proto: \"%u\"; ", sig->ip_proto);;
		}
		ADVANCE_POINTER_SAFELY;
	}

	if (sig->active & HC_SIG_IP_FLAGS) {
		
		int unset_bits = 0;
		int add_plus = 0;

		snprintf(bufptr, remaining, "fragbits: ");
		ADVANCE_POINTER_SAFELY;
		
		if ((sig->ip_flags_mask & sig->ip_flags) == 0)
			unset_bits = 1;

		if ((sig->ip_flags_mask & IP_RF) != 0) {
			if ((sig->ip_flags & IP_RF) != 0 || unset_bits) {
				snprintf(bufptr, remaining, "R");
				ADVANCE_POINTER_SAFELY;
			}
		} else
			add_plus = 1;
		
		if ((sig->ip_flags_mask & IP_DF) != 0) {
			if ((sig->ip_flags & IP_DF) != 0 || unset_bits) {
				snprintf(bufptr, remaining, "D");
				ADVANCE_POINTER_SAFELY;
			}
		} else
			add_plus = 1;
				
		if ((sig->ip_flags_mask & IP_MF) != 0) {
			if ((sig->ip_flags & IP_MF) != 0 || unset_bits) {
				snprintf(bufptr, remaining, "M");
				ADVANCE_POINTER_SAFELY;
			}
		} else
			add_plus = 1;
		
		if (unset_bits) {
			snprintf(bufptr, remaining, "-");
		} else if (add_plus) {
			snprintf(bufptr, remaining, "+");
			ADVANCE_POINTER_SAFELY;
		}
		
		snprintf(bufptr, remaining, "; ");
		ADVANCE_POINTER_SAFELY;
	}

	if (sig->active & HC_SIG_IP_FRAGOFF) {
		switch (sig->ip_fragoff_comp) {
		case HC_COMP_ST:
			snprintf(bufptr, remaining, "fragoffset: <%u; ", sig->ip_fragoff);
			break;
		case HC_COMP_STE:
			snprintf(bufptr, remaining, "fragoffset: <%u; ", sig->ip_fragoff + 1);
			break;
		case HC_COMP_GT:
			snprintf(bufptr, remaining, "fragoffset: >%u; ", sig->ip_fragoff);
			break;
		case HC_COMP_GTE:
			snprintf(bufptr, remaining, "fragoffset: >%u; ", sig->ip_fragoff - 1);
			break;
		case HC_COMP_EQ:
		default:
			snprintf(bufptr, remaining, "fragoffset: %u; ", sig->ip_fragoff);
		}
		ADVANCE_POINTER_SAFELY;
	}

	if (sig->active & HC_SIG_TCP_FLAGS) {
		
		int none_set = 0;
		int ignore_unmasked = 0;
		
		snprintf(bufptr, remaining, "flags: ");
		ADVANCE_POINTER_SAFELY;

		/* If none of the flags specified in the mask are set in
		 * the flags specification, we just request that these
		 * bits are unset.
		 */
		if ((sig->tcp_flags_mask & sig->tcp_flags) == 0)
			none_set = 1;

		if ((sig->tcp_flags_mask & TH_FIN) != 0) {
			if ((sig->tcp_flags & TH_FIN) != 0 || none_set) {
				snprintf(bufptr, remaining, "F");
				ADVANCE_POINTER_SAFELY;
			}
		} else
			ignore_unmasked = 1;

		if ((sig->tcp_flags_mask & TH_SYN) != 0) {
			if ((sig->tcp_flags & TH_SYN) != 0 || none_set) {
				snprintf(bufptr, remaining, "S");
				ADVANCE_POINTER_SAFELY;
			}
		} else
			ignore_unmasked = 1;
		if ((sig->tcp_flags_mask & TH_RST) != 0) {
			if ((sig->tcp_flags & TH_RST) != 0 || none_set) {
				snprintf(bufptr, remaining, "R");
				ADVANCE_POINTER_SAFELY;
			}
		} else
			ignore_unmasked = 1;
		
		if ((sig->tcp_flags_mask & TH_PUSH) != 0) {
			if ((sig->tcp_flags & TH_PUSH) != 0 || none_set) {
				snprintf(bufptr, remaining, "P");
				ADVANCE_POINTER_SAFELY;
			}
		} else
			ignore_unmasked = 1;
		
		if ((sig->tcp_flags_mask & TH_ACK) != 0) {
			if ((sig->tcp_flags & TH_ACK) != 0 || none_set) {
				snprintf(bufptr, remaining, "A");
				ADVANCE_POINTER_SAFELY;
			}
		} else
			ignore_unmasked = 1;
		
		if ((sig->tcp_flags_mask & TH_URG) != 0) {
			if ((sig->tcp_flags & TH_URG) != 0 || none_set) {
				snprintf(bufptr, remaining, "U");
				ADVANCE_POINTER_SAFELY;
			}
		} else
			ignore_unmasked = 1;
		
		if ((sig->tcp_flags_mask & TH_ECE) != 0) {
			if ((sig->tcp_flags & TH_ECE) != 0 || none_set) {
				snprintf(bufptr, remaining, "2");
				ADVANCE_POINTER_SAFELY;
			}
		} else
			ignore_unmasked = 1;
		
		if ((sig->tcp_flags_mask & TH_CWR) != 0) {
			if ((sig->tcp_flags & TH_CWR) != 0 || none_set) {
				snprintf(bufptr, remaining, "1");
				ADVANCE_POINTER_SAFELY;
			}
		} else
			ignore_unmasked = 1;		

		if ((sig->tcp_flags_mask == UCHAR_MAX) &&
		    (sig->tcp_flags == 0)) {
			snprintf(bufptr, remaining, "0");
		} else if (none_set) {
			snprintf(bufptr, remaining, "!");
		} else if (ignore_unmasked) {
			snprintf(bufptr, remaining, "+");
		}
		ADVANCE_POINTER_SAFELY;

		snprintf(bufptr, remaining, "; ");
		ADVANCE_POINTER_SAFELY;
	}

	if (sig->active & HC_SIG_TCP_ACK) {
		snprintf(bufptr, remaining, "ack: %u; ", sig->tcp_ack);
		ADVANCE_POINTER_SAFELY;
	}

	if (sig->active & HC_SIG_TCP_SEQ) {
		snprintf(bufptr, remaining, "seq: %u; ", sig->tcp_seq);
		ADVANCE_POINTER_SAFELY;
	}

	if (sig->active & HC_SIG_PAYLOAD) {

		switch (sig->payload_comp) {
		case HC_COMP_ST:
			snprintf(bufptr, remaining, "dsize: <%u; ", sig->payload);
			break;
		case HC_COMP_STE:
			snprintf(bufptr, remaining, "dsize: <%u; ", sig->payload + 1);
			break;
		case HC_COMP_GT:
			snprintf(bufptr, remaining, "dsize: >%u; ", sig->payload);
			break;
		case HC_COMP_GTE:
			snprintf(bufptr, remaining, "dsize: >%u; ", sig->payload - 1);
			break;
		case HC_COMP_EQ:
		default:
			snprintf(bufptr, remaining, "dsize: %u; ", sig->payload);
		}
		ADVANCE_POINTER_SAFELY;	       
	}

	if (sig->proto == IP_PROTO_TCP) {
		if ((sig->active & HC_SIG_TCP_EST) != 0) {
			snprintf(bufptr, remaining, "flow: established; ");
		} else {
			snprintf(bufptr, remaining, "flow: stateless; ");
		}
		ADVANCE_POINTER_SAFELY;	       
	}

	if (sig->active & HC_SIG_CONTENT) {

		/* This is our SNORT content data printer. It switches back
		 * and forth between ascii and hex mode whenever a (non)printable
		 * character is encountered.
		 */		
		u_int i, ascii = 1;

		snprintf(bufptr, remaining, "content: \"");
		ADVANCE_POINTER_SAFELY;
		
		for (i = 0; i < sig->content_len - 1; i++) {
			if (! isprint(sig->content[i])) {

				if (ascii == 1) {
					/* Switch from ascii to hex mode --> insert "|". */
					snprintf(bufptr, remaining, "|%.2X", sig->content[i]);
					ascii = 0;
				} else {
					snprintf(bufptr, remaining, " %.2X", sig->content[i]);
				}
			} else {

				if (ascii == 1) {
					snprintf(bufptr, remaining, "%c", sig->content[i]);
				} else {
					/* Switch from hex to ascii mode --> insert "|". */
					snprintf(bufptr, remaining, "|%c", sig->content[i]);
					ascii = 1;
				}
			}
			ADVANCE_POINTER_SAFELY;
		}

		/* If we're in hex mode at the end of the content string, e
		 * need to include another "|" in the output.
		 */
		if (!ascii)
			snprintf(bufptr, remaining, "|\"; ");
		else
			snprintf(bufptr, remaining, "\"; ");
		ADVANCE_POINTER_SAFELY;
	}
	
	snprintf(bufptr, remaining, ")");
	
	return 1;
}
