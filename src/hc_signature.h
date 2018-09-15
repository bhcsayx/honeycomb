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
#ifndef __hc_signature_h
#define __hc_signature_h

#include <time.h>
#include <sys/time.h>
#include <event.h>
#include "honeycomb.h"

/* Comparison operators. The meaning here is that the
 * value in the *packet* should be smaller, equal, larger,
 * etc than the value in the signature.
 */
typedef enum
{
	HC_COMP_NA          = 0,  /* not applicable */
	HC_COMP_ST          = 1,  /* smaller than */
	HC_COMP_STE         = 2,  /* smaller than or equal */
	HC_COMP_EQ          = 4,  /* equal */
	HC_COMP_GT          = 8,  /* greater than */
	HC_COMP_GTE         = 16, /* greater than or equal */
	HC_COMP_NE          = 32  /* not equal */
} HC_CheckType;


/* This enum defines the various building blocks contained
 * in our signatures.
 */
typedef enum
{
	HC_SIG_IP_HL        = (1 << 0),
	HC_SIG_IP_TOS       = (1 << 1),
	HC_SIG_IP_LEN       = (1 << 2),
	HC_SIG_IP_ID        = (1 << 3),
	HC_SIG_IP_TTL       = (1 << 4),
	HC_SIG_IP_PROTO     = (1 << 5),
	HC_SIG_IP_FLAGS     = (1 << 6),
	HC_SIG_IP_FRAGOFF   = (1 << 7),
	HC_SIG_IP_SRC       = (1 << 8),
	HC_SIG_IP_DST       = (1 << 9),
	HC_SIG_PORT_SRC     = (1 << 10),
	HC_SIG_PORT_DST     = (1 << 11),
	HC_SIG_TCP_FLAGS    = (1 << 12),
	HC_SIG_TCP_SEQ      = (1 << 13),
	HC_SIG_TCP_ACK      = (1 << 14),
	HC_SIG_TCP_EST      = (1 << 15),
	HC_SIG_PAYLOAD      = (1 << 16),
	HC_SIG_CONTENT      = (1 << 17)
} HC_SigActiveFlags;


/* This structure defines a port number range.
 */
typedef struct hc_signature_port
{
	uint16_t      val1;
	HC_CheckType  comp1;
	uint16_t      val2;
	HC_CheckType  comp2;

} HC_SignaturePort;



/* Here's our concept of a signature. It's kept independent of
 * any particular IDS - it's up to the output handlers to make
 * the best use for the information given for the specific
 * system. Field names should be obvious.
 */
typedef struct hc_signature
{
	uint16_t              id;
	u_int                 duplicates;

	time_t                timestamp;

	u_char               *portmap;

	uint8_t               proto;
	HC_SigActiveFlags     active;

	uint8_t               ip_hl;
	uint8_t               ip_tos;
	uint16_t              ip_len;
	uint16_t              ip_id;

	uint8_t               ip_ttl;
	HC_CheckType          ip_ttl_comp;

	uint8_t               ip_proto;
	
	uint16_t              ip_flags;
	uint16_t              ip_flags_mask;

	uint16_t              ip_fragoff;
	HC_CheckType          ip_fragoff_comp;

	ip_addr_t             ip_src;
	int                   ip_src_mask;

	ip_addr_t             ip_dst;
	int                   ip_dst_mask;

	HC_SignaturePort      port_src;
	HC_SignaturePort      port_dst;
	uint16_t              port_dst_orig1;
	uint16_t              port_dst_orig2;

	uint8_t               tcp_flags;
	uint8_t               tcp_flags_mask;

	uint32_t              tcp_seq;
	uint32_t              tcp_ack;

	uint32_t              payload;
	HC_CheckType          payload_comp;

	u_char               *content;
	u_int                 content_len;

	char                 *comment;

} HC_Signature;



/**
 * HC_SigPrintFunc - signature of a signature output function.
 * @sig: signature to print.
 * @buf: buffer to print signature into.
 * @buflen: length of @buf.
 *
 * This signature is used for signature printers accepted by
 * hc_sig_set_printer(). We currently output signatures as text
 * data, this'll need to change in case some IDS stores them in
 * a binary format.
 *
 * Returns: value > 0 if output was possible or 0 if not.
 */
typedef int (*HC_SigPrintFunc) (const HC_Signature *sig, char *buf, u_int buflen);


/**
 * hc_sig_set_print - sets output function.
 * @print_func: new output function to use.
 *
 * The function sets the print handler used in subsequent calls
 * to hc_sig_print().
 */
void          hc_sig_set_printer(HC_SigPrintFunc print_func);

/**
 * hc_sig_print - prints signature into a buffer.
 * @sig: signature to print.
 * @buf: buffer to print signature into.
 * @buflen: length of @buf.
 *
 * The function prints @sig into @buf, using the printer function set
 * with hc_sig_set_printer().
 */ 
void          hc_sig_print(const HC_Signature *sig, char *buf, u_int buflen);


/**
 * hc_sig_new - creates new signature.
 *
 * The function creates a new empty signature and returns it.
 *
 * Returns: new signature, or %NULL when out of memory.
 */
HC_Signature *hc_sig_new(void);


/**
 * hc_sig_free - releases signature's memory.
 * @sig: signature to clear.
 * 
 * The function releases all memory occupied by @sig.
 */
void          hc_sig_free(HC_Signature *sig);


/**
 * hc_sig_init - initializes signature structure.
 * @sig: signature to initialize.
 * 
 * The function initializes a new signature like hc_sig_new() but
 * used an existing structure instead of allocating one.
 */
void          hc_sig_init(HC_Signature *sig);


/**
 * hc_sig_clear - counterpart to hc_sig_init().
 * @sig: signature to clean up.
 *
 * This is the counterpart to hc_sig_init() in that it releases
 * any memory occupied by @sig but not the structure itself.
 */
void          hc_sig_clear(HC_Signature *sig);


/**
 * hc_sig_contained - checks if one signature's checks are contained in another.
 * @sig1: first signature.
 * @sig2: second signature.
 *
 * The function checks whether @sig1's tests are a subset of the tests
 * performed by @sig2.
 *
 * Returns: value > 0 when the @sig1 is contained, 0 otherwise.
 */
int           hc_sig_contained(HC_Signature *sig1, HC_Signature *sig2);


/**
 * hc_sig_equal - compares two signatures.
 * @sig1: first signature.
 * @sig2: second signature.
 *
 * The function checks whether two signatures define the same
 * set of traffic.
 *
 * Returns: value > 0 when the signatures match, 0 otherwise.
 */
int           hc_sig_equal(HC_Signature *sig1, HC_Signature *sig2);

/**
 * hc_sig_copy - duplicates a signature.
 * @sig: signature to copy.
 *
 * Returns: copy of @sig, or %NULL if out of memory.
 */
HC_Signature *hc_sig_copy(const HC_Signature *sig);


/* The functions below set various characteristics in the signature,
 * meaning should be obvious.
 */

void          hc_sig_set_ip_hl(HC_Signature *sig, uint8_t hl);
void          hc_sig_set_ip_tos(HC_Signature *sig, uint8_t tos);
void          hc_sig_set_ip_len(HC_Signature *sig, uint16_t len);
void          hc_sig_set_ip_id(HC_Signature *sig, uint16_t id);
void          hc_sig_set_ip_ttl(HC_Signature *sig, uint8_t ttl, HC_CheckType check);
void          hc_sig_set_ip_proto(HC_Signature *sig, uint8_t proto);
void          hc_sig_set_ip_flag(HC_Signature *sig, uint16_t bit, int state);
void          hc_sig_set_ip_fragoffset(HC_Signature *sig, uint16_t offset, HC_CheckType check);
void          hc_sig_set_ip_src(HC_Signature *sig, ip_addr_t addr, u_int netmask);
void          hc_sig_set_ip_dst(HC_Signature *sig, ip_addr_t addr, u_int netmask);

void          hc_sig_set_proto(HC_Signature *sig, int proto);

void          hc_sig_set_src_port(HC_Signature *sig,
				  uint16_t port1, HC_CheckType check1,
				  uint16_t port2, HC_CheckType check2);

void          hc_sig_set_dst_port(HC_Signature *sig,
				  uint16_t port1, HC_CheckType check1,
				  uint16_t port2, HC_CheckType check2);

void          hc_sig_set_orig_dports(HC_Signature *sig,
				     uint16_t port1, uint16_t port2);

void          hc_sig_set_tcp_flags(HC_Signature *sig, uint8_t bits, int state);
void          hc_sig_set_tcp_seq(HC_Signature *sig, uint32_t seq);
void          hc_sig_set_tcp_ack(HC_Signature *sig, uint32_t ack);
void          hc_sig_set_tcp_est(HC_Signature *sig);

void          hc_sig_set_payload_size(HC_Signature *sig, u_int size, HC_CheckType check);

void          hc_sig_set_content(HC_Signature *sig, u_char *data, u_int data_len);

void          hc_sig_add_comment(HC_Signature *sig, u_char *comment);

#endif
