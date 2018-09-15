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

#include "hc_debug.h"
#include "hc_string_alg.h"


LST_String   *
hc_string_alg_lcs(u_char *data1, u_int data1_len,
		  u_char *data2, u_int data2_len,
		  u_int min_len)
{
	LST_STree  tree;
	LST_String payload1, payload2;
	LST_StringSet *strings;
	LST_String *pattern = NULL;		

	if (!data1 || data1_len == 0 || !data2 || data2_len == 0) {
		D(("Invalid string matching input\n"));
		return NULL;
	}
	
	/* Initialize the suffix tree: */
	if (!lst_stree_init(&tree)) {
		D(("Out of memory\n"));
		return NULL;
	}
	
	/* Initialize the string representations: */
	lst_string_init(&payload1, data1, 1, data1_len);
	lst_string_init(&payload2, data2, 1, data2_len);

	/*
	D(("String1: %s\n", lst_string_print(&payload1)));
	D(("String2: %s\n", lst_string_print(&payload2)));
	*/

	/* Insert them into the tree: */
	lst_stree_add_string(&tree, &payload1);
	lst_stree_add_string(&tree, &payload2);
	
	/* Find all longest common substrings: */
	strings = lst_alg_longest_common_substring(&tree, min_len, 0);
	
	if (strings) {
		
		/* Woohoo! We found something! Now what we should do
		 * ideally is check the payload type and ignore substrings
		 * or substring parts that consist of protocol-inherent
		 * information (ie stuff that is *always* contained in
		 * packet data of the given protocol. For now mark this
		 * as a big FIXME and just pick the first substring we've
		 * found ...*/
		
		pattern = strings->members.lh_first;
		lst_stringset_remove(strings, pattern);
		lst_stringset_free(strings);
	}

	lst_stree_clear(&tree);

	return pattern;
}

