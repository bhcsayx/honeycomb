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

#include "honeycomb.h"
#include "hc_debug.h"
#include "hc_bitmaps.h"


#define HC_LARGEST_MASK     16384


/* dnet should really use a prefix for its symbols.
 * Noticed that blob_new() clashes with dnet...
 */
HC_Blob *
hc_blob_new(HC_Bitmap *map, u_int blob_len)
{
	HC_Blob   *blob;

	if (! (blob = calloc(1, sizeof(HC_Blob)))) {
		D(("Out of memory\n"));
		return NULL;
	}

	blob->data_len  = blob_len;
	blob->data_used = 0;

	if (! (blob->data = malloc(sizeof(u_char) * blob_len))) {
		D(("Out of memory\n"));
		free(blob);
		return NULL;
	}
	
	blob->map = map;

	return blob;
}


void
hc_blob_free(HC_Blob *blob)
{
	if (!blob)
		return;

	if (blob->data)
		free(blob->data);
	
	free(blob);
}


void             
hc_blob_crop(HC_Blob *blob)
{
	if (!blob || blob->data_len == blob->data_used)
		return;

	if (blob->data_used == 0) {
		
		/* We don't completely nuke the memory to
		 * avoid complicating the code. We instead crop
		 * it to a single byte, but set the data_len
		 * flag to 0. Basically this shouldn't happen anyway.
		 */

		D(("Caution -- cropping 0-byte blob\n"));
		blob->data = realloc(blob->data, sizeof(u_char));
		blob->data_len = blob->data_used = 0;
		return;
	}
	
	blob->data = realloc(blob->data, sizeof(u_char) * blob->data_used);
	blob->data_len = blob->data_used;
	D(("Cropping blob to %u bytes.\n", blob->data_used));
}


int              
hc_blob_is_full(HC_Blob *blob)
{
	if (!blob)
		return 0;

	return (blob->data_used == blob->data_len);
}


u_int         
hc_blob_add_data(HC_Blob *blob, u_char *data, u_int data_len)
{
	u_int data_left, data_copied;

	if (!blob || !data || data_len == 0) {
		D(("Invalid blob input %p %p %u %u %u\n",
		   blob, data, data_len, blob->data_used, blob->data_len));
		return 0;
	}
	
	if (blob->data_used == blob->data_len) {
		D(("Blob full -- not adding data\n"));
		return 0;
	}
	
	data_left   = blob->data_len - blob->data_used;
	data_copied = MIN(data_left, data_len);

	memcpy(blob->data + blob->data_used, data, data_copied);
	blob->data_used += data_copied;
	D(("Adding to blob, now %u %u\n", blob->data_used, blob->data_len));

	if (blob->map)
		blob->map->blobs_size += data_len;

	return data_copied;	
}


void
hc_blob_get_mask(const u_char *data1, u_int data1_len,
		 const u_char *data2, u_int data2_len,
		 u_char *mask, u_int mask_len)
{
	u_int len = 0, i;
	const u_char *data1_ptr, *data2_ptr;
	u_char *mask_ptr;
	
	memset(mask, 0, sizeof(u_char) * mask_len);	
	len = MIN(MIN(data1_len, data2_len), mask_len);	
	data1_ptr = data1; data2_ptr = data2; mask_ptr = mask;
	
	for (i = 0; i < len; i++) {
		
		*mask_ptr = ~(*data1_ptr ^ *data2_ptr);
		mask_ptr++; data1_ptr++; data2_ptr++;
	}
}


HC_Bitmap *
hc_bitmap_new(u_int blob_len)
{
	HC_Bitmap *map;
	HC_Blob   *blob;

	if (blob_len == 0)
		return NULL;

	if (! (map = calloc(1, sizeof(HC_Bitmap)))) {
		D(("Out of memory\n"));
		return NULL;
	}
	
	if (! (blob = hc_blob_new(map, blob_len))) {
		D(("Out of memory\n"));
		free(map);
		return NULL;
	}

	TAILQ_INIT(&map->blobs);

	TAILQ_INSERT_TAIL(&map->blobs, blob, items);
	map->num_blobs = 1;
	map->last_blob = blob;
	
	return map;
}


HC_Bitmap *
hc_bitmap_new_with_data(u_char *data, u_int data_len)
{
	HC_Bitmap *map;

	if (! (map = hc_bitmap_new(data_len)))
		return NULL;

	hc_blob_add_data(map->last_blob, data, data_len);

	return map;
}


void
hc_bitmap_free(HC_Bitmap *map)
{
	HC_Blob *blob;

	if (!map)
		return;

	while (map->blobs.tqh_first) {

		blob = map->blobs.tqh_first;
		TAILQ_REMOVE(&map->blobs, blob, items);
		hc_blob_free(blob);
	}

	free(map);
}


void             
hc_bitmap_get_mask(const HC_Bitmap *map1,
		   const HC_Bitmap *map2,
		   HC_Bitmap *mask)
{
	HC_Blob *blob1, *blob2, *blob3;
	u_int num_blobs, i;
	
	if (!map1 || !map2 || !mask)
		return;
	
	num_blobs = MIN(MIN(map1->num_blobs, map2->num_blobs), mask->num_blobs);
	blob1 = map1->blobs.tqh_first;
	blob2 = map2->blobs.tqh_first;
	blob3 = mask->blobs.tqh_first;
	
	for (i = 0; i < num_blobs; i++) {
		
		hc_blob_get_mask(blob1->data, blob1->data_len,
				 blob2->data, blob2->data_len,
				 blob3->data, blob3->data_len);
		
		blob1 = blob1->items.tqe_next;
		blob2 = blob2->items.tqe_next;
		blob3 = blob3->items.tqe_next;
	}
}


HC_BitmapQueue *
hc_bitmap_queue_new(u_int max_size)
{
	HC_BitmapQueue *queue;

	if (max_size == 0)
		return NULL;
	
	if (! (queue = calloc(1, sizeof(HC_BitmapQueue)))) {
		D(("Out of memory\n"));
		return NULL;
	}

	TAILQ_INIT(&queue->maps);
	queue->max_size = max_size;

	return queue;
}


void             
hc_bitmap_queue_free(HC_BitmapQueue *queue)
{
	HC_Bitmap *map;

	if (!queue)
		return;

	while (queue->maps.tqh_first) {
		map = queue->maps.tqh_first;
		TAILQ_REMOVE(&queue->maps, map, items);
		hc_bitmap_free(map);
	}

	free(queue);
}


void             
hc_bitmap_add_blob(HC_Bitmap *map, u_char *data, u_int data_len, u_int blob_size)
{
	HC_Blob *blob;

	if (!map)
		return;

	if (! (blob = hc_blob_new(map, blob_size))) {
		D(("Out of memory.\n"));
		return;
	}

	hc_blob_add_data(blob, data, data_len);
	
	TAILQ_INSERT_TAIL(&map->blobs, blob, items);
	map->num_blobs++;
	map->last_blob = blob;
}


HC_Blob *
hc_bitmap_get_last_blob(HC_Bitmap *map)
{
	if (!map)
		return NULL;

	return map->last_blob;
}


void
hc_bitmap_queue_add(HC_BitmapQueue *queue, HC_Bitmap *bitmap)
{
	HC_Bitmap *map = NULL;

	if (!queue || !bitmap)
		return;      	
	
	TAILQ_INSERT_TAIL(&queue->maps, bitmap, items);
	queue->size++;

	if (queue->size <= queue->max_size)
		return;
	
	map = queue->maps.tqh_first;
	TAILQ_REMOVE(&queue->maps, map, items);
	hc_bitmap_free(map);
	
	queue->size--;
}


void             
hc_bitmap_queue_foreach(HC_BitmapQueue *queue,
			HC_BitmapCB callback, void *user_data)
{
	HC_Bitmap *map;

	if (!queue || !callback)
		return;

	for (map = queue->maps.tqh_first; map; map = map->items.tqe_next)
		callback(map, user_data);
	
}
