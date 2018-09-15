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
#ifndef __hc_bitmap_queue_h
#define __hc_bitmap_queue_h

#include <stdlib.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/queue.h>


/* This header introduces three things:
 *
 * - HC_Blobs: chunks of byte data that is allocated at a given size and
 * can be incrementally filled up. Users can obtain the current fill status etc.
 *
 * - HC_Bitmaps: this is a bit of a misnomer and should rather be called
 * bloblist (FIXME really :) It mainly contains a tail queue of blobs,
 * keeping state regarding how many blobs are contained in it. Think of
 * it as a sequence of bitmaps as this is the context in which they're used
 * in in this plugin: as bitmaps to find masks/subsequences in.
 *
 * - HC_BitmapQueues: these are bounded queues of bitmap objects that
 * represent the "history" of packet data in which the plugin searches
 * for previously seen data.
 *
 *          <----   bounded length bitmap queue ---->
 *          +------+   +------+   +------+  \   +------+
 * add  --> | blob |-->| blob |-->| blob |- | ->| blob | --> drop
 *          +--+---+   +------+   +--+---+  |   +------+
 *             |                     |      |
 *          +--+---+              +--+---+  |
 *          | blob |              | blob |  +-> Bitmap
 *          +--+---+              +--+---+  |
 *                                   |      |
 *                                +--+---+  |
 *                                | blob |  |
 *                                +------+  /
 *             
 */

/* When checking bitmap fields, we're often interested in whether
 * or not all bits in a field are set. Most relevant values can be
 * found in limits.h; we make sure the rest is defined here.
 */
#undef  UNIBBLE_MAX
#define UNIBBLE_MAX 15

typedef struct hc_bitmap HC_Bitmap;

typedef struct hc_blob
{
	TAILQ_ENTRY(hc_blob)     items;
	u_char                  *data;
	u_int                    data_len;
	u_int                    data_used;

	/* The bitmap this blob belongs to: */
	HC_Bitmap               *map;

} HC_Blob;

TAILQ_HEAD(hc_blob_tq, hc_blob) blobs;


/* Bitmap queue items, each holding a list of one or more
 * HC_Blob objects.
 */
struct hc_bitmap
{
	TAILQ_ENTRY(hc_bitmap)   items;
	struct hc_blob_tq        blobs;
	u_int                    num_blobs;
	u_int                    blobs_size;

	HC_Blob                 *last_blob;
};

TAILQ_HEAD(hc_bitmap_tq, hc_bitmap);


/* This is the actual bitmap queue, linking up HC_BitmapQueues up
 * to a maximum length.
 */
typedef struct hc_bitmaps_queue
{
	struct hc_bitmap_tq      maps;

	u_int                    size;
	u_int                    max_size;
} HC_BitmapQueue;



/**
 * HC_BitmapCB - callback signature for hc_bitmap_queue_foreach().
 * @bitmap: bitmap contained in queue.
 * @user_data: arbitrary data passed to hc_bitmap_queue_foreach().
 *
 * This is the signature of callbacks you can pass to hc_bitmap_queue_foreach.
 */
typedef void (*HC_BitmapCB) (HC_Bitmap *bitmap, void *user_data);


/**
 * hc_blob_new - creates new blob.
 * @map: bitmap this blob belongs to. May be NULL.
 * @blob_len: size of blob data.
 *
 * The function creates a new blob with length @blob_len and
 * returns it. The new blob's data_used field is set to 0.
 *
 * Returns: new blob or %NULL when out of memory.
 */
HC_Blob         *hc_blob_new(HC_Bitmap *map, u_int blob_len);

/**
 * hc_blob_free - blob destructor.
 * @blob: blob to free.
 *
 * The function releases all memory occupied by @blob.
 */
void             hc_blob_free(HC_Blob *blob);


/**
 * hc_blob_crop - releases unused memory in blob.
 * @blob: blob to crop.
 *
 * Blobs are allocated with a certain size, afterwards chunks of data are
 * added. This function releases all the memory that was initially allocated
 * but is not currently used.
 */
void             hc_blob_crop(HC_Blob *blob);


/**
 * hc_bob_is_full - checks whether blob can hold more data.
 * @blob: blob to check.
 * 
 * Returns: value > 0 when the blob can hold more data, 0 otherwise.
 */
int              hc_blob_is_full(HC_Blob *blob);


/**
 * hc_blob_add_data - adds data to a blob.
 * @blob: blob to add data to.
 * @data: data to add.
 * @data_len: length of @data chunk.
 *
 * The function copies @data_len bytes starting at @data into the region of
 * @blob that is not yet used, up to the amount available in the blob.
 *
 * Returns: actual number of bytes copied.
 */
u_int            hc_blob_add_data(HC_Blob *blob, u_char *data, u_int data_len);


/**
 * hc_blob_get_mask - gets a bitmap of data chunks indicating identical bits.
 * @data1: first data chunk.
 * @data1_len: length of @data1.
 * @data2: second data chunk.
 * @data2_len: length of @data2.
 * @mask: result data
 * @mask_len: size of @mask in bytes.
 *
 * The function writes a one-bit into each bit in @mask where the corresponding
 * bits in @data1 and @data2 are either both 0 or both 1. If the mask is larger
 * than both @data1 and @data2, the rest of it is set to 0. Otherwise, only the
 * amount of data available in @mask is compared.
 */
void             hc_blob_get_mask(const u_char *data1, u_int data1_len,
				  const u_char *data2, u_int data2_len,
				  u_char *mask, u_int mask_len);


/**
 * hc_bitmap_new - creates a new bitmap.
 * @data_len: length of data for bitmap.
 *
 * The function creates a new bitmap consisting of one empty blob of
 * @data_len.
 *
 * Returns: new bitmap, or @NULL if out of memory.
 */
HC_Bitmap       *hc_bitmap_new(u_int data_len);


/**
 * hc_bitmap_new_with_data - creates a bitmap with data.
 * @data: data to put into bitmap.
 * @data_len: size of @data.
 *
 * This funtion is like hc_bitmap_new() but puts data into the bitmap
 * right away. @data is copied into the blob.
 *
 * Returns: new bitmap, or %NULL if out of memory.
 */
HC_Bitmap       *hc_bitmap_new_with_data(u_char *data, u_int data_len);


/**
 * hc_bitmap_free - releases bitmap memory.
 * @map: bitmap to free.
 *
 * The function releases all memory occupied by @map.
 */
void             hc_bitmap_free(HC_Bitmap *map);


/**
 * hc_bitmap_add_blob - adds a blob to the bitmap.
 * @map: bitmap to add data to.
 * @data: blob data to add to bitmap.
 * @data_len: size of @data.
 * @blob_size: size of blob to allocate.
 *
 * The function adds a new blob of @blob_size containing
 * @data to the bitmap.
 */
void             hc_bitmap_add_blob(HC_Bitmap *map, u_char *data,
				    u_int data_len, u_int blob_size);


/**
 * hc_bitmap_get_last_blob - returns most recent blob in map.
 * @map: map to query.
 *
 * The function returns the most recently added blob in @map.
 */
HC_Blob         *hc_bitmap_get_last_blob(HC_Bitmap *map);


/**
 * hc_bitmap_get_mask - creates a mask bitmap for two bitmaps.
 * @map1: first input map.
 * @map2: second input map.
 *
 * The function fills the @mask bitmap as much as possible with
 * one bits where the corresponding blobs in @map1 and @map2
 * have matching bits.
 */
void             hc_bitmap_get_mask(const HC_Bitmap *map1,
				    const HC_Bitmap *map2,
				    HC_Bitmap *mask);



/**
 * hc_bitmap_queue_new - creates new bitmap queue.
 * @max_size: size limit for new bounded queue.
 * 
 * Creates new queue for bitmap objects, limited to @max_size.
 * Bitmaps are dropped off the far end of the queue once it
 * hits the size limit.
 *
 * Returns: new bitmap queue, or %NULL when out of memory.
 */
HC_BitmapQueue  *hc_bitmap_queue_new(u_int max_size);


/**
 * hc_bitmap_queue_free - releases queue.
 * @queue: queue to free.
 *
 * The function releases all memory occupied by @queue, including
 * all the bitmaps currently contained in it.
 */
void             hc_bitmap_queue_free(HC_BitmapQueue *queue);


/**
 * hc_bitmap_queue_add - adds a bitmap to the queue.
 * @queue: queue to add bitmap to.
 * @bitmap: bitmap to add.
 *
 * The function adds @bitmap to @queue.
 */
void             hc_bitmap_queue_add(HC_BitmapQueue *queue, HC_Bitmap *bitmap);


/**
 * hc_bitmap_queue_foreach - queue element iterator.
 * @queue: queue to iterate over.
 * @callback: callback to call for each queue item.
 * @data: arbitrary user data to pass to @callback.
 *
 * This is a queue item iterator that calls @callback with every item
 * currently contained in @queue, passing it that item and @data.
 */
void             hc_bitmap_queue_foreach(HC_BitmapQueue *queue,
					 HC_BitmapCB callback, void *data);

#endif
