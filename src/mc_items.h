/*
 * twemcache - Twitter memcached.
 * Copyright (c) 2012, Twitter, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 * * Neither the name of the Twitter nor the names of its contributors
 *   may be used to endorse or promote products derived from this software
 *   without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _MC_ITEMS_H_
#define _MC_ITEMS_H_

#include <mc_slabs.h>

typedef enum item_flags {
    ITEM_LINKED  = 1,  /* item in hash */
    ITEM_SLABBED = 2,  /* item in free q */
} item_flags_t;

typedef enum item_store_result {
    NOT_STORED,
    STORED,
} item_store_result_t;

struct item_idx {
    TAILQ_ENTRY(item_idx) h_tqe;  /* link in hash */

    uint8_t               nkey;   /* key length */
    char                  *key;   /* key */

    uint32_t              sid;    /* owner slab id */
    uint32_t              offset; /* offset within owner slab */
};

TAILQ_HEAD(itx_tqh, item_idx);

/*
 * Every item chunk in the twemcache starts with an header (struct item)
 * followed by item data. An item is essentially a chunk of memory
 * carved out of a slab. Every item is owned by its parent slab
 *
 * Items are either linked or unlinked. When item is first allocated and
 * has no data, it is unlinked. When data is copied into an item, it is
 * linked into hash and lru q (ITEM_LINKED). When item is deleted either
 * explicitly or due to flush or expiry, it is moved in the free q
 * (ITEM_SLABBED). The flags ITEM_LINKED and ITEM_SLABBED are mutually
 * exclusive and when an item is unlinked it has neither of these flags
 *
 *   <-----------------------item size------------------>
 *   +---------------+----------------------------------+
 *   |               |                                  |
 *   |  item header  |          item payload            |
 *   | (struct item) |         ...      ...             |
 *   +---------------+-------+-------+------------------+
 *   ^               ^       ^       ^
 *   |               |       |       |
 *   |               |       |       |
 *   |               |       |       |
 *   |               |       |       \
 *   |               |       |       item_data()
 *   |               |       \
 *   \               |       item_key()
 *   item            \
 *                   item->end
 *
 * item->end is followed by:
 * - key with terminating '\0', length = item->nkey + 1
 * - data with no terminating '\0'
 */
struct item {
    uint32_t          magic;      /* item magic (const) */
    SLIST_ENTRY(item) h_sle;      /* link in hash */
    rel_time_t        exptime;    /* expiry time in secs */
    uint32_t          nbyte;      /* date size */
    uint32_t          offset;     /* offset of item in slab */
    uint32_t          dataflags;  /* data flags opaque to the server */
    uint16_t          refcount;   /* # concurrent users of item */
    uint8_t           flags;      /* item flags */
    uint8_t           cid;        /* slab class id */
    uint8_t           nkey;       /* key length */
    char              end[1];     /* item data */
};

SLIST_HEAD(item_slh, item);

TAILQ_HEAD(item_tqh, item);

#define ITEM_MAGIC      0xfeedface
#define ITEM_HDR_SIZE   offsetof(struct item, end)

/*
 * An item chunk is the portion of the memory carved out from the slab
 * for an item. An item chunk contains the item header followed by item
 * data.
 *
 * The smallest item data is actually a single byte key with a zero byte
 * value which internally is of sizeof("k"), as key is stored with
 * terminating '\0'.
 *
 * The largest item data is actually the room left in the slab_size()
 * slab, after the item header has been factored out
 */
#define ITEM_MIN_PAYLOAD_SIZE   (sizeof("k") + sizeof(uint64_t))
#define ITEM_MIN_CHUNK_SIZE     \
    MC_ALIGN(ITEM_HDR_SIZE + ITEM_MIN_PAYLOAD_SIZE, MC_ALIGNMENT)

#define ITEM_PAYLOAD_SIZE       32
#define ITEM_CHUNK_SIZE         \
    MC_ALIGN(ITEM_HDR_SIZE + ITEM_PAYLOAD_SIZE, MC_ALIGNMENT)

static inline bool
item_is_linked(struct item *it)
{
    return (it->flags & ITEM_LINKED) ? true : false;
}

static inline bool
item_is_slabbed(struct item *it)
{
    return (it->flags & ITEM_SLABBED) ? true : false;
}

static inline char *
item_key(struct item *it)
{
    ASSERT(it->magic == ITEM_MAGIC);

    return it->end;
}

static inline size_t
item_ntotal(uint8_t nkey, uint32_t nbyte)
{
    return ITEM_HDR_SIZE + nkey + 1 + nbyte;
}

static inline size_t
item_size(struct item *it)
{
    ASSERT(it->magic == ITEM_MAGIC);

    return item_ntotal(it->nkey, it->nbyte);
}

void item_init(void);
void item_deinit(void);
char *item_data(struct item *it);
struct slab *item_2_slab(struct item *it);
void item_hdr_init(struct item *it, uint32_t offset, uint8_t cid);
uint8_t item_slabcid(uint8_t nkey, uint32_t nbyte);
struct item *item_alloc(uint8_t cid, char *key, uint8_t nkey, uint32_t dataflags, rel_time_t exptime, uint32_t nbyte);
void item_delete(struct item *it);
void item_remove(struct item *it);
struct item *item_get(char *key, size_t nkey);
item_store_result_t item_store(struct item *it, req_type_t type, struct conn *c);

#endif
