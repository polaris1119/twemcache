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

#include <stdlib.h>
#include <stdio.h>

#include <mc_core.h>

extern struct settings settings;

/*
 * Return true if the item has expired, otherwise return false. Items
 * with expiry of 0 are considered as unexpirable.
 */
static bool
item_expired(struct item *it)
{
    ASSERT(it->magic == ITEM_MAGIC);

    return (it->exptime != 0 && it->exptime < time_now()) ? true : false;
}

void
item_init(void)
{
}

void
item_deinit(void)
{
}

/*
 * Get start location of item payload
 */
char *
item_data(struct item *it)
{
    ASSERT(it->magic == ITEM_MAGIC);

    return it->end + it->nkey + 1; /* 1 for terminal '\0' in key */
}

/*
 * Get the slab that contains this item.
 */
struct slab *
item_2_slab(struct item *it)
{
    struct slab *slab;

    ASSERT(it->magic == ITEM_MAGIC);
    ASSERT(it->offset < settings.slab_size);

    slab = (struct slab *)((uint8_t *)it - it->offset);

    ASSERT(slab->magic == SLAB_MAGIC);

    return slab;
}

void
item_hdr_init(struct item *it, uint32_t offset, uint8_t cid, uint32_t sid)
{
    ASSERT(offset >= SLAB_HDR_SIZE && offset < settings.slab_size);

    it->magic = ITEM_MAGIC;
    it->offset = offset;
    it->cid = cid;
    it->flags = 0;
    it->sid = sid;
}

uint8_t
item_slabcid(uint8_t nkey, uint32_t nbyte)
{
    size_t ntotal;
    uint8_t cid;

    ntotal = item_ntotal(nkey, nbyte);

    cid = slab_cid(ntotal);
    if (cid == SLABCLASS_INVALID_ID) {
        log_debug(LOG_NOTICE, "slab class id out of range with %"PRIu8" bytes "
                  "key, %"PRIu32" bytes value and %zu item chunk size", nkey,
                  nbyte, ntotal);
    }

    return cid;
}

/*
 * Allocate an item. We allocate an item by consuming the next free item
 * from slab of the item's an slab class.
 *
 * On success we return the pointer to the allocated item.
 */
struct item *
item_alloc(uint8_t cid, char *key, uint8_t nkey, uint32_t dataflags,
           rel_time_t exptime, uint32_t nbyte)
{
    struct item *it;

    ASSERT(cid >= SLABCLASS_MIN_ID && cid <= SLABCLASS_MAX_ID);

    it = slab_get_item(cid);
    if (it == NULL) {
        log_warn("server error on allocating item in slab %"PRIu8, cid);
        return NULL;
    }

    ASSERT(it->cid == cid);
    ASSERT(!item_is_linked(it));
    ASSERT(!item_is_slabbed(it));
    ASSERT(it->offset != 0);

    it->flags = 0;
    it->dataflags = dataflags;
    it->nbyte = nbyte;
    it->exptime = exptime;
    it->nkey = nkey;
    memcpy(item_key(it), key, nkey);

    stats_slab_incr(cid, item_acquire);

    log_debug(LOG_VERB, "alloc it '%.*s' at offset %"PRIu32" with cid %"PRIu8
              " expiry %u", it->nkey, item_key(it), it->offset, it->cid,
              it->exptime);

    return it;
}

static void
item_free(struct item *it)
{
    ASSERT(it->magic == ITEM_MAGIC);
    slab_put_item(it);
}

/*
 * Link an item into the hash table and lru q
 */
static void
item_link(struct item *it)
{
    ASSERT(it->magic == ITEM_MAGIC);
    ASSERT(!item_is_linked(it));
    ASSERT(!item_is_slabbed(it));

    log_debug(LOG_DEBUG, "link it '%.*s' at offset %"PRIu32" with flags "
              "%02x cid %"PRId8"", it->nkey, item_key(it), it->offset,
              it->flags, it->cid);

    it->flags |= ITEM_LINKED;

    assoc_insert(item_key(it), it->nkey, it->sid, it->offset);
}

/*
 * Unlinks an item from the hash table and free it.
 */
static void
item_unlink(struct item *it)
{
    ASSERT(it->magic == ITEM_MAGIC);
    ASSERT(item_is_linked(it));

    log_debug(LOG_DEBUG, "unlink it '%.*s' at offset %"PRIu32" with flags "
              "%02x cid %"PRId8"", it->nkey, item_key(it), it->offset,
              it->flags, it->cid);

    if (item_is_linked(it)) {
        it->flags &= ~ITEM_LINKED;
        assoc_delete(item_key(it), it->nkey);
        item_free(it);
    }
}

/*
 * Free an item if it is unlinked.
 */
void
item_remove(struct item *it)
{
    ASSERT(it->magic == ITEM_MAGIC);
    ASSERT(!item_is_slabbed(it));

    if (item_is_linked(it)) {
        return;
    }

    log_debug(LOG_DEBUG, "remove it '%.*s' at offset %"PRIu32" with flags "
              "%02x cid %"PRId8"", it->nkey, item_key(it), it->offset,
              it->flags, it->cid);

    item_free(it);
}

/*
 * Unlink an item and remove it (if its recount drops to zero).
 */
void
item_delete(struct item *it)
{
    item_unlink(it);
    item_remove(it);
}

/*
 * Replace one item with another in the hash table and lru q.
 */
static void
item_replace(struct item *it, struct item *nit)
{
    ASSERT(it->magic == ITEM_MAGIC);
    ASSERT(!item_is_slabbed(it));

    ASSERT(nit->magic == ITEM_MAGIC);
    ASSERT(!item_is_slabbed(nit));

    log_debug(LOG_VERB, "replace it '%.*s' at offset %"PRIu32" cid %"PRIu8" "
              "with one at offset %"PRIu32" cid %"PRIu8"", it->nkey,
              item_key(it), it->offset, it->cid, nit->offset, nit->cid);

    item_unlink(it);
    item_link(nit);
}

/*
 * Return an item if it hasn't been marked as expired, lazily expiring
 * item as-and-when needed
 */
struct item *
item_get(char *key, size_t nkey)
{
    struct item_idx *itx;
    struct item *it;

    itx = assoc_find(key, nkey);
    if (itx == NULL) {
        log_debug(LOG_VERB, "get itx '%.*s' not found", nkey, key);
        return NULL;
    }

    struct slab *slab = slab_read(itx->sid);

    it = (struct item *)((uint8_t *)slab + itx->offset);

    if (item_expired(it)) {
        item_unlink(it);
        stats_slab_incr(it->cid, item_expire);
        stats_slab_settime(it->cid, item_reclaim_ts, time_now());
        stats_slab_settime(it->cid, item_expire_ts, it->exptime);
        log_debug(LOG_VERB, "get it '%.*s' expired and nuked", nkey, key);
        return NULL;
    }

    log_debug(LOG_VERB, "get it '%.*s' found at offset %"PRIu32" with flags "
              "%02x cid %"PRIu8"", it->nkey, item_key(it),
              it->offset, it->flags, it->cid);

    return it;
}


item_store_result_t
item_store(struct item *it, req_type_t type, struct conn *c)
{
    char *key;                   /* item key */
    struct item *oit;            /* old (existing) item */

    key = item_key(it);

    oit = item_get(key, it->nkey);

    if (oit != NULL) {
        item_replace(oit, it);
    } else {
        item_link(it);
    }

    /* release our reference, if any */
    if (oit != NULL) {
        item_remove(oit);
    }

    return STORED;
}
