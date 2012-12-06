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

pthread_mutex_t cache_lock; /* lock protecting hash */

/*
 * Return true if the item has expired, otherwise return false. Items
 * with expiry of 0 are considered as unexpirable.
 */
static bool
item_expired(struct item *it)
{
    ASSERT(it->magic == ITEM_MAGIC);

    return (it->exptime != 0 && it->exptime > time_now()) ? true : false;
}

void
item_init(void)
{
    pthread_mutex_init(&cache_lock, NULL);
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

static void
item_acquire_refcount(struct item *it)
{
    ASSERT(pthread_mutex_trylock(&cache_lock) != 0);
    ASSERT(it->magic == ITEM_MAGIC);

    it->refcount++;
    slab_acquire_refcount(item_2_slab(it));
}

static void
item_release_refcount(struct item *it)
{
    ASSERT(pthread_mutex_trylock(&cache_lock) != 0);
    ASSERT(it->magic == ITEM_MAGIC);
    ASSERT(it->refcount > 0);

    it->refcount--;
    slab_release_refcount(item_2_slab(it));
}

void
item_hdr_init(struct item *it, uint32_t offset, uint8_t id)
{
    ASSERT(offset >= SLAB_HDR_SIZE && offset < settings.slab_size);

    it->magic = ITEM_MAGIC;
    it->offset = offset;
    it->id = id;
    it->refcount = 0;
    it->flags = 0;
}

uint8_t
item_slabid(uint8_t nkey, uint32_t nbyte)
{
    size_t ntotal;
    uint8_t id;

    ntotal = item_ntotal(nkey, nbyte);

    id = slab_id(ntotal);
    if (id == SLABCLASS_INVALID_ID) {
        log_debug(LOG_NOTICE, "slab class id out of range with %"PRIu8" bytes "
                  "key, %"PRIu32" bytes value and %zu item chunk size", nkey,
                  nbyte, ntotal);
    }

    return id;
}

/*
 * Allocate an item. We allocate an item by consuming the next free item
 * from slab of the item's an slab class.
 *
 * On success we return the pointer to the allocated item. The returned item
 * is refcounted so that it is not deleted under callers nose. It is the
 * callers responsibilty to release this refcount when the item is inserted
 * into the hash or freed.
 */
static struct item *
_item_alloc(uint8_t id, char *key, uint8_t nkey, uint32_t dataflags,
            rel_time_t exptime, uint32_t nbyte)
{
    struct item *it;

    ASSERT(id >= SLABCLASS_MIN_ID && id <= SLABCLASS_MAX_ID);

    it = slab_get_item(id);
    if (it == NULL) {
        log_warn("server error on allocating item in slab %"PRIu8, id);
        return NULL;
    }

    ASSERT(it->id == id);
    ASSERT(!item_is_linked(it));
    ASSERT(!item_is_slabbed(it));
    ASSERT(it->offset != 0);
    ASSERT(it->refcount == 0);

    item_acquire_refcount(it);

    it->flags = 0;
    it->dataflags = dataflags;
    it->nbyte = nbyte;
    it->exptime = exptime;
    it->nkey = nkey;
    memcpy(item_key(it), key, nkey);

    stats_slab_incr(id, item_acquire);

    log_debug(LOG_VERB, "alloc it '%.*s' at offset %"PRIu32" with id %"PRIu8
              " expiry %u refcount %"PRIu16"", it->nkey, item_key(it),
              it->offset, it->id, it->exptime, it->refcount);

    return it;
}

struct item *
item_alloc(uint8_t id, char *key, size_t nkey, uint32_t flags,
           rel_time_t exptime, uint32_t nbyte)
{
    struct item *it;

    pthread_mutex_lock(&cache_lock);
    it = _item_alloc(id, key, nkey, flags, exptime, nbyte);
    pthread_mutex_unlock(&cache_lock);

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
_item_link(struct item *it)
{
    ASSERT(it->magic == ITEM_MAGIC);
    ASSERT(!item_is_linked(it));
    ASSERT(!item_is_slabbed(it));

    log_debug(LOG_DEBUG, "link it '%.*s' at offset %"PRIu32" with flags "
              "%02x id %"PRId8"", it->nkey, item_key(it), it->offset,
              it->flags, it->id);

    it->flags |= ITEM_LINKED;

    assoc_insert(it);
}

/*
 * Unlinks an item from the lru q and hash table. Free an unlinked
 * item if it's refcount is zero.
 */
static void
_item_unlink(struct item *it)
{
    ASSERT(it->magic == ITEM_MAGIC);
    ASSERT(item_is_linked(it));

    log_debug(LOG_DEBUG, "unlink it '%.*s' at offset %"PRIu32" with flags "
              "%02x id %"PRId8"", it->nkey, item_key(it), it->offset,
              it->flags, it->id);

    if (item_is_linked(it)) {
        it->flags &= ~ITEM_LINKED;

        assoc_delete(item_key(it), it->nkey);

        if (it->refcount == 0) {
            item_free(it);
        }
    }
}

/*
 * Decrement the refcount on an item. Free an unliked item if its refcount
 * drops to zero.
 */
static void
_item_remove(struct item *it)
{
    ASSERT(it->magic == ITEM_MAGIC);
    ASSERT(!item_is_slabbed(it));

    log_debug(LOG_DEBUG, "remove it '%.*s' at offset %"PRIu32" with flags "
              "%02x id %"PRId8" refcount %"PRIu16"", it->nkey, item_key(it),
              it->offset, it->flags, it->id, it->refcount);

    if (it->refcount != 0) {
        item_release_refcount(it);
    }

    if (it->refcount == 0 && !item_is_linked(it)) {
        item_free(it);
    }
}

void
item_remove(struct item *it)
{
    pthread_mutex_lock(&cache_lock);
    _item_remove(it);
    pthread_mutex_unlock(&cache_lock);
}

/*
 * Unlink an item and remove it (if its recount drops to zero).
 */
void
item_delete(struct item *it)
{
    pthread_mutex_lock(&cache_lock);
    _item_unlink(it);
    _item_remove(it);
    pthread_mutex_unlock(&cache_lock);
}

/*
 * Replace one item with another in the hash table and lru q.
 */
static void
_item_replace(struct item *it, struct item *nit)
{
    ASSERT(it->magic == ITEM_MAGIC);
    ASSERT(!item_is_slabbed(it));

    ASSERT(nit->magic == ITEM_MAGIC);
    ASSERT(!item_is_slabbed(nit));

    log_debug(LOG_VERB, "replace it '%.*s' at offset %"PRIu32" id %"PRIu8" "
              "with one at offset %"PRIu32" id %"PRIu8"", it->nkey,
              item_key(it), it->offset, it->id, nit->offset, nit->id);

    _item_unlink(it);
    _item_link(nit);
}

/*
 * Return an item if it hasn't been marked as expired, lazily expiring
 * item as-and-when needed
 *
 * When a non-null item is returned, it's the callers responsibily to
 * release refcount on the item
 */
static struct item *
_item_get(const char *key, size_t nkey)
{
    struct item *it;

    it = assoc_find(key, nkey);
    if (it == NULL) {
        log_debug(LOG_VERB, "get it '%.*s' not found", nkey, key);
        return NULL;
    }

    if (item_expired(it)) {
        _item_unlink(it);
        stats_slab_incr(it->id, item_expire);
        stats_slab_settime(it->id, item_reclaim_ts, time_now());
        stats_slab_settime(it->id, item_expire_ts, it->exptime);
        log_debug(LOG_VERB, "get it '%.*s' expired and nuked", nkey, key);
        return NULL;
    }

    if (settings.oldest_live != 0 && settings.oldest_live <= time_now() &&
        it->atime <= settings.oldest_live) {
        _item_unlink(it);
        stats_slab_incr(it->id, item_evict);
        stats_slab_settime(it->id, item_evict_ts, time_now() );
        log_debug(LOG_VERB, "it '%.*s' nuked", nkey, key);
        return NULL;
    }

    item_acquire_refcount(it);

    log_debug(LOG_VERB, "get it '%.*s' found at offset %"PRIu32" with flags "
              "%02x id %"PRIu8" refcount %"PRIu32"", it->nkey, item_key(it),
              it->offset, it->flags, it->id);

    return it;
}

struct item *
item_get(const char *key, size_t nkey)
{
    struct item *it;

    pthread_mutex_lock(&cache_lock);
    it = _item_get(key, nkey);
    pthread_mutex_unlock(&cache_lock);

    return it;
}

/*
 * Store an item in the cache according to the semantics of one of the
 * update commands - set
 */
static item_store_result_t
_item_store(struct item *it, req_type_t type, struct conn *c)
{
    item_store_result_t result;  /* item store result */
    bool store_it;               /* store item ? */
    char *key;                   /* item key */
    struct item *oit, *nit;      /* old (existing) item & new item */

    result = NOT_STORED;
    store_it = true;

    key = item_key(it);
    nit = NULL;
    oit = _item_get(key, it->nkey);
    if (oit == NULL) {
        switch (type) {
        case REQ_SET:
            stats_slab_incr(it->id, set_success);
            break;

        default:
            NOT_REACHED();
        }
    } else {
        switch (type) {
        case REQ_SET:
            stats_slab_incr(it->id, set_success);
            break;

        default:
            NOT_REACHED();
        }
    }

    if (result == NOT_STORED && store_it) {
        if (oit != NULL) {
            _item_replace(oit, it);
        } else {
            _item_link(it);
        }
        result = STORED;
    }

    /* release our reference, if any */
    if (oit != NULL) {
        _item_remove(oit);
    }

    if (nit != NULL) {
        _item_remove(nit);
    }

    return result;
}

item_store_result_t
item_store(struct item *it, req_type_t type, struct conn *c)
{
    item_store_result_t ret;

    pthread_mutex_lock(&cache_lock);
    ret = _item_store(it, type, c);
    pthread_mutex_unlock(&cache_lock);

    return ret;
}
