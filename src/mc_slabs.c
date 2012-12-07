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
#include <sys/mman.h>

#include <mc_core.h>

extern struct settings settings;
extern pthread_mutex_t cache_lock;

struct slabclass slabclass[SLABCLASS_MAX_IDS]; /* collection of slabs bucketed by slabclass */
uint8_t slabclass_max_id;                      /* maximum slabclass id */
static struct slabaddr *slabtable;             /* table of all slabs in the system */
static uint32_t nslab;                         /* # slab allocated */
static uint32_t max_nslab;                     /* max # slab allowed */
pthread_mutex_t slab_lock;                     /* lock protecting slabclass and other globals */

static void slab_add_one(struct slab *slab, uint8_t id);

/*
 * Return the usable space for item sized chunks that would be carved out
 * of a given slab.
 */
size_t
slab_size(void)
{
    return settings.slab_size - SLAB_HDR_SIZE;
}

void
slab_print(void)
{
    uint8_t id;
    struct slabclass *p;

    loga("slab size %zu, slab hdr size %zu, item hdr size %zu, "
         "item chunk size %zu, total memory %zu", settings.slab_size,
         SLAB_HDR_SIZE, ITEM_HDR_SIZE, settings.chunk_size,
         settings.maxbytes);

    for (id = SLABCLASS_MIN_ID; id <= slabclass_max_id; id++) {
        p = &slabclass[id];

        loga("class %3"PRId8": items %7"PRIu32"  size %7zu  data %7zu  "
             "slack %7zu", id, p->nitem, p->size, p->size - ITEM_HDR_SIZE,
             slab_size() - p->nitem * p->size);
    }
}

void
slab_acquire_refcount(struct slab *slab)
{
    ASSERT(pthread_mutex_trylock(&cache_lock) != 0);
    ASSERT(slab->magic == SLAB_MAGIC);
    slab->refcount++;
}

void
slab_release_refcount(struct slab *slab)
{
    ASSERT(pthread_mutex_trylock(&cache_lock) != 0);
    ASSERT(slab->magic == SLAB_MAGIC);
    ASSERT(slab->refcount > 0);
    slab->refcount--;
}

/*
 * Get the idx^th item with a given size from the slab.
 */
static struct item *
slab_2_item(struct slab *slab, uint32_t idx, size_t size)
{
    struct item *it;
    uint32_t offset = idx * size;

    ASSERT(slab->magic == SLAB_MAGIC);
    ASSERT(offset < settings.slab_size);

    it = (struct item *)((uint8_t *)slab->data + offset);

    return it;
}

/*
 * Return the item size given a slab id
 */
size_t
slab_item_size(uint8_t id)
{
    ASSERT(id >= SLABCLASS_MIN_ID && id <= slabclass_max_id);

    return slabclass[id].size;
}

/*
 * Return the id of the slab which can store an item of a given size.
 *
 * Return SLABCLASS_INVALID_ID, for large items which cannot be stored in
 * any of the configured slabs.
 */
uint8_t
slab_id(size_t size)
{
    uint8_t id, imin, imax;

    ASSERT(size != 0);

    /* binary search */
    imin = SLABCLASS_MIN_ID;
    imax = slabclass_max_id;
    while (imax >= imin) {
        id = (imin + imax) / 2;
        if (size > slabclass[id].size) {
            imin = id + 1;
        } else if (id > SLABCLASS_MIN_ID && size <= slabclass[id - 1].size) {
            imax = id - 1;
        } else {
            break;
        }
    }

    if (imin > imax) {
        /* size too big for any slab */
        return SLABCLASS_INVALID_ID;
    }

    return id;
}

/*
 * Initialize all slabclasses.
 *
 * Every slabclass is a collection of slabs of fixed size specified by
 * --slab-size. A single slab is a collection of contiguous, equal sized
 * item chunks of a given size specified by the settings.profile array
 */
static void
slab_slabclass_init(void)
{
    uint8_t id;      /* slabclass id */
    size_t *profile; /* slab profile */

    profile = settings.profile;
    slabclass_max_id = settings.profile_last_id;

    ASSERT(slabclass_max_id <= SLABCLASS_MAX_ID);

    for (id = SLABCLASS_MIN_ID; id <= slabclass_max_id; id++) {
        struct slabclass *p; /* slabclass */
        uint32_t nitem;      /* # item per slabclass */
        size_t item_sz;      /* item size */

        nitem = slab_size() / profile[id];
        item_sz = profile[id];
        p = &slabclass[id];

        p->nitem = nitem;
        p->size = item_sz;

        p->nfree_item = 0;
        p->free_item = NULL;
    }
}

/*
 * Initialize the slab module
 */
rstatus_t
slab_init(void)
{
    struct slab *slab;
    struct slabaddr *saddr;
    size_t size;
    uint8_t id, *base;
    uint32_t i;

    pthread_mutex_init(&slab_lock, NULL);

    slab_slabclass_init();

    /*
     * For now, in-memory slabs equals the number of usable slabclass. In
     * future, this would be controlled by the usable space that would
     * be available to be in-memory
     */
    nslab = 0;
    max_nslab = slabclass_max_id; /* slabclass 0 has no slabs */
    size = max_nslab * settings.slab_size;

    slabtable = mc_alloc(sizeof(*slabtable) * max_nslab);
    if (slabtable == NULL) {
        log_error("slabtable create with %"PRIu32" entries failed: %s",
                  max_nslab, strerror(errno));
        return MC_ENOMEM;
    }
    log_debug(LOG_INFO, "created slabtable of %zu bytes with %"PRIu32" "
              "entries", 100, max_nslab);

    base = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
                -1, 0);
    if (base == ((void *) -1)) {
        log_error("mmap %zu bytes for %"PRIu32" slabs failed: %s",
                  size, max_nslab, strerror(errno));
        mc_free(slabtable);
        return MC_ENOMEM;
    }
    log_debug(LOG_INFO, "pre-allocated %zu bytes for %"PRIu32" in-memory slabs",
              size, max_nslab);

    /* populate the slabtable with in-memory slabs */
    for (i = 0, id = SLABCLASS_MIN_ID; id <= slabclass_max_id; id++, i++) {
        slab = (struct slab *)base;
        base += settings.slab_size;

        saddr = &slabtable[nslab];
        saddr->offset = nslab * settings.slab_size;
        nslab++;
        log_debug(LOG_INFO, "new slab %p allocated at pos %u", slab, nslab - 1);

        /* link the nslab into the slabclass identified by the given id */
        slab_add_one(slab, id);
    }
    ASSERT(nslab == max_nslab);

    return MC_OK;
}

void
slab_deinit(void)
{
    /* FIXME: munmap */
}

static void
slab_hdr_init(struct slab *slab, uint8_t id)
{
    ASSERT(id >= SLABCLASS_MIN_ID && id <= slabclass_max_id);

    slab->magic = SLAB_MAGIC;
    slab->id = id;
    slab->unused = 0;
    slab->refcount = 0;
}

static bool
slab_heap_full(void)
{
    return (nslab >= max_nslab) ? true : false;
}

/*
 * Get a raw slab from the slab pool.
 */
static struct slab *
slab_get_new(void)
{
    ASSERT(slab_heap_full());

    return NULL;
}

/*
 * All the prep work before start using a slab.
 */
static void
slab_add_one(struct slab *slab, uint8_t id)
{
    struct slabclass *p;
    struct item *it;
    uint32_t i, offset;

    p = &slabclass[id];

    /* initialize slab header */
    slab_hdr_init(slab, id);

    /* initialize all slab items */
    for (i = 0; i < p->nitem; i++) {
        it = slab_2_item(slab, i, p->size);
        offset = (uint32_t)((uint8_t *)it - (uint8_t *)slab);
        item_hdr_init(it, offset, id);
    }

    /* make this slab as the current slab */
    p->nfree_item = p->nitem;
    p->free_item = (struct item *)&slab->data[0];
}

/*
 * Get a slab from the slab pool, if not empy.
 */
static rstatus_t
slab_get(uint8_t id)
{
    struct slab *slab;

    ASSERT(slabclass[id].free_item == NULL);

    slab = slab_get_new();
    if (slab == NULL) {
        return MC_ENOMEM;
    }

    /*
     * Link the new slab into the slabclass identified
     * by the given id
     */
    slab_add_one(slab, id);

    return MC_OK;
}

/*
 * Get an item from the slab with a given id. We get an item either from:
 * 1. item free Q of given slab with id. or,
 * 2. current slab.
 * If the current slab is empty, we get a new slab from the slab allocator
 * and return the next item from this new slab.
 */
static struct item *
_slab_get_item(uint8_t id)
{
    rstatus_t status;
    struct slabclass *p;
    struct item *it;

    p = &slabclass[id];

    if (p->free_item == NULL) {
        NOT_REACHED();
        status = slab_get(id);
        if (status != MC_OK) {
            return NULL;
        }

        ASSERT(p->free_item != NULL);
    }

    /* return item from current slab */
    it = p->free_item;
    if (--p->nfree_item != 0) {
        p->free_item = (struct item *)(((uint8_t *)p->free_item) + p->size);
    } else {
        p->free_item = NULL;
    }

    log_debug(LOG_VERB, "get new it at offset %"PRIu32" with id %"PRIu8"",
              it->offset, it->id);

    return it;
}

struct item *
slab_get_item(uint8_t id)
{
    struct item *it;

    log_debug(LOG_INFO, "get it from slab with id %"PRIu8, id);

    ASSERT(id >= SLABCLASS_MIN_ID && id <= slabclass_max_id);

    pthread_mutex_lock(&slab_lock);
    it = _slab_get_item(id);
    pthread_mutex_unlock(&slab_lock);

    return it;
}

/*
 * Put an item back into the slab
 */
void
slab_put_item(struct item *it)
{
#if 0
    struct slabclass *p;
    struct item *lit;
    uint32_t offset;
#endif

    log_debug(LOG_INFO, "put it '%.*s' at offset %"PRIu32" with id %"PRIu8,
              it->nkey, item_key(it), it->offset, it->id);

#if 0
    /*
     * FIXME: We can't do this, because upper layers keep a direct reference
     * to lit and maybe even it and that sucks because now if they try to
     * reference it, we have changed it underneath
     */
    p = &slabclass[it->id];

    ASSERT(p->free_item != NULL);

    /* last non-free item */
    lit = (struct item *)((uint8_t*)p->free_item - p->size);

    /* there is only one item in this slab, which is about to be freed */
    if (lit == it) {
        p->free_item = lit;
        p->nfree_item++;
        return;
    }

    /*
     * Move lit into space occupied by it and adjust offset.
     * FIXME: what if lit->refcount > 0
     */
    log_debug(LOG_INFO, "move it '%.*s' with id %"PRIu8" at offset %"PRIu32" "
              "to offset %"PRIu32" ", lit->nkey, item_key(lit), lit->id,
              lit->offset, it->offset);
    p->free_item = lit;
    p->nfree_item++;

    /* move the lit to it slot */
    offset = it->offset;
    memcpy(it, lit, p->size);
    lit->offset = offset;
#endif
}
