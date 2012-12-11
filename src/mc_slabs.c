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

struct slabclass slabclass[SLABCLASS_MAX_IDS]; /* collection of slabs bucketed by slabclass */
uint8_t slabclass_max_id;                      /* maximum slabclass id */

static struct slabaddr *slabtable;             /* table of all slabs index by sid */
static uint32_t nslabtable;                    /* # entries in slab table */

static uint32_t nslab;                         /* # slab allocated */
static uint32_t max_mem_nslab;
static uint32_t max_nslab;                     /* max # slab allowed */

static uint8_t *mbase;                         /* base of in-memory slabs */
static int fd;                                 /* ssd.dump fd */

static off_t woff;                             /* write offset on disk */
static off_t last_woff;
static bool evict;

static char sbuf[MB];


/*
 * Return the usable space for item sized chunks that would be carved out
 * of a given slab.
 */
size_t
slab_size(void)
{
    return settings.slab_size - SLAB_HDR_SIZE;
}

struct slab *
slab_read(uint32_t id)
{
    struct slabaddr *saddr;
    struct slab *slab;

    ASSERT(id < nslabtable);

    saddr = &slabtable[id];

    if (saddr->memory) {
        slab = (struct slab *)(mbase + saddr->offset);
    } else {
        int n, status;
        off_t off = saddr->offset;

        status = lseek(fd, off, SEEK_SET);
        if (status < 0) {
            log_error("lseek to woff %d failed: %s", (int)off, strerror(errno));
            NOT_REACHED();
        }

        n = read(fd, sbuf, MB);
        if (n < MB) {
            log_error("read MB failed: %s", strerror(errno));
            NOT_REACHED();
        }

        slab = (struct slab *)sbuf;
    }

    return slab;
}

void
slab_print(void)
{
    uint8_t cid;
    struct slabclass *p;

    loga("slab size %zu, slab hdr size %zu, item hdr size %zu, "
         "item chunk size %zu, total memory %zu", settings.slab_size,
         SLAB_HDR_SIZE, ITEM_HDR_SIZE, settings.chunk_size,
         settings.maxbytes);

    for (cid = SLABCLASS_MIN_ID; cid <= slabclass_max_id; cid++) {
        p = &slabclass[cid];

        loga("class %3"PRId8": items %7"PRIu32"  size %7zu  data %7zu  "
             "slack %7zu", cid, p->nitem, p->size, p->size - ITEM_HDR_SIZE,
             slab_size() - p->nitem * p->size);
    }
}

static void
slab_dump(void)
{
    uint32_t i;
    struct slab *slab;

    for (i = 0; i < max_nslab; i++) {
        slab = slab_read(i);
        loga("slab %p id %"PRIu8" cid %"PRIu8"", slab, slab->sid, slab->cid);
    }
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
 * Return the item size given a slab cid
 */
size_t
slab_item_size(uint8_t cid)
{
    ASSERT(cid >= SLABCLASS_MIN_ID && cid <= slabclass_max_id);

    return slabclass[cid].size;
}

/*
 * Return the cid of the slab which can store an item of a given size.
 *
 * Return SLABCLASS_INVALID_ID, for large items which cannot be stored in
 * any of the configured slabs.
 */
uint8_t
slab_cid(size_t size)
{
    uint8_t cid, imin, imax;

    ASSERT(size != 0);

    /* binary search */
    imin = SLABCLASS_MIN_ID;
    imax = slabclass_max_id;
    while (imax >= imin) {
        cid = (imin + imax) / 2;
        if (size > slabclass[cid].size) {
            imin = cid + 1;
        } else if (cid > SLABCLASS_MIN_ID && size <= slabclass[cid - 1].size) {
            imax = cid - 1;
        } else {
            break;
        }
    }

    if (imin > imax) {
        /* size too big for any slab */
        return SLABCLASS_INVALID_ID;
    }

    return cid;
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
    uint8_t cid;     /* slabclass id */
    size_t *profile; /* slab profile */

    profile = settings.profile;
    slabclass_max_id = settings.profile_last_id;

    ASSERT(slabclass_max_id <= SLABCLASS_MAX_ID);

    for (cid = SLABCLASS_MIN_ID; cid <= slabclass_max_id; cid++) {
        struct slabclass *p; /* slabclass */
        uint32_t nitem;      /* # item per slabclass */
        size_t item_sz;      /* item size */

        nitem = slab_size() / profile[cid];
        item_sz = profile[cid];
        p = &slabclass[cid];

        p->nitem = nitem;
        p->size = item_sz;

        p->nfree_item = 0;
        p->free_item = NULL;
    }
}

/*
 * All the prep work before start using a slab.
 */
static void
slab_add_one(struct slab *slab, uint8_t cid, uint32_t sid)
{
    struct slabclass *p;
    struct item *it;
    uint32_t i, offset;

    p = &slabclass[cid];

    /* init slab header */
    slab->magic = SLAB_MAGIC;
    slab->cid = cid;
    slab->sid = sid;

    /* initialize all slab items */
    for (i = 0; i < p->nitem; i++) {
        it = slab_2_item(slab, i, p->size);
        offset = (uint32_t)((uint8_t *)it - (uint8_t *)slab);
        item_hdr_init(it, offset, cid, sid);
    }

    /* make this slab as the current slab */
    p->nfree_item = p->nitem;
    p->free_item = (struct item *)&slab->data[0];
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
    uint8_t cid, *cur;

    slab_slabclass_init();

    /*
     * Create a 64M file in your home directory
     *  $ dd if=/dev/zero of=~/ssd.dump bs=1024K count=64
     */
    fd = open("/home/manj/ssd.dump", O_RDWR, 0644);
    if (fd < 0) {
        log_error("open /home/manj/ssd.dump failed: %s", strerror(errno));
        return MC_ERROR;
    }

    /*
     * For now, in-memory slabs equals the number of usable slabclass. In
     * future, this would be controlled by the usable space that would
     * be available to be in-memory
     */
    nslab = 0;
    max_nslab = 64;
    max_mem_nslab = slabclass_max_id; /* slabclass 0 has no slabs */
    size = max_mem_nslab * settings.slab_size;

    evict = false;
    woff = 0;
    last_woff = woff + (max_nslab * settings.slab_size);

    nslabtable = max_mem_nslab + max_nslab;

    slabtable = mc_alloc(sizeof(*slabtable) * nslabtable);
    if (slabtable == NULL) {
        log_error("slabtable create with %"PRIu32" entries failed: %s",
                  nslabtable, strerror(errno));
        return MC_ENOMEM;
    }
    log_debug(LOG_INFO, "created slabtable of %zu bytes with %"PRIu32" "
              "entries", sizeof(*slabtable) * nslabtable, nslabtable);

    mbase = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
                 -1, 0);
    if (mbase == ((void *) -1)) {
        log_error("mmap %zu bytes for %"PRIu32" slabs failed: %s",
                  size, max_mem_nslab, strerror(errno));
        mc_free(slabtable);
        return MC_ENOMEM;
    }
    log_debug(LOG_INFO, "pre-allocated %zu bytes for %"PRIu32" in-memory slabs",
              size, max_mem_nslab);

    /* populate the slabtable with in-memory slabs */
    for (nslab = 0, cur = mbase, cid = SLABCLASS_MIN_ID;
         cid <= slabclass_max_id;
         nslab++, cur += settings.slab_size, cid++) {

        slab = (struct slab *)cur;

        /* create the slab address for this slab */
        saddr = &slabtable[nslab];
        saddr->offset = nslab * settings.slab_size;
        saddr->memory = 1;

        /* link the nslab into the slabclass identified by the given cid */
        slab_add_one(slab, cid, nslab);

        slabclass[cid].slab = slab;

        log_debug(LOG_INFO, "new slab %p allocated at pos %u", slab, nslab);

    }
    ASSERT(nslab <= max_nslab);

    return MC_OK;
}

void
slab_deinit(void)
{
    /* FIXME: munmap */
}

static uint32_t
slab_evict_slab(void)
{
    int n, status;

    if (woff >= last_woff) {
        /* [0, woff, last_woff] is a circular buffer  */
        woff = 0;
    }

    log_debug(LOG_INFO, "evict slab at offset woff %d", (int)woff);

    status = lseek(fd, woff, SEEK_SET);
    if (status < 0) {
        log_error("lseek to woff %d failed: %s", (int)woff, strerror(errno));
        NOT_REACHED();
    }

    n = read(fd, sbuf, MB);
    if (n < MB) {
        log_error("read MB failed: %s", strerror(errno));
        NOT_REACHED();
    }

    struct slab *slab = (struct slab *)sbuf;
    ASSERT(slab->magic == SLAB_MAGIC);

    uint32_t i;
    struct slabclass *p;

    p = &slabclass[slab->cid];

    // assoc_dump();

    for (i = 0; i < p->nitem; i++) {
        struct item *it = slab_2_item(slab, i, p->size);

        ASSERT(it->magic == ITEM_MAGIC);

        if (item_is_linked(it)) {
            it->flags &= ~ITEM_LINKED;
            ASSERT(assoc_find(item_key(it), it->nkey) != NULL);
            assoc_delete(item_key(it), it->nkey);
        }
    }

    return slab->sid;
}

static void
slab_write_to_disk(uint8_t cid, uint32_t slabtable_id)
{
    rstatus_t status;
    struct slabclass *p;
    int n;
    struct slab *slab;
    uint32_t i;

    p = &slabclass[cid];

    status = lseek(fd, woff, SEEK_SET);
    if (status < 0) {
        log_error("lseek to woff %d failed: %s", (int)woff, strerror(errno));
        NOT_REACHED();
    }

    /* current slab */
    slab = slabclass[cid].slab;

    /* write the current slab */
    n = write(fd, slab, MB);
    if (n < MB) {
        log_error("write 1MB failed: %s", strerror(errno));
        NOT_REACHED();
    }

    log_debug(LOG_INFO, "slab cid %"PRIu8" is empty, write sid %d to disk, "
              "use sid %d as in-memory slab", cid, slab->sid, slabtable_id);

    /* update slab address to point to disk */
    slabtable[slab->sid].offset = woff;
    slabtable[slab->sid].memory = 0;

    /* reuse the in-memory slab */
    p->nfree_item = p->nitem;
    p->free_item = (struct item *)&slab->data[0];
    for (i = 0; i < p->nitem; i++) {
        struct item *it = slab_2_item(slab, i, p->size);
        uint32_t offset = (uint32_t)((uint8_t *)it - (uint8_t *)slab);
        item_hdr_init(it, offset, cid, slab->sid);
    }

    /* update the slab table */
    slabtable[slabtable_id].offset = ((uint8_t *)slab - mbase);
    slabtable[slabtable_id].memory = 1;
    slab->sid = slabtable_id;

    /* update the write offset */
    woff += MB;
}

/*
 * Get an item from the slab with a given id. We get an item either from:
 * 1. item free Q of given slab with id. or,
 * 2. current slab.
 * If the current slab is empty, we get a new slab from the slab allocator
 * and return the next item from this new slab.
 */
struct item *
slab_get_item(uint8_t cid)
{
    struct slabclass *p;
    struct item *it;

    ASSERT(cid >= SLABCLASS_MIN_ID && cid <= slabclass_max_id);
    p = &slabclass[cid];

    if (p->free_item == NULL) {
        uint32_t slabtable_id;
        /*
         * No more free item in this in-memory slab; it it time to reuse this
         * slab by writing it to disk tier
         */
        if (woff >= last_woff || evict == true) {
            /* disk tier is full, evict one slab from the disk tier */
            ASSERT(nslab == nslabtable);
            evict = true;
            slabtable_id = slab_evict_slab();
        } else {
            slabtable_id = nslab;
            nslab++;
            ASSERT(nslab <= (max_nslab + max_mem_nslab));
            ASSERT(nslab <= nslabtable);
        }

        slab_write_to_disk(cid, slabtable_id);

    }

    /* return item from current slab */
    it = p->free_item;
    if (--p->nfree_item != 0) {
        p->free_item = (struct item *)(((uint8_t *)p->free_item) + p->size);
    } else {
        p->free_item = NULL;
    }

    log_debug(LOG_VERB, "get new it at offset %"PRIu32" with id %"PRIu8"",
              it->offset, it->cid);

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

    log_debug(LOG_INFO, "put it '%.*s' at offset %"PRIu32" with cid %"PRIu8,
              it->nkey, item_key(it), it->offset, it->cid);

#if 0
    /*
     * FIXME: We can't do this, because upper layers keep a direct reference
     * to lit and maybe even it and that sucks because now if they try to
     * reference it, we have changed it underneath
     */
    p = &slabclass[it->cid];

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
     */
    log_debug(LOG_INFO, "move it '%.*s' with cid %"PRIu8" at offset %"PRIu32" "
              "to offset %"PRIu32" ", lit->nkey, item_key(lit), lit->cid,
              lit->offset, it->offset);
    p->free_item = lit;
    p->nfree_item++;

    /* move the lit to it slot */
    offset = it->offset;
    memcpy(it, lit, p->size);
    lit->offset = offset;
#endif
}
