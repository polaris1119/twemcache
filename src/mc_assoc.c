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

#include <mc_core.h>

#define HASHSIZE(_n) (1UL << (_n))
#define HASHMASK(_n) (HASHSIZE(_n) - 1)

#define HASH_POWER  16

static struct itx_tqh *hashtable;   /* hash table */
static uint32_t nhash_item;         /* # itx in hash table */
static uint32_t hash_power;         /* # buckets = 2^hash_power */

static struct itx_tqh *
assoc_create_table(uint32_t nbucket)
{
    struct itx_tqh *table;
    uint32_t i;

    table = mc_alloc(sizeof(*table) * nbucket);
    if (table == NULL) {
        return NULL;
    }

    for (i = 0; i < nbucket; i++) {
        TAILQ_INIT(&table[i]);
    }

    return table;
}

static struct itx_tqh *
assoc_get_bucket(uint8_t *key, size_t nkey)
{
    struct itx_tqh *bucket;
    uint32_t hv, idx;

    hv = hash(key, nkey, 0);
    idx = hv & HASHMASK(hash_power);
    bucket = &hashtable[idx];

    return bucket;
}

rstatus_t
assoc_init(void)
{
    uint32_t nbucket;

    hashtable = NULL;
    hash_power = HASH_POWER;

    nhash_item = 0;
    nbucket = HASHSIZE(hash_power);

    hashtable = assoc_create_table(nbucket);
    if (hashtable == NULL) {
        return MC_ENOMEM;
    }

    return MC_OK;
}

void
assoc_deinit(void)
{
}

struct item_idx *
assoc_find(uint8_t *key, size_t nkey)
{
    struct itx_tqh *bucket;
    struct item_idx *itx;

    ASSERT(key != NULL && nkey != 0);

    bucket = assoc_get_bucket(key, nkey);

    TAILQ_FOREACH(itx, bucket, h_tqe) {
        if (nkey == itx->nkey && memcmp(key, itx->key, nkey == 0)) {
            break;
        }
    }

    return itx;
}

void
assoc_insert(struct item_idx *itx)
{
    struct itx_tqh *bucket;

    ASSERT(assoc_find(itx->key, itx->nkey) == NULL);

    bucket = assoc_get_bucket(itx->key, itx->nkey);
    TAILQ_INSERT_HEAD(bucket, itx, h_tqe);
    nhash_item++;
}

void
assoc_delete(uint8_t *key, size_t nkey)
{
    struct itx_tqh *bucket;
    struct item_idx *itx;

    bucket = assoc_get_bucket(key, nkey);
    itx = assoc_find(key, nkey);
    ASSERT(itx != NULL);
    TAILQ_REMOVE(bucket, itx, h_tqe);

    nhash_item--;
}
