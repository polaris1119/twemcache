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

#define HASH_DEFAULT_MOVE_SIZE  1
#define HASH_DEFAULT_POWER      16

extern struct settings settings;
extern pthread_mutex_t cache_lock;

static struct item_slh *primary_hashtable;  /* primary (main) hash table */
static uint32_t nhash_item;                 /* # items in hash table */
static uint32_t hash_power;                 /* # buckets = 2^hash_power */

static struct item_slh *
assoc_create_table(uint32_t table_sz)
{
    struct item_slh *table;
    uint32_t i;

    table = mc_alloc(sizeof(*table) * table_sz);
    if (table == NULL) {
        return NULL;
    }

    for (i = 0; i < table_sz; i++) {
        SLIST_INIT(&table[i]);
    }

    return table;
}

static struct item_slh *
assoc_get_bucket(const char *key, size_t nkey)
{
    struct item_slh *bucket;
    uint32_t hv, curbucket;

    hv = hash(key, nkey, 0);
    curbucket = hv & HASHMASK(hash_power);

    bucket = &primary_hashtable[curbucket];

    return bucket;
}

rstatus_t
assoc_init(void)
{
    uint32_t hashtable_sz;

    primary_hashtable = NULL;
    hash_power = settings.hash_power > 0 ? settings.hash_power : HASH_DEFAULT_POWER;

    nhash_item = 0;

    hashtable_sz = HASHSIZE(hash_power);

    primary_hashtable = assoc_create_table(hashtable_sz);
    if (primary_hashtable == NULL) {
        return MC_ENOMEM;
    }

    return MC_OK;
}

void
assoc_deinit(void)
{
}

struct item *
assoc_find(const char *key, size_t nkey)
{
    struct item_slh *bucket;
    struct item *it;
    uint32_t depth;

    ASSERT(pthread_mutex_trylock(&cache_lock) != 0);
    ASSERT(key != NULL && nkey != 0);

    bucket = assoc_get_bucket(key, nkey);

    for (depth = 0, it = SLIST_FIRST(bucket); it != NULL;
         depth++, it = SLIST_NEXT(it, h_sle)) {
        if ((nkey == it->nkey) && (memcmp(key, item_key(it), nkey) == 0)) {
            break;
        }
    }

    return it;
}

void
assoc_insert(struct item *it)
{
    struct item_slh *bucket;

    ASSERT(pthread_mutex_trylock(&cache_lock) != 0);
    ASSERT(assoc_find(item_key(it), it->nkey) == NULL);

    bucket = assoc_get_bucket(item_key(it), it->nkey);
    SLIST_INSERT_HEAD(bucket, it, h_sle);
    nhash_item++;
}

void
assoc_delete(const char *key, size_t nkey)
{
    struct item_slh *bucket;
    struct item *it, *prev;

    ASSERT(pthread_mutex_trylock(&cache_lock) != 0);
    ASSERT(assoc_find(key, nkey) != NULL);

    bucket = assoc_get_bucket(key, nkey);

    for (prev = NULL, it = SLIST_FIRST(bucket); it != NULL;
         prev = it, it = SLIST_NEXT(it, h_sle)) {
        if ((nkey == it->nkey) && (memcmp(key, item_key(it), nkey) == 0)) {
            break;
        }
    }

    if (prev == NULL) {
        SLIST_REMOVE_HEAD(bucket, h_sle);
    } else {
        SLIST_REMOVE_AFTER(prev, h_sle);
    }

    nhash_item--;
}
