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

#include <stdio.h>
#include <stdlib.h>

#include <mc_core.h>

extern struct settings settings;

/*
 * Parsing tokens:
 *
 * COMMAND  KEY   FLAGS   EXPIRY   VLEN
 * set      <key> <flags> <expiry> <datalen> [noreply]\r\n<data>\r\n
 *
 * COMMAND  KEY
 * get      <key>\r\n
 * get      <key> [<key>]+\r\n
 *
 * COMMAND   SUBCOMMAND CACHEDUMP_ID CACHEDUMP_LIMIT
 * stats\r\n
 * stats    <args>\r\n
 */

#define TOKEN_COMMAND           0
#define TOKEN_KEY               1
#define TOKEN_FLAGS             2
#define TOKEN_EXPIRY            3
#define TOKEN_VLEN              4
#define TOKEN_SUBCOMMAND        1
#define TOKEN_MAX               8

#define SUFFIX_MAX_LEN 32 /* enough to hold "<uint32_t> <uint32_t> \r\n" */

struct token {
    char   *val; /* token value */
    size_t len;  /* token length */
};

struct bound {
    struct {
        int min; /* min # token */
        int max; /* max # token */
    } b[2];      /* bound without and with noreply */
};

#define DEFINE_ACTION(_t, _min, _max, _nmin, _nmax) \
    { {{ _min, _max }, { _nmin, _nmax }} },
static struct bound ntoken_bound[] = {
    REQ_CODEC( DEFINE_ACTION )
};
#undef DEFINE_ACTION

#define strcrlf(m)                                                          \
    (*(m) == '\r' && *((m) + 1) == '\n')

#ifdef MC_LITTLE_ENDIAN

#define str4cmp(m, c0, c1, c2, c3)                                          \
    (*(uint32_t *) m == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0))

#define str5cmp(m, c0, c1, c2, c3, c4)                                      \
    (str4cmp(m, c0, c1, c2, c3) && (m[4] == c4))

#define str6cmp(m, c0, c1, c2, c3, c4, c5)                                  \
    (str4cmp(m, c0, c1, c2, c3) &&                                          \
        (((uint32_t *) m)[1] & 0xffff) == ((c5 << 8) | c4))

#define str7cmp(m, c0, c1, c2, c3, c4, c5, c6)                              \
    (str6cmp(m, c0, c1, c2, c3, c4, c5) && (m[6] == c6))

#define str8cmp(m, c0, c1, c2, c3, c4, c5, c6, c7)                          \
    (str4cmp(m, c0, c1, c2, c3) &&                                          \
        (((uint32_t *) m)[1] == ((c7 << 24) | (c6 << 16) | (c5 << 8) | c4)))

#define str9cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8)                      \
    (str8cmp(m, c0, c1, c2, c3, c4, c5, c6, c7) && m[8] == c8)

#define str10cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9)                 \
    (str8cmp(m, c0, c1, c2, c3, c4, c5, c6, c7) &&                          \
        (((uint32_t *) m)[2] & 0xffff) == ((c9 << 8) | c8))

#define str11cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10)            \
    (str10cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9) && (m[10] == c10))

#define str12cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11)       \
    (str8cmp(m, c0, c1, c2, c3, c4, c5, c6, c7) &&                          \
        (((uint32_t *) m)[2] == ((c11 << 24) | (c10 << 16) | (c9 << 8) | c8)))

#else

#define str4cmp(m, c0, c1, c2, c3)                                          \
    (m[0] == c0 && m[1] == c1 && m[2] == c2 && m[3] == c3)

#define str5cmp(m, c0, c1, c2, c3, c4)                                      \
    (str4cmp(m, c0, c1, c2, c3) && (m[4] == c4))

#define str6cmp(m, c0, c1, c2, c3, c4, c5)                                  \
    (str5cmp(m, c0, c1, c2, c3, c4) && m[5] == c5)

#define str7cmp(m, c0, c1, c2, c3, c4, c5, c6)                              \
    (str6cmp(m, c0, c1, c2, c3, c4, c5) && m[6] == c6)

#define str8cmp(m, c0, c1, c2, c3, c4, c5, c6, c7)                          \
    (str7cmp(m, c0, c1, c2, c3, c4, c5, c6) && m[7] == c7)

#define str9cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8)                      \
    (str8cmp(m, c0, c1, c2, c3, c4, c5, c6, c7) && m[8] == c8)

#define str10cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9)                 \
    (str9cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8) && m[9] == c9)

#define str11cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10)            \
    (str10cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9) && m[10] == c10)

#define str12cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11)       \
    (str11cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10) && m[11] == c11)

#endif

/*
 * Returns true if ntoken is within the bounds for a given request
 * type, false otherwise.
 */
static bool
asc_ntoken_valid(struct conn *c, int ntoken)
{
    struct bound *t;
    int min, max;

    ASSERT(c->req_type > REQ_UNKNOWN && c->req_type < REQ_SENTINEL);

    t = &ntoken_bound[c->req_type];
    min = t->b[c->noreply].min;
    max = t->b[c->noreply].max;

    return (ntoken >= min && ntoken <= max) ? true : false;
}

/*
 * Tokenize the request header and update the token array token with
 * pointer to start of each token and length. Note that tokens are
 * not null terminated.
 *
 * Returns total number of tokens. The last valid token is the terminal
 * token (value points to the first unprocessed character of the string
 * and length zero).
 */
static size_t
asc_tokenize(char *command, struct token *token, int ntoken_max)
{
    char *s, *e; /* start and end marker */
    int ntoken;  /* # tokens */

    ASSERT(command != NULL);
    ASSERT(token != NULL);
    ASSERT(ntoken_max > 1);

    for (s = e = command, ntoken = 0; ntoken < ntoken_max - 1; e++) {
        if (*e == ' ') {
            if (s != e) {
                /* save token */
                token[ntoken].val = s;
                token[ntoken].len = e - s;
                ntoken++;
            }
            s = e + 1;
        } else if (*e == '\0') {
            if (s != e) {
                /* save final token */
                token[ntoken].val = s;
                token[ntoken].len = e - s;
                ntoken++;
            }
            break;
        }
    }

    /*
     * If we scanned the whole string, the terminal value pointer is NULL,
     * otherwise it is the first unprocessed character.
     */
    token[ntoken].val = (*e == '\0') ? NULL : e;
    token[ntoken].len = 0;
    ntoken++;

    return ntoken;
}

static void
asc_write_string(struct conn *c, const char *str, size_t len)
{
    log_debug(LOG_VVERB, "write on c %d noreply %d str '%.*s'", c->sd,
              c->noreply, len, str);

    if (c->noreply) {
        c->noreply = 0;
        conn_set_state(c, CONN_NEW_CMD);
        return;
    }

    if ((len + CRLF_LEN) > c->wsize) {
        log_warn("server error on c %d for str '%.*s' because wbuf is not big "
                 "enough", c->sd, len, str);

        stats_thread_incr(server_error);
        str = "SERVER_ERROR";
        len = sizeof("SERVER_ERROR") - 1;
    }

    memcpy(c->wbuf, str, len);
    memcpy(c->wbuf + len, CRLF, CRLF_LEN);
    c->wbytes = len + CRLF_LEN;
    c->wcurr = c->wbuf;

    conn_set_state(c, CONN_WRITE);
    c->write_and_go = CONN_NEW_CMD;
}

static void
asc_write_stored(struct conn *c)
{
    const char *str = "STORED";
    size_t len = sizeof("STORED") - 1;

    asc_write_string(c, str, len);
}

static void
asc_write_not_stored(struct conn *c)
{
    const char *str = "NOT_STORED";
    size_t len = sizeof("NOT_STORED") - 1;

    asc_write_string(c, str, len);
}

static void
asc_write_client_error(struct conn *c)
{
    const char *str = "CLIENT_ERROR";
    size_t len = sizeof("CLIENT_ERROR") - 1;

    stats_thread_incr(cmd_error);

    asc_write_string(c, str, len);
}

void
asc_write_server_error(struct conn *c)
{
    const char *str = "SERVER_ERROR";
    size_t len = sizeof("SERVER_ERROR") - 1;

    stats_thread_incr(server_error);

    asc_write_string(c, str, len);
}

/*
 * We get here after reading the value in update commands. The command
 * is stored in c->req_type, and the item is ready in c->item.
 */
void
asc_complete_nread(struct conn *c)
{
    item_store_result_t ret;
    struct item *it;
    char *end;

    it = c->item;
    end = item_data(it) + it->nbyte;

    if (!strcrlf(end)) {
        log_hexdump(LOG_NOTICE, c->req, c->req_len, "client error on c %d for "
                    "req of type %d with missing crlf", c->sd, c->req_type);

        asc_write_client_error(c);
    } else {
      ret = item_store(it, c->req_type, c);
      switch (ret) {
      case STORED:
          asc_write_stored(c);
          break;

      case NOT_STORED:
          asc_write_not_stored(c);
          break;

      default:
          log_warn("server error on c %d for req of type %d with unknown "
                   "store result %d", c->sd, c->req_type, ret);
          asc_write_server_error(c);
          break;
      }
    }

    item_remove(c->item);
    c->item = NULL;
}

static void
asc_set_noreply_maybe(struct conn *c, struct token *token, int ntoken)
{
    struct token *t;

    if (ntoken < 2) {
        return;
    }

    t = &token[ntoken - 2];

    if ((t->len == sizeof("noreply") - 1) &&
        str7cmp(t->val, 'n', 'o', 'r', 'e', 'p', 'l', 'y')) {
        c->noreply = 1;
    }
}

static rstatus_t
asc_create_suffix(struct conn *c, unsigned valid_key_iter, char **suffix)
{
    if (valid_key_iter >= c->ssize) {
        char **new_suffix_list;

        new_suffix_list = mc_realloc(c->slist, sizeof(char *) * c->ssize * 2);
        if (new_suffix_list == NULL) {
            return MC_ENOMEM;
        }
        c->ssize *= 2;
        c->slist  = new_suffix_list;
    }

    *suffix = cache_alloc(c->thread->suffix_cache);
    if (*suffix == NULL) {
        log_warn("server error on c %d for req of type %d with enomem on "
                 "suffix cache", c->sd, c->req_type);

        asc_write_server_error(c);
        return MC_ENOMEM;
    }

    *(c->slist + valid_key_iter) = *suffix;
    return MC_OK;
}

/*
 * Build the response. Each hit adds three elements to the outgoing
 * reponse vector, viz:
 *   "VALUE "
 *   key
 *   " " + flags + " " + data length + "\r\n" + data (with \r\n)
 */
static rstatus_t
asc_respond_get(struct conn *c, unsigned valid_key_iter, struct item *it)
{
    rstatus_t status;
    char *suffix = NULL;
    int sz;
    int total_len = 0;

    status = conn_add_iov(c, "VALUE ", sizeof("VALUE ") - 1);
    if (status != MC_OK) {
        return status;
    }

    status = conn_add_iov(c, item_key(it), it->nkey);
    if (status != MC_OK) {
        return status;
    }
    total_len += it->nkey;

    status = asc_create_suffix(c, valid_key_iter, &suffix);
    if (status != MC_OK) {
        return status;
    }

    sz = mc_snprintf(suffix, SUFFIX_MAX_LEN, " %"PRIu32" %"PRIu32,
                  it->dataflags, it->nbyte);
    if (sz < 0) {
        return MC_ERROR;
    }

    status = conn_add_iov(c, suffix, sz);
    if (status != MC_OK) {
        return status;
    }
    total_len += sz;

    status = conn_add_iov(c, CRLF, CRLF_LEN);
    if (status != MC_OK) {
        return status;
    }
    total_len += CRLF_LEN;

    status = conn_add_iov(c, item_data(it), it->nbyte);
    if (status != MC_OK) {
        return status;
    }
    total_len += it->nbyte;

    status = conn_add_iov(c, CRLF, CRLF_LEN);
    if (status != MC_OK) {
        return status;
    }
    total_len += CRLF_LEN;

    return MC_OK;
}

static void
asc_process_read(struct conn *c, struct token *token, int ntoken)
{
    rstatus_t status;
    char *key;
    size_t nkey;
    unsigned valid_key_iter = 0;
    struct item *it;
    struct token *key_token;

    if (!asc_ntoken_valid(c, ntoken)) {
        log_hexdump(LOG_NOTICE, c->req, c->req_len, "client error on c %d for "
                    "req of type %d with %d invalid tokens", c->sd,
                    c->req_type, ntoken);

        asc_write_client_error(c);
        return;
    }

    key_token = &token[TOKEN_KEY];

    do {
        while (key_token->len != 0) {

            key = key_token->val;
            nkey = key_token->len;

            if (nkey > KEY_MAX_LEN) {
                log_debug(LOG_NOTICE, "client error on c %d for req of type %d "
                          "and %d length key", c->sd, c->req_type, nkey);

                asc_write_client_error(c);
                return;
            }

            stats_thread_incr(get);

            it = item_get(key, nkey);
            if (it != NULL) {
                /* item found */
                stats_slab_incr(it->cid, get_hit);

                if (valid_key_iter >= c->isize) {
                    struct item **new_list;

                    new_list = mc_realloc(c->ilist, sizeof(struct item *) * c->isize * 2);
                    if (new_list != NULL) {
                        c->isize *= 2;
                        c->ilist = new_list;
                    } else {
                        item_remove(it);
                        break;
                    }
                }

                status = asc_respond_get(c, valid_key_iter, it);
                if (status != MC_OK) {
                    log_debug(LOG_NOTICE, "client error on c %d for req of type "
                              "%d with %d tokens", c->sd, c->req_type, ntoken);

                    stats_thread_incr(cmd_error);
                    item_remove(it);
                    break;
                }

                log_debug(LOG_VVERB, ">%d sending key %.*s", c->sd, it->nkey,
                          item_key(it));

                *(c->ilist + valid_key_iter) = it;
                valid_key_iter++;
            } else {
                /* item not found */
                stats_thread_incr(get_miss);
            }

            key_token++;
        }

        /*
         * If the command string hasn't been fully processed, get the next set
         * of token.
         */
        if (key_token->val != NULL) {
            ntoken = asc_tokenize(key_token->val, token, TOKEN_MAX);
            /* ntoken is unused */
            key_token = token;
        }

    } while (key_token->val != NULL);

    c->icurr = c->ilist;
    c->ileft = valid_key_iter;

    log_debug(LOG_VVERB, ">%d END", c->sd);

    /*
     * If the loop was terminated because of out-of-memory, it is not
     * reliable to add END\r\n to the buffer, because it might not end
     * in \r\n. So we send SERVER_ERROR instead.
     */
    if (key_token->val != NULL || conn_add_iov(c, "END\r\n", 5) != MC_OK) {
        log_warn("server error on c %d for req of type %d with enomem", c->sd,
                 c->req_type);
        asc_write_server_error(c);
    } else {
        conn_set_state(c, CONN_MWRITE);
        c->msg_curr = 0;
    }
}

static void
asc_process_update(struct conn *c, struct token *token, int ntoken)
{
    char *key;
    size_t nkey;
    uint32_t flags, vlen;
    int32_t exptime_int;
    time_t exptime;
    struct item *it;
    req_type_t type;
    uint8_t cid;

    asc_set_noreply_maybe(c, token, ntoken);

    if (!asc_ntoken_valid(c, ntoken)) {
        log_hexdump(LOG_NOTICE, c->req, c->req_len, "client error on c %d for "
                    "req of type %d with %d invalid tokens", c->sd,
                    c->req_type, ntoken);

        asc_write_client_error(c);
        return;
    }

    type = c->req_type;
    key = token[TOKEN_KEY].val;
    nkey = token[TOKEN_KEY].len;

    if (nkey > KEY_MAX_LEN) {
        log_debug(LOG_NOTICE, "client error on c %d for req of type %d and %d "
                  "length key", c->sd, c->req_type, nkey);

        asc_write_client_error(c);
        return;
    }

    if (!mc_strtoul(token[TOKEN_FLAGS].val, &flags)) {
        log_debug(LOG_NOTICE, "client error on c %d for req of type %d and "
                  "invalid flags '%.*s'", c->sd, c->req_type,
                  token[TOKEN_FLAGS].len, token[TOKEN_FLAGS].val);

        asc_write_client_error(c);
        return;
    }

    if (!mc_strtol(token[TOKEN_EXPIRY].val, &exptime_int)) {
        log_debug(LOG_NOTICE, "client error on c %d for req of type %d and "
                  "invalid expiry '%.*s'", c->sd, c->req_type,
                  token[TOKEN_EXPIRY].len, token[TOKEN_EXPIRY].val);

        asc_write_client_error(c);
        return;
    }

    if (!mc_strtoul(token[TOKEN_VLEN].val, &vlen)) {
        log_debug(LOG_NOTICE, "client error on c %d for req of type %d and "
                  "invalid vlen '%.*s'", c->sd, c->req_type,
                  token[TOKEN_VLEN].len, token[TOKEN_VLEN].val);

        asc_write_client_error(c);
        return;
    }

    cid = item_slabcid(nkey, vlen);
    if (cid == SLABCLASS_INVALID_ID) {
        log_debug(LOG_NOTICE, "client error on c %d for req of type %d and "
                  "slab id out of range for key size %"PRIu8" and value size "
                  "%"PRIu32, c->sd, c->req_type, nkey, vlen);

        asc_write_client_error(c);
        return;
    }

    exptime = (time_t)exptime_int;

    it = item_alloc(cid, key, nkey, flags, time_reltime(exptime), vlen);
    if (it == NULL) {
        log_warn("server error on c %d for req of type %d because of oom in "
                 "storing item", c->sd, c->req_type);

        asc_write_server_error(c);

        /* swallow the data line */
        c->write_and_go = CONN_SWALLOW;
        c->sbytes = vlen + CRLF_LEN;

        /*
         * Avoid stale data persisting in cache because we failed alloc.
         * Unacceptable for SET. Anywhere else too?
         *
         * FIXME: either don't delete anything or should be unacceptable for
         * all but add.
         */
        if (type == REQ_SET) {
            it = item_get(key, nkey);
            if (it != NULL) {
                item_delete(it);
            }
        }
        return;
    }

    c->item = it;
    c->ritem = item_data(it);
    c->rlbytes = it->nbyte + CRLF_LEN;
    conn_set_state(c, CONN_NREAD);
}

static void
asc_process_stats(struct conn *c, struct token *token, int ntoken)
{
    struct token *t = &token[TOKEN_SUBCOMMAND];

    if (!stats_enabled()) {
        log_warn("server error on c %d for req of type %d because stats is "
                 "disabled", c->sd, c->req_type);

        asc_write_server_error(c);
        return;
    }

    if (!asc_ntoken_valid(c, ntoken)) {
        log_hexdump(LOG_NOTICE, c->req, c->req_len, "client error on c %d for "
                    "req of type %d with %d invalid tokens", c->sd,
                    c->req_type, ntoken);
        asc_write_client_error(c);
        return;
    }

    if (ntoken == 2) {
        stats_default(c);
    } else {
        /*
         * Getting here means that the sub command is either engine specific
         * or is invalid. query the engine and see
         */
        if (strncmp(t->val, "slabs", t->len) == 0) {
            stats_slabs(c);
        } else {
            log_debug(LOG_NOTICE, "client error on c %d for req of type %d with "
                      "invalid stats subcommand '%.*s", c->sd, c->req_type,
                      t->len, t->val);
            asc_write_client_error(c);
            return;
        }

        if (c->stats.buffer == NULL) {
            log_warn("server error on c %d for req of type %d because of oom "
                     "writing stats", c->sd, c->req_type);
            asc_write_server_error(c);
        } else {
            core_write_and_free(c, c->stats.buffer, c->stats.offset);
            c->stats.buffer = NULL;
        }

        return;
    }

    /* append terminator and start the transfer */
    stats_append(c, NULL, 0, NULL, 0);

    if (c->stats.buffer == NULL) {
        log_warn("server error on c %d for req of type %d because of oom "
                 "writing stats", c->sd, c->req_type);

        asc_write_server_error(c);
    } else {
        core_write_and_free(c, c->stats.buffer, c->stats.offset);
        c->stats.buffer = NULL;
    }
}

static req_type_t
asc_parse_type(struct conn *c, struct token *token, int ntoken)
{
    char *tval;      /* token value */
    size_t tlen;     /* token length */
    req_type_t type; /* request type */

    if (ntoken < 2) {
        return REQ_UNKNOWN;
    }

    tval = token[TOKEN_COMMAND].val;
    tlen = token[TOKEN_COMMAND].len;

    type = REQ_UNKNOWN;

    switch (tlen) {
    case 3:
        if (str4cmp(tval, 'g', 'e', 't', ' ')) {
            type = REQ_GET;
        } else if (str4cmp(tval, 's', 'e', 't', ' ')) {
            type = REQ_SET;
        }

        break;

    case 5:
        if (str5cmp(tval, 's', 't', 'a', 't', 's')) {
            type = REQ_STATS;
        }

        break;

    default:
        type = REQ_UNKNOWN;
        break;
    }

    return type;
}

static void
asc_dispatch(struct conn *c)
{
    rstatus_t status;
    struct token token[TOKEN_MAX];
    int ntoken;

    /*
     * For commands set, add, or replace, we build an item and read the data
     * directly into it, then continue in asc_complete_nread().
     */

    c->msg_curr = 0;
    c->msg_used = 0;
    c->iov_used = 0;
    status = conn_add_msghdr(c);
    if (status != MC_OK) {
        log_warn("server error on c %d for req of type %d because of oom in "
                 "preparing response", c->sd, c->req_type);

        asc_write_server_error(c);
        return;
    }

    ntoken = asc_tokenize(c->req, token, TOKEN_MAX);

    c->req_type = asc_parse_type(c, token, ntoken);
    switch (c->req_type) {
    case REQ_GET:
        /* we do not update stats metrics here because of multi-get */
        asc_process_read(c, token, ntoken);
        break;

    case REQ_SET:
        stats_thread_incr(set);
        asc_process_update(c, token, ntoken);
        break;

    case REQ_STATS:
        stats_thread_incr(stats);
        asc_process_stats(c, token, ntoken);
        break;

    case REQ_UNKNOWN:
    default:
        log_hexdump(LOG_INFO, c->req, c->req_len, "req on c %d with %d "
                    "invalid tokens", c->sd, ntoken);
        asc_write_client_error(c);
        break;
    }
}

rstatus_t
asc_parse(struct conn *c)
{
    char *el, *cont; /* eol marker, continue marker */

    ASSERT(c->rcurr <= c->rbuf + c->rsize);

    if (c->rbytes == 0) {
        return MC_EAGAIN;
    }

    el = memchr(c->rcurr, '\n', c->rbytes);
    if (el == NULL) {
        if (c->rbytes > 1024) {
            char *ptr = c->rcurr;

            /*
             * We didn't have a '\n' in the first k. This _has_ to be a
             * large multiget, if not we should just nuke the connection.
             */

            /* ignore leading whitespaces */
            while (*ptr == ' ') {
                ++ptr;
            }

            if (ptr - c->rcurr > 100 || strncmp(ptr, "get ", 4) != 0) {
                conn_set_state(c, CONN_CLOSE);
                return MC_ERROR;
            }
        }

        return MC_EAGAIN;
    }

    cont = el + 1;
    if ((el - c->rcurr) > 1 && *(el - 1) == '\r') {
        el--;
    }
    *el = '\0';

    log_hexdump(LOG_VERB, c->rcurr, el - c->rcurr, "recv on c %d req with "
                "%d bytes", c->sd, el - c->rcurr);

    ASSERT(cont <= c->rbuf + c->rsize);
    ASSERT(cont <= c->rcurr + c->rbytes);

    c->req = c->rcurr;
    c->req_len = (uint16_t)(el - c->rcurr);

    asc_dispatch(c);

    /* update the read marker to point to continue marker */
    c->rbytes -= (cont - c->rcurr);
    c->rcurr = cont;

    return MC_OK;
}

void
asc_append_stats(struct conn *c, const char *key, uint16_t klen,
                 const char *val, uint32_t vlen)
{
    char *pos;
    uint32_t nbyte;
    int remaining, room;

    pos = c->stats.buffer + c->stats.offset;
    remaining = c->stats.size - c->stats.offset;
    room = remaining - 1;

    if (klen == 0 && vlen == 0) {
        nbyte = snprintf(pos, room, "END\r\n");
    } else if (vlen == 0) {
        nbyte = snprintf(pos, room, "STAT %s\r\n", key);
    } else {
        nbyte = snprintf(pos, room, "STAT %s %s\r\n", key, val);
    }

    c->stats.offset += nbyte;
}
