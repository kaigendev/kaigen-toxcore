/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2026 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_SHARED_KEY_CACHE_INTERNAL_H
#define C_TOXCORE_TOXCORE_SHARED_KEY_CACHE_INTERNAL_H

#include "network_internal.h"
#include "shared_key_cache.h"

typedef struct Shared_Key Shared_Key;

typedef const uint8_t *_Nullable shared_key_cache_lookup_internal_cb(
    Shared_Key_Cache *_Nonnull cache, Networking_Core *_Nullable net,
    const IP *_Nullable source_ip,
    const uint8_t public_key[_Nonnull CRYPTO_PUBLIC_KEY_SIZE],
    Shared_Key_Budget_Policy policy);

struct Shared_Key_Cache {
    Shared_Key *_Nonnull keys;
    const uint8_t *_Nonnull self_secret_key;
    uint64_t timeout;
    const Mono_Time *_Nonnull mono_time;
    const Memory *_Nonnull mem;
    const Logger *_Nonnull log;
    uint8_t keys_per_slot;
    shared_key_cache_lookup_internal_cb *_Nonnull lookup_internal;
};

/** Private inbound path: cache hits bypass the shared Networking_Core budget. */
static inline const uint8_t *_Nullable shared_key_cache_lookup_inbound(
    Shared_Key_Cache *cache, Networking_Core *net, const IP *source_ip,
    const uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE])
{
    return cache->lookup_internal(
               cache, net, source_ip, public_key, SHARED_KEY_BUDGET_STRICT_SOURCE);
}

/** Private inbound relay path: multiplexed relay keys get independent source buckets. */
static inline const uint8_t *_Nullable shared_key_cache_lookup_inbound_aggregate(
    Shared_Key_Cache *cache, Networking_Core *net, const IP *source_ip,
    const uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE])
{
    return cache->lookup_internal(
               cache, net, source_ip, public_key, SHARED_KEY_BUDGET_AGGREGATE_RELAY);
}

#endif /* C_TOXCORE_TOXCORE_SHARED_KEY_CACHE_INTERNAL_H */
