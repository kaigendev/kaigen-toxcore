/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2026 The TokTok team.
 * Copyright © 2013 Tox project.
 */

#ifndef C_TOXCORE_TOXCORE_ONION_ANNOUNCE_INTERNAL_H
#define C_TOXCORE_TOXCORE_ONION_ANNOUNCE_INTERNAL_H

#include <stdbool.h>
#include <stdint.h>

#include "onion_announce.h"
#include "shared_key_cache.h"

typedef int pack_extra_data_admission_cb(
    void *_Nonnull object, const Logger *_Nonnull logger,
    const Memory *_Nonnull mem, const Mono_Time *_Nonnull mono_time,
    bool timed_auth_valid, uint8_t *_Nonnull plain, uint16_t plain_size);

typedef struct Onion_Announce_Entry {
    uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE];
    IP_Port ret_ip_port;
    uint8_t ret[ONION_RETURN_3];
    uint8_t data_public_key[CRYPTO_PUBLIC_KEY_SIZE];
    uint64_t announce_time;
} Onion_Announce_Entry;

struct Onion_Announce {
    const Logger *_Nonnull log;
    const Mono_Time *_Nonnull mono_time;
    const Random *_Nonnull rng;
    const Memory *_Nonnull mem;
    DHT *_Nonnull dht;
    Networking_Core *_Nonnull net;
    Onion_Announce_Entry entries[ONION_ANNOUNCE_MAX_ENTRIES];
    uint8_t hmac_key[CRYPTO_HMAC_KEY_SIZE];

    Shared_Key_Cache *_Nonnull shared_keys_recv;

    uint16_t extra_data_max_size;
    pack_extra_data_cb *_Nullable extra_data_callback;
    pack_extra_data_admission_cb *_Nullable extra_data_admission_callback;
    void *_Nullable extra_data_object;
};

static inline void onion_announce_extra_data_admission_callback_internal(
    Onion_Announce *_Nonnull onion_a,
    pack_extra_data_admission_cb *_Nonnull admission_callback)
{
    onion_a->extra_data_admission_callback = admission_callback;
}

#endif /* C_TOXCORE_TOXCORE_ONION_ANNOUNCE_INTERNAL_H */
