/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2026 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_DHT_INTERNAL_H
#define C_TOXCORE_TOXCORE_DHT_INTERNAL_H

#include "DHT.h"
#include "shared_key_cache_internal.h"

typedef struct Cryptopacket_Handler {
    cryptopacket_handler_cb *_Nullable function;
    void *_Nullable object;
} Cryptopacket_Handler;

struct DHT {
    const Logger *_Nonnull log;
    const Network *_Nonnull ns;
    Mono_Time *_Nonnull mono_time;
    const Memory *_Nonnull mem;
    const Random *_Nonnull rng;
    Networking_Core *_Nonnull net;

    bool hole_punching_enabled;
    bool lan_discovery_enabled;

    Client_data close_clientlist[LCLIENT_LIST];
    uint64_t close_last_nodes_request;
    uint32_t close_bootstrap_times;

    uint8_t self_public_key[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t self_secret_key[CRYPTO_SECRET_KEY_SIZE];

    DHT_Friend *_Nullable friends_list;
    uint16_t num_friends;

    Node_format *_Nullable loaded_nodes_list;
    uint32_t loaded_num_nodes;
    unsigned int loaded_nodes_index;

    Shared_Key_Cache *_Nonnull shared_keys_recv;
    Shared_Key_Cache *_Nonnull shared_keys_sent;

    struct Ping *_Nonnull ping;
    Ping_Array *_Nonnull dht_ping_array;
    uint64_t cur_time;

    Cryptopacket_Handler cryptopackethandlers[256];

    Node_format to_bootstrap[MAX_CLOSE_TO_BOOTSTRAP_NODES];
    unsigned int num_to_bootstrap;

    dht_nodes_response_cb *_Nullable nodes_response_callback;
};

/** Private inbound DHT cache path; public dht_get_shared_key_recv keeps its ABI. */
static inline const uint8_t *_Nullable dht_get_shared_key_recv_inbound(
    DHT *dht, const IP_Port *source, const uint8_t *public_key)
{
    return shared_key_cache_lookup_inbound(
               dht->shared_keys_recv, dht->net, &source->ip, public_key);
}

#endif /* C_TOXCORE_TOXCORE_DHT_INTERNAL_H */
