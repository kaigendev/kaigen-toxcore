/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2026 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_NETWORK_INTERNAL_H
#define C_TOXCORE_TOXCORE_NETWORK_INTERNAL_H

#include "ccompat.h"
#include "crypto_core.h"
#include "mono_time.h"
#include "network.h"

/* Private pre-authentication work limits for inbound shared-key cache misses. */
#define NET_SHARED_KEY_GLOBAL_RATE 256U
#define NET_SHARED_KEY_GLOBAL_BURST 512U
#define NET_SHARED_KEY_SOURCE_RATE 16U
#define NET_SHARED_KEY_SOURCE_BURST 32U
#define NET_SHARED_KEY_IP_SOURCE_BURST 64U
#define NET_SHARED_KEY_SOURCE_CAP 1024U
#define NET_SHARED_KEY_ITERATION_CAP 64U

#define NET_SHARED_KEY_TOKEN_UNITS 1000U
#define NET_SHARED_KEY_SOURCE_NONE UINT16_MAX

typedef struct Packet_Handler {
    packet_handler_cb *_Nullable function;
    void *_Nullable object;
} Packet_Handler;

typedef enum Shared_Key_Budget_Policy {
    SHARED_KEY_BUDGET_STRICT_SOURCE,
    SHARED_KEY_BUDGET_AGGREGATE_RELAY,
} Shared_Key_Budget_Policy;

typedef struct Shared_Key_Source_Budget {
    IP source_ip;
    uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE];
    uint64_t refill_ms;
    uint32_t token_units;
    uint16_t previous;
    uint16_t next;
    Shared_Key_Budget_Policy policy;
    bool used;
} Shared_Key_Source_Budget;

typedef struct Shared_Key_Work_Budget {
    Shared_Key_Source_Budget sources[NET_SHARED_KEY_SOURCE_CAP];
    uint64_t global_refill_ms;
    uint32_t global_token_units;
    uint16_t iteration_remaining;
    uint16_t source_count;
    uint16_t lru_head;
    uint16_t lru_tail;
    bool global_refill_set;
} Shared_Key_Work_Budget;

typedef bool networking_shared_key_budget_cb(
    Networking_Core *_Nonnull net, const Mono_Time *_Nonnull mono_time,
    const IP *_Nonnull source_ip,
    const uint8_t public_key[_Nonnull CRYPTO_PUBLIC_KEY_SIZE],
    Shared_Key_Budget_Policy policy);

struct Networking_Core {
    const Logger *_Nonnull log;
    const Memory *_Nonnull mem;
    Packet_Handler packethandlers[256];
    const Network *_Nonnull ns;

    Family family;
    uint16_t port;
    Socket sock;

    Net_Profile *_Nullable udp_net_profile;
    Shared_Key_Work_Budget shared_key_budget;
    networking_shared_key_budget_cb *_Nonnull shared_key_budget_take;
};

/** Private cross-translation-unit dispatch; never part of the exported API. */
static inline bool networking_shared_key_budget_take_internal(
    Networking_Core *net, const Mono_Time *mono_time, const IP *source_ip,
    const uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE],
    Shared_Key_Budget_Policy policy)
{
    return net != nullptr && net->shared_key_budget_take != nullptr
           && net->shared_key_budget_take(net, mono_time, source_ip, public_key, policy);
}

#ifdef C_TOXCORE_SHARED_KEY_BUDGET_TESTING
static inline size_t networking_shared_key_budget_tracked_sources_internal(
    const Networking_Core *net)
{
    return net->shared_key_budget.source_count;
}

static inline bool networking_shared_key_budget_tracks_source_internal(
    const Networking_Core *net, const IP *source_ip)
{
    IP normalized = *source_ip;

    if (net_family_is_ipv6(normalized.family) && ipv6_ipv4_in_v6(&normalized.ip.v6)) {
        normalized.family = net_family_ipv4();
        normalized.ip.v4.uint32 = normalized.ip.v6.uint32[3];
    }

    if (!net_family_is_ipv4(normalized.family) && !net_family_is_ipv6(normalized.family)) {
        return false;
    }

    for (uint16_t i = 0; i < NET_SHARED_KEY_SOURCE_CAP; ++i) {
        const Shared_Key_Source_Budget *source = &net->shared_key_budget.sources[i];

        if (source->used && ip_equal(&source->source_ip, &normalized)) {
            return true;
        }
    }

    return false;
}
#endif /* C_TOXCORE_SHARED_KEY_BUDGET_TESTING */

#endif /* C_TOXCORE_TOXCORE_NETWORK_INTERNAL_H */
