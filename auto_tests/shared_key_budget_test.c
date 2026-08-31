/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2026 The TokTok team.
 */

#include <stdint.h>
#include <string.h>

#include "../toxcore/crypto_core.h"
#include "../toxcore/logger.h"
#include "../toxcore/mono_time.h"
#include "../toxcore/network.h"
#include "../toxcore/network_internal.h"
#include "../toxcore/os_memory.h"
#include "../toxcore/os_network.h"
#include "../toxcore/shared_key_cache_internal.h"
#include "check_compat.h"

typedef struct Test_Clock {
    uint64_t now_ms;
} Test_Clock;

typedef struct Budget_Fixture {
    const Memory *mem;
    const Network *ns;
    Logger *log;
    Mono_Time *mono_time;
    Networking_Core *net;
    Shared_Key_Cache *cache;
    uint8_t self_secret_key[CRYPTO_SECRET_KEY_SIZE];
    uint32_t next_key;
    Test_Clock clock;
} Budget_Fixture;

static void derive_test_key(uint32_t value, uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE],
                            uint8_t secret_key[CRYPTO_SECRET_KEY_SIZE])
{
    memset(secret_key, 0, CRYPTO_SECRET_KEY_SIZE);
    secret_key[0] = (uint8_t)value;
    secret_key[1] = (uint8_t)(value >> 8);
    secret_key[2] = (uint8_t)(value >> 16);
    secret_key[3] = (uint8_t)(value >> 24);
    secret_key[CRYPTO_SECRET_KEY_SIZE - 1] = 0x5a;
    crypto_derive_public_key(public_key, secret_key);
}

static uint64_t test_clock_now(void *user_data)
{
    const Test_Clock *clock = (const Test_Clock *)user_data;
    return clock->now_ms;
}

static void fixture_init(Budget_Fixture *fixture)
{
    memset(fixture, 0, sizeof(*fixture));
    fixture->mem = os_memory();
    fixture->ns = os_network();
    ck_assert(fixture->mem != nullptr);
    ck_assert(fixture->ns != nullptr);
    fixture->log = logger_new(fixture->mem);
    ck_assert(fixture->log != nullptr);
    fixture->clock.now_ms = UINT64_C(1000000);
    fixture->mono_time = mono_time_new(fixture->mem, test_clock_now, &fixture->clock);
    ck_assert(fixture->mono_time != nullptr);
    fixture->net = new_networking_no_udp(fixture->log, fixture->mem, fixture->ns);
    ck_assert(fixture->net != nullptr);
    uint8_t self_public_key[CRYPTO_PUBLIC_KEY_SIZE];
    derive_test_key(UINT32_C(0x10000000), self_public_key, fixture->self_secret_key);
    fixture->cache = shared_key_cache_new(
                         fixture->log, fixture->mono_time, fixture->mem,
                         fixture->self_secret_key, UINT64_C(60000), 4);
    ck_assert(fixture->cache != nullptr);
    fixture->next_key = UINT32_C(0x20000000);
}

static void fixture_kill(Budget_Fixture *fixture)
{
    shared_key_cache_free(fixture->cache);
    kill_networking(fixture->net);
    mono_time_free(fixture->mem, fixture->mono_time);
    logger_kill(fixture->log);
}

static const uint8_t *fixture_lookup_policy(
    Budget_Fixture *fixture, Shared_Key_Cache *cache, const IP *source,
    const uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE],
    Shared_Key_Budget_Policy policy)
{
    if (policy == SHARED_KEY_BUDGET_AGGREGATE_RELAY) {
        return shared_key_cache_lookup_inbound_aggregate(
                   cache, fixture->net, source, public_key);
    }

    return shared_key_cache_lookup_inbound(
               cache, fixture->net, source, public_key);
}

static const uint8_t *fixture_lookup_new_key_in_cache_policy(
    Budget_Fixture *fixture, Shared_Key_Cache *cache, const IP *source,
    Shared_Key_Budget_Policy policy)
{
    uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t secret_key[CRYPTO_SECRET_KEY_SIZE];
    derive_test_key(fixture->next_key, public_key, secret_key);
    fixture->next_key += 8; /* Preserve uniqueness after Curve25519 scalar clamping. */
    return fixture_lookup_policy(fixture, cache, source, public_key, policy);
}

static const uint8_t *fixture_lookup_new_key_in_cache(
    Budget_Fixture *fixture, Shared_Key_Cache *cache, const IP *source)
{
    return fixture_lookup_new_key_in_cache_policy(
               fixture, cache, source, SHARED_KEY_BUDGET_STRICT_SOURCE);
}

static const uint8_t *fixture_lookup_new_key(Budget_Fixture *fixture, const IP *source)
{
    return fixture_lookup_new_key_in_cache(fixture, fixture->cache, source);
}

static const uint8_t *fixture_lookup_new_key_aggregate(
    Budget_Fixture *fixture, const IP *source)
{
    return fixture_lookup_new_key_in_cache_policy(
               fixture, fixture->cache, source, SHARED_KEY_BUDGET_AGGREGATE_RELAY);
}

static bool fixture_lookup_cold_identity(
    Budget_Fixture *fixture, const IP *source,
    const uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE],
    Shared_Key_Budget_Policy policy)
{
    Shared_Key_Cache *cache = shared_key_cache_new(
                                  fixture->log, fixture->mono_time, fixture->mem,
                                  fixture->self_secret_key, UINT64_C(60000), 4);
    ck_assert(cache != nullptr);
    const bool allowed = fixture_lookup_policy(
                             fixture, cache, source, public_key, policy) != nullptr;
    shared_key_cache_free(cache);
    return allowed;
}

static void fixture_advance(Budget_Fixture *fixture, uint64_t milliseconds)
{
    fixture->clock.now_ms += milliseconds;
    mono_time_update(fixture->mono_time);
}

static IP source_ipv4(uint32_t host_address)
{
    IP source;
    ip_reset(&source);
    source.family = net_family_ipv4();
    source.ip.v4.uint32 = net_htonl(host_address);
    return source;
}

static IP source_mapped_ipv6(uint32_t host_address)
{
    IP source;
    ip_reset(&source);
    source.family = net_family_ipv6();
    source.ip.v6.uint32[2] = net_htonl(UINT32_C(0x0000ffff));
    source.ip.v6.uint32[3] = net_htonl(host_address);
    return source;
}

static IP source_tcp_client(uint32_t connection_id, uint64_t identifier)
{
    IP source;
    ip_reset(&source);
    source.family = net_family_tcp_client();
    source.ip.v6.uint32[0] = connection_id;
    source.ip.v6.uint64[1] = identifier;
    return source;
}

static void test_tcp_client_source_bound_and_refill(void)
{
    Budget_Fixture fixture;
    fixture_init(&fixture);
    const IP source = source_tcp_client(7, UINT64_C(0x5000000000000001));

    for (uint32_t i = 0; i < NET_SHARED_KEY_SOURCE_BURST; ++i) {
        ck_assert(fixture_lookup_new_key(&fixture, &source) != nullptr);
    }

    networking_poll(fixture.net, nullptr);
    ck_assert(fixture_lookup_new_key(&fixture, &source) == nullptr);
    fixture_advance(&fixture, 62);
    ck_assert(fixture_lookup_new_key(&fixture, &source) == nullptr);
    fixture_advance(&fixture, 1);
    ck_assert(fixture_lookup_new_key(&fixture, &source) != nullptr);
    ck_assert(networking_shared_key_budget_tracked_sources_internal(fixture.net) == 1);
    fixture_kill(&fixture);
}

static void test_tcp_client_iteration_bound(void)
{
    Budget_Fixture fixture;
    fixture_init(&fixture);

    for (uint32_t i = 0; i < NET_SHARED_KEY_ITERATION_CAP; ++i) {
        const IP source = source_tcp_client(
                              i + 1U, UINT64_C(0x5100000000000000) + i);
        ck_assert(fixture_lookup_new_key(&fixture, &source) != nullptr);
    }

    const IP overflow = source_tcp_client(
                            NET_SHARED_KEY_ITERATION_CAP + 1U,
                            UINT64_C(0x5100000000000000) + NET_SHARED_KEY_ITERATION_CAP);
    ck_assert(fixture_lookup_new_key(&fixture, &overflow) == nullptr);
    networking_poll(fixture.net, nullptr);
    ck_assert(fixture_lookup_new_key(&fixture, &overflow) != nullptr);
    fixture_kill(&fixture);
}

static void test_tcp_client_global_bound(void)
{
    Budget_Fixture fixture;
    fixture_init(&fixture);

    for (uint32_t i = 0; i < NET_SHARED_KEY_GLOBAL_BURST; ++i) {
        const uint32_t connection = i / NET_SHARED_KEY_SOURCE_BURST;
        const IP source = source_tcp_client(
                              connection + 1U,
                              UINT64_C(0x5200000000000000) + connection);
        ck_assert(fixture_lookup_new_key(&fixture, &source) != nullptr);

        if ((i + 1) % NET_SHARED_KEY_ITERATION_CAP == 0) {
            networking_poll(fixture.net, nullptr);
        }
    }

    const IP overflow = source_tcp_client(999, UINT64_C(0x52ffffffffffffff));
    ck_assert(fixture_lookup_new_key(&fixture, &overflow) == nullptr);
    fixture_advance(&fixture, 3);
    ck_assert(fixture_lookup_new_key(&fixture, &overflow) == nullptr);
    fixture_advance(&fixture, 1);
    ck_assert(fixture_lookup_new_key(&fixture, &overflow) != nullptr);
    fixture_kill(&fixture);
}

static void test_iteration_bound(void)
{
    Budget_Fixture fixture;
    fixture_init(&fixture);

    for (uint32_t i = 0; i < NET_SHARED_KEY_ITERATION_CAP; ++i) {
        const IP source = source_ipv4(UINT32_C(0x0a000001) + i);
        ck_assert(fixture_lookup_new_key(&fixture, &source) != nullptr);
    }

    const IP overflow = source_ipv4(
                            UINT32_C(0x0a000001) + NET_SHARED_KEY_ITERATION_CAP);
    ck_assert(fixture_lookup_new_key(&fixture, &overflow) == nullptr);
    networking_poll(fixture.net, nullptr);
    ck_assert(fixture_lookup_new_key(&fixture, &overflow) != nullptr);
    fixture_kill(&fixture);
}

static void test_source_bound_and_refill(void)
{
    Budget_Fixture fixture;
    fixture_init(&fixture);
    const IP source = source_ipv4(UINT32_C(0x0a010001));

    for (uint32_t i = 0; i < NET_SHARED_KEY_IP_SOURCE_BURST; ++i) {
        ck_assert(fixture_lookup_new_key(&fixture, &source) != nullptr);
    }

    networking_poll(fixture.net, nullptr);
    ck_assert(fixture_lookup_new_key(&fixture, &source) == nullptr);
    fixture_advance(&fixture, 62);
    ck_assert(fixture_lookup_new_key(&fixture, &source) == nullptr);
    fixture_advance(&fixture, 1);
    ck_assert(fixture_lookup_new_key(&fixture, &source) != nullptr);
    fixture_kill(&fixture);
}

static void test_global_bound_and_refill(void)
{
    Budget_Fixture fixture;
    fixture_init(&fixture);

    for (uint32_t i = 0; i < NET_SHARED_KEY_GLOBAL_BURST; ++i) {
        const IP source = source_ipv4(
                              UINT32_C(0x0a020001) + i / NET_SHARED_KEY_IP_SOURCE_BURST);
        ck_assert(fixture_lookup_new_key(&fixture, &source) != nullptr);

        if ((i + 1) % NET_SHARED_KEY_ITERATION_CAP == 0) {
            networking_poll(fixture.net, nullptr);
        }
    }

    const IP overflow = source_ipv4(UINT32_C(0x0a02ff01));
    ck_assert(fixture_lookup_new_key(&fixture, &overflow) == nullptr);
    fixture_advance(&fixture, 3);
    ck_assert(fixture_lookup_new_key(&fixture, &overflow) == nullptr);
    fixture_advance(&fixture, 1);
    ck_assert(fixture_lookup_new_key(&fixture, &overflow) != nullptr);
    fixture_kill(&fixture);
}

static void test_aggregate_relay_iteration_bound(void)
{
    Budget_Fixture fixture;
    fixture_init(&fixture);
    const IP relay = source_ipv4(UINT32_C(0x0e000001));

    for (uint32_t i = 0; i < NET_SHARED_KEY_ITERATION_CAP; ++i) {
        ck_assert(fixture_lookup_new_key_aggregate(&fixture, &relay) != nullptr);
    }

    ck_assert(fixture_lookup_new_key_aggregate(&fixture, &relay) == nullptr);
    networking_poll(fixture.net, nullptr);
    ck_assert(fixture_lookup_new_key_aggregate(&fixture, &relay) != nullptr);
    fixture_kill(&fixture);
}

static void test_aggregate_relay_identity_bound_and_refill(void)
{
    Budget_Fixture fixture;
    fixture_init(&fixture);
    const IP relay = source_ipv4(UINT32_C(0x0e010001));
    uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t secret_key[CRYPTO_SECRET_KEY_SIZE];
    derive_test_key(UINT32_C(0x41000000), public_key, secret_key);

    for (uint32_t i = 0; i < NET_SHARED_KEY_SOURCE_BURST; ++i) {
        ck_assert(fixture_lookup_cold_identity(
                      &fixture, &relay, public_key,
                      SHARED_KEY_BUDGET_AGGREGATE_RELAY));
    }

    ck_assert(!fixture_lookup_cold_identity(
                  &fixture, &relay, public_key,
                  SHARED_KEY_BUDGET_AGGREGATE_RELAY));
    fixture_advance(&fixture, 62);
    ck_assert(!fixture_lookup_cold_identity(
                  &fixture, &relay, public_key,
                  SHARED_KEY_BUDGET_AGGREGATE_RELAY));
    fixture_advance(&fixture, 1);
    ck_assert(fixture_lookup_cold_identity(
                  &fixture, &relay, public_key,
                  SHARED_KEY_BUDGET_AGGREGATE_RELAY));
    fixture_kill(&fixture);
}

static void test_aggregate_relay_global_bound(void)
{
    Budget_Fixture fixture;
    fixture_init(&fixture);
    const IP relay = source_ipv4(UINT32_C(0x0e020001));

    for (uint32_t i = 0; i < NET_SHARED_KEY_GLOBAL_BURST; ++i) {
        ck_assert(fixture_lookup_new_key_aggregate(&fixture, &relay) != nullptr);

        if ((i + 1) % NET_SHARED_KEY_ITERATION_CAP == 0) {
            networking_poll(fixture.net, nullptr);
        }
    }

    ck_assert(fixture_lookup_new_key_aggregate(&fixture, &relay) == nullptr);
    fixture_advance(&fixture, 3);
    ck_assert(fixture_lookup_new_key_aggregate(&fixture, &relay) == nullptr);
    fixture_advance(&fixture, 1);
    ck_assert(fixture_lookup_new_key_aggregate(&fixture, &relay) != nullptr);
    fixture_kill(&fixture);
}

static void test_budget_policies_do_not_alias(void)
{
    Budget_Fixture fixture;
    fixture_init(&fixture);
    const IP relay = source_ipv4(UINT32_C(0x0e030001));
    uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t secret_key[CRYPTO_SECRET_KEY_SIZE];
    derive_test_key(UINT32_C(0x42000000), public_key, secret_key);

    ck_assert(fixture_lookup_cold_identity(
                  &fixture, &relay, public_key,
                  SHARED_KEY_BUDGET_STRICT_SOURCE));
    ck_assert(fixture_lookup_cold_identity(
                  &fixture, &relay, public_key,
                  SHARED_KEY_BUDGET_AGGREGATE_RELAY));

    for (uint32_t i = 1; i < NET_SHARED_KEY_SOURCE_BURST; ++i) {
        ck_assert(fixture_lookup_cold_identity(
                      &fixture, &relay, public_key,
                      SHARED_KEY_BUDGET_AGGREGATE_RELAY));
    }

    ck_assert(!fixture_lookup_cold_identity(
                  &fixture, &relay, public_key,
                  SHARED_KEY_BUDGET_AGGREGATE_RELAY));
    ck_assert(fixture_lookup_cold_identity(
                  &fixture, &relay, public_key,
                  SHARED_KEY_BUDGET_STRICT_SOURCE));
    ck_assert(networking_shared_key_budget_tracked_sources_internal(fixture.net) == 2);
    fixture_kill(&fixture);
}

static void test_global_budget_shared_across_caches(void)
{
    Budget_Fixture fixture;
    fixture_init(&fixture);
    uint8_t second_public_key[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t second_secret_key[CRYPTO_SECRET_KEY_SIZE];
    derive_test_key(UINT32_C(0x30000000), second_public_key, second_secret_key);
    Shared_Key_Cache *second_cache = shared_key_cache_new(
                                         fixture.log, fixture.mono_time, fixture.mem,
                                         second_secret_key, UINT64_C(60000), 4);
    ck_assert(second_cache != nullptr);

    for (uint32_t i = 0; i < NET_SHARED_KEY_GLOBAL_BURST; ++i) {
        const IP source = source_ipv4(
                              UINT32_C(0x0d000001) + i / NET_SHARED_KEY_IP_SOURCE_BURST);
        Shared_Key_Cache *cache = i % 2 == 0 ? fixture.cache : second_cache;
        ck_assert(fixture_lookup_new_key_in_cache(&fixture, cache, &source) != nullptr);

        if ((i + 1) % NET_SHARED_KEY_ITERATION_CAP == 0) {
            networking_poll(fixture.net, nullptr);
        }
    }

    const IP overflow = source_ipv4(UINT32_C(0x0d00ff01));
    ck_assert(fixture_lookup_new_key_in_cache(
                  &fixture, second_cache, &overflow) == nullptr);
    shared_key_cache_free(second_cache);
    fixture_kill(&fixture);
}

static void test_source_normalization(void)
{
    Budget_Fixture fixture;
    fixture_init(&fixture);
    const IP source4 = source_ipv4(UINT32_C(0x7f000001));
    const IP mapped = source_mapped_ipv6(UINT32_C(0x7f000001));
    IP non_udp = source4;
    non_udp.family = net_family_tcp_ipv4();
    ck_assert(fixture_lookup_new_key(&fixture, &non_udp) == nullptr);
    non_udp.family = net_family_tcp_server();
    ck_assert(fixture_lookup_new_key(&fixture, &non_udp) == nullptr);
    non_udp.family = net_family_unspec();
    ck_assert(fixture_lookup_new_key(&fixture, &non_udp) == nullptr);
    const IP tcp_client = source_tcp_client(1, UINT64_C(0x5300000000000001));
    ck_assert(fixture_lookup_new_key_aggregate(&fixture, &tcp_client) == nullptr);
    ck_assert(networking_shared_key_budget_tracked_sources_internal(fixture.net) == 0);

    for (uint32_t i = 0; i < NET_SHARED_KEY_IP_SOURCE_BURST - 1; ++i) {
        ck_assert(fixture_lookup_new_key(&fixture, &source4) != nullptr);
    }

    ck_assert(fixture_lookup_new_key(&fixture, &mapped) != nullptr);
    networking_poll(fixture.net, nullptr);
    ck_assert(fixture_lookup_new_key(&fixture, &source4) == nullptr);
    ck_assert(networking_shared_key_budget_tracked_sources_internal(fixture.net) == 1);
    fixture_kill(&fixture);
}

static void test_exact_lru_cap(void)
{
    Budget_Fixture fixture;
    fixture_init(&fixture);

    for (uint32_t i = 0; i < NET_SHARED_KEY_SOURCE_CAP; ++i) {
        if (i != 0 && i % NET_SHARED_KEY_ITERATION_CAP == 0) {
            networking_poll(fixture.net, nullptr);
            fixture_advance(&fixture, 250);
        }

        const IP source = source_ipv4(UINT32_C(0x0b000001) + i);
        ck_assert(fixture_lookup_new_key(&fixture, &source) != nullptr);
    }

    const IP source0 = source_ipv4(UINT32_C(0x0b000001));
    const IP source1 = source_ipv4(UINT32_C(0x0b000002));
    const IP newcomer = source_ipv4(UINT32_C(0x0b000001) + NET_SHARED_KEY_SOURCE_CAP);
    ck_assert(networking_shared_key_budget_tracked_sources_internal(fixture.net) == NET_SHARED_KEY_SOURCE_CAP);
    ck_assert(networking_shared_key_budget_tracks_source_internal(fixture.net, &source0));
    ck_assert(networking_shared_key_budget_tracks_source_internal(fixture.net, &source1));

    networking_poll(fixture.net, nullptr);
    ck_assert(fixture_lookup_new_key(&fixture, &source0) != nullptr);
    ck_assert(fixture_lookup_new_key(&fixture, &newcomer) != nullptr);
    ck_assert(networking_shared_key_budget_tracked_sources_internal(fixture.net) == NET_SHARED_KEY_SOURCE_CAP);
    ck_assert(networking_shared_key_budget_tracks_source_internal(fixture.net, &source0));
    ck_assert(!networking_shared_key_budget_tracks_source_internal(fixture.net, &source1));
    ck_assert(networking_shared_key_budget_tracks_source_internal(fixture.net, &newcomer));
    fixture_kill(&fixture);
}

static void test_cache_hit_and_denied_miss(void)
{
    Budget_Fixture fixture;
    fixture_init(&fixture);
    uint8_t self_pk[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t self_sk[CRYPTO_SECRET_KEY_SIZE];
    uint8_t first_pk[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t first_sk[CRYPTO_SECRET_KEY_SIZE];
    uint8_t colliding_pk[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t colliding_sk[CRYPTO_SECRET_KEY_SIZE];
    derive_test_key(1, self_pk, self_sk);
    derive_test_key(2, first_pk, first_sk);

    bool found_collision = false;

    for (uint32_t value = 3; value < UINT32_C(65539); ++value) {
        derive_test_key(value, colliding_pk, colliding_sk);

        if (colliding_pk[8] == first_pk[8]
                && memcmp(colliding_pk, first_pk, CRYPTO_PUBLIC_KEY_SIZE) != 0) {
            found_collision = true;
            break;
        }
    }

    ck_assert(found_collision);
    Shared_Key_Cache *cache = shared_key_cache_new(
                                   fixture.log, fixture.mono_time, fixture.mem,
                                   self_sk, UINT64_C(60000), 1);
    ck_assert(cache != nullptr);
    const IP source = source_ipv4(UINT32_C(0x0c000001));
    const uint8_t *first = shared_key_cache_lookup_inbound(
                               cache, fixture.net, &source, first_pk);
    ck_assert(first != nullptr);
    uint8_t expected[CRYPTO_SHARED_KEY_SIZE];
    memcpy(expected, first, sizeof(expected));

    for (uint32_t i = 1; i < NET_SHARED_KEY_ITERATION_CAP; ++i) {
        const IP other_source = source_ipv4(UINT32_C(0x0c000001) + i);
        ck_assert(fixture_lookup_new_key(&fixture, &other_source) != nullptr);
    }

    const IP overflow = source_ipv4(
                            UINT32_C(0x0c000001) + NET_SHARED_KEY_ITERATION_CAP);
    ck_assert(fixture_lookup_new_key(&fixture, &overflow) == nullptr);
    const uint8_t *hit = shared_key_cache_lookup_inbound(
                             cache, fixture.net, &source, first_pk);
    ck_assert(hit != nullptr);
    ck_assert(memcmp(hit, expected, sizeof(expected)) == 0);
    ck_assert(shared_key_cache_lookup_inbound(
                  cache, fixture.net, &source, colliding_pk) == nullptr);
    hit = shared_key_cache_lookup_inbound(cache, fixture.net, &source, first_pk);
    ck_assert(hit != nullptr);
    ck_assert(memcmp(hit, expected, sizeof(expected)) == 0);

    shared_key_cache_free(cache);
    fixture_kill(&fixture);
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);
    test_tcp_client_source_bound_and_refill();
    test_tcp_client_iteration_bound();
    test_tcp_client_global_bound();
    test_iteration_bound();
    test_source_bound_and_refill();
    test_global_bound_and_refill();
    test_aggregate_relay_iteration_bound();
    test_aggregate_relay_identity_bound_and_refill();
    test_aggregate_relay_global_bound();
    test_budget_policies_do_not_alias();
    test_global_budget_shared_across_caches();
    test_source_normalization();
    test_exact_lru_cap();
    test_cache_hit_and_denied_miss();
    return 0;
}
