/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2026 The TokTok team.
 */

/**
 * Tests GCA (group chat announce) response size bounds.
 *
 * Sends a GCA announce request to a server that has a full DHT node list and
 * a full GCA announce list, then verifies that the response fits within
 * GCA_ANNOUNCE_RESPONSE_MAX_SIZE.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../toxcore/DHT.h"
#include "../toxcore/crypto_core.h"
#include "../toxcore/group_announce.h"
#include "../toxcore/group_onion_announce.h"
#include "../toxcore/logger.h"
#include "../toxcore/mono_time.h"
#include "../toxcore/net.h"
#include "../toxcore/network.h"
#include "../toxcore/onion.h"
#include "../toxcore/onion_announce.h"
#include "../toxcore/onion_client.h"
#include "../toxcore/os_memory.h"
#include "../toxcore/os_random.h"
#include "auto_test_support.h"
#include "check_compat.h"

#ifndef USE_IPV6
#define USE_IPV6 1
#endif

static void test_client_group_retry_contract(void)
{
    const uint32_t saved_path = UINT32_C(0x1234567a);

    ck_assert_uint_eq(onion_client_announce_path_for_retry(saved_path, 0, false), saved_path);
    ck_assert_uint_eq(onion_client_announce_path_for_retry(
                          saved_path, ONION_NODE_MAX_PINGS - 1, false), saved_path);
    ck_assert_uint_eq(onion_client_announce_path_for_retry(
                          saved_path, ONION_NODE_MAX_PINGS - 1, true), UINT32_MAX);

    ck_assert_uint_eq(onion_client_normalize_announce_status(1, true, 1, 2), 0);
    ck_assert_uint_eq(onion_client_normalize_announce_status(0, true, 1, 2), 2);
    ck_assert_uint_eq(onion_client_normalize_announce_status(1, false, 1, 2), 2);
    ck_assert_uint_eq(onion_client_normalize_announce_status(1, true, 0, 2), 2);
    ck_assert_uint_eq(onion_client_normalize_announce_status(1, true, 1, 1), 1);
}

static inline IP get_loopback(void)
{
    IP ip;
#if USE_IPV6
    ip.family = net_family_ipv6();
    ip.ip.v6 = get_ip6_loopback();
#else
    ip.family = net_family_ipv4();
    ip.ip.v4 = get_ip4_loopback();
#endif
    return ip;
}

typedef struct {
    bool     received;
    uint16_t length;
    uint8_t  packet[MAX_UDP_PACKET_SIZE];
} Recv3_State;

static int handle_recv_3(void *object, const IP_Port *source, const uint8_t *packet,
                         uint16_t length, void *userdata)
{
    Recv3_State *state = (Recv3_State *)object;
    ck_assert(length <= sizeof(state->packet));
    state->received = true;
    state->length   = length;
    memcpy(state->packet, packet, length);
    return 0;
}

/** Fill @p ann with a maximum-size IPv6 announce (IPv6 ip_port + IPv6 TCP relay). */
static void fill_max_public_announce(const Random *rng, GC_Public_Announce *ann,
                                     const uint8_t *chat_pk)
{
    memcpy(ann->chat_public_key, chat_pk, ENC_PUBLIC_KEY_SIZE);
    random_bytes(rng, ann->base_announce.peer_public_key, ENC_PUBLIC_KEY_SIZE);

    ann->base_announce.ip_port.ip.family = net_family_ipv6();
    random_bytes(rng, ann->base_announce.ip_port.ip.ip.v6.uint8,
                 sizeof(ann->base_announce.ip_port.ip.ip.v6.uint8));
    ann->base_announce.ip_port.port   = net_htons(33445);
    ann->base_announce.ip_port_is_set = true;

    ann->base_announce.tcp_relays_count = GCA_MAX_ANNOUNCED_TCP_RELAYS;
    random_bytes(rng, ann->base_announce.tcp_relays[0].public_key,
                 CRYPTO_PUBLIC_KEY_SIZE);
    ann->base_announce.tcp_relays[0].ip_port.ip.family = net_family_tcp_ipv6();
    random_bytes(rng, ann->base_announce.tcp_relays[0].ip_port.ip.ip.v6.uint8,
                 sizeof(ann->base_announce.tcp_relays[0].ip_port.ip.ip.v6.uint8));
    ann->base_announce.tcp_relays[0].ip_port.port = net_htons(33445);
}

/** Fill @p ann with a small IPv4-only announce (fits within GCA_ANNOUNCE_MAX_SIZE). */
static void fill_small_public_announce(const Random *rng, GC_Public_Announce *ann,
                                       const uint8_t *chat_pk)
{
    memcpy(ann->chat_public_key, chat_pk, ENC_PUBLIC_KEY_SIZE);
    random_bytes(rng, ann->base_announce.peer_public_key, ENC_PUBLIC_KEY_SIZE);

    ann->base_announce.ip_port.ip.family = net_family_ipv4();
    ann->base_announce.ip_port.ip.ip.v4  = get_ip4_loopback();
    ann->base_announce.ip_port.port       = net_htons(33445);
    ann->base_announce.ip_port_is_set     = true;
    ann->base_announce.tcp_relays_count   = 0;
}

static void send_gca_request_and_wait(
    const Memory *mem, const Random *rng, const uint8_t *dest_client_id,
    const uint8_t *client_public_key, const uint8_t *client_secret_key,
    const uint8_t *ping_id, const uint8_t *data_public_key, uint64_t sendback,
    const uint8_t *gc_data, uint16_t gc_data_len, Networking_Core *client_net,
    Networking_Core *server_net, Mono_Time *client_mono, Mono_Time *server_mono,
    const IP_Port *server_ip_port, Recv3_State *state)
{
    const uint16_t req_cap = ONION_ANNOUNCE_REQUEST_MAX_SIZE + ONION_RETURN_3;
    uint8_t *req_buf = (uint8_t *)malloc(req_cap);
    ck_assert(req_buf != nullptr);

    const int req_len = create_gca_announce_request(
                            mem, rng, req_buf, ONION_ANNOUNCE_REQUEST_MAX_SIZE,
                            dest_client_id, client_public_key, client_secret_key,
                            ping_id, client_public_key, data_public_key, sendback,
                            gc_data, gc_data_len);
    ck_assert_msg(req_len > 0, "Failed to create GCA announce request");

    memset(req_buf + req_len, 0, ONION_RETURN_3);
    const uint16_t total_len = (uint16_t)(req_len + ONION_RETURN_3);
    state->received = false;
    state->length = 0;
    ck_assert_msg(sendpacket(client_net, server_ip_port, req_buf, total_len) == total_len,
                  "Failed to send GCA announce request");
    free(req_buf);

    for (int i = 0; i < 200 && !state->received; ++i) {
        mono_time_update(server_mono);
        mono_time_update(client_mono);
        networking_poll(server_net, nullptr);
        networking_poll(client_net, nullptr);
        c_sleep(5);
    }

    ck_assert_msg(state->received, "No GCA announce response received within timeout");
}

static int decrypt_gca_response(const Memory *mem, const Recv3_State *state,
                                const uint8_t *server_public_key, const uint8_t *client_secret_key,
                                uint8_t *plain, uint16_t plain_capacity)
{
    const uint16_t onion_payload_offset = 1 + ONION_RETURN_3;
    ck_assert(state->length > onion_payload_offset);
    const uint8_t *response = state->packet + onion_payload_offset;
    const uint16_t response_length = state->length - onion_payload_offset;
    const uint16_t header_length = 1 + ONION_ANNOUNCE_SENDBACK_DATA_LENGTH + CRYPTO_NONCE_SIZE;
    ck_assert(response_length > header_length + CRYPTO_MAC_SIZE);
    ck_assert(response[0] == NET_PACKET_ANNOUNCE_RESPONSE);
    const uint16_t ciphertext_length = response_length - header_length;
    ck_assert(plain_capacity + CRYPTO_MAC_SIZE >= ciphertext_length);

    uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE];
    encrypt_precompute(server_public_key, client_secret_key, shared_key);
    const int plain_length = decrypt_data_symmetric(
                                 mem, shared_key,
                                 response + 1 + ONION_ANNOUNCE_SENDBACK_DATA_LENGTH,
                                 response + header_length, ciphertext_length, plain);
    crypto_memzero(shared_key, sizeof(shared_key));
    return plain_length;
}

typedef struct Test_Clock {
    uint64_t now_ms;
} Test_Clock;

static uint64_t test_clock_now(void *object)
{
    return ((const Test_Clock *)object)->now_ms;
}

static void set_chat_id(uint8_t *chat_id, uint32_t value)
{
    memset(chat_id, 0, CHAT_ID_SIZE);
    memcpy(chat_id, &value, sizeof(value));
    chat_id[CHAT_ID_SIZE - 1] = 0xa5;
}

static uint32_t count_live_chats(const GC_Announces_List *list)
{
    uint32_t count = 0;

    for (const GC_Announces *announces = list->root_announces;
            announces != nullptr; announces = announces->next_announce) {
        ++count;
    }

    return count;
}

static void test_gca_live_chat_cap(void)
{
    const Memory *mem = os_memory();
    const Random *rng = os_random();
    ck_assert(mem != nullptr);
    ck_assert(rng != nullptr);
    Test_Clock clock = {UINT64_C(1000000)};
    Mono_Time *mono_time = mono_time_new(mem, test_clock_now, &clock);
    ck_assert(mono_time != nullptr);
    GC_Announces_List *list = new_gca_list(mem);
    ck_assert(list != nullptr);
    GC_Public_Announce announce;

    for (uint32_t i = 0; i < GCA_MAX_LIVE_CHATS; ++i) {
        uint8_t chat_id[CHAT_ID_SIZE];
        set_chat_id(chat_id, i);
        fill_small_public_announce(rng, &announce, chat_id);
        ck_assert(gca_add_announce(mem, mono_time, list, &announce) != nullptr);
    }

    ck_assert(list->live_chats == GCA_MAX_LIVE_CHATS);
    ck_assert(count_live_chats(list) == GCA_MAX_LIVE_CHATS);

    const uint64_t half_timeout_ms = (GCA_ANNOUNCE_SAVE_TIMEOUT * UINT64_C(1000)) / 2;
    clock.now_ms += half_timeout_ms;
    mono_time_update(mono_time);

    uint8_t existing_chat_id[CHAT_ID_SIZE];
    set_chat_id(existing_chat_id, 0);
    fill_small_public_announce(rng, &announce, existing_chat_id);
    ck_assert(gca_add_announce(mem, mono_time, list, &announce) != nullptr);
    ck_assert(list->live_chats == GCA_MAX_LIVE_CHATS);
    ck_assert(count_live_chats(list) == GCA_MAX_LIVE_CHATS);

    uint8_t overflow_chat_id[CHAT_ID_SIZE];
    set_chat_id(overflow_chat_id, GCA_MAX_LIVE_CHATS);
    fill_small_public_announce(rng, &announce, overflow_chat_id);
    ck_assert(gca_add_announce(mem, mono_time, list, &announce) == nullptr);
    ck_assert(list->live_chats == GCA_MAX_LIVE_CHATS);

    uint8_t second_overflow_chat_id[CHAT_ID_SIZE];
    set_chat_id(second_overflow_chat_id, GCA_MAX_LIVE_CHATS + 1);
    fill_small_public_announce(rng, &announce, second_overflow_chat_id);
    ck_assert(gca_add_announce(mem, mono_time, list, &announce) == nullptr);
    ck_assert(list->live_chats == GCA_MAX_LIVE_CHATS);

    clock.now_ms += half_timeout_ms + UINT64_C(1000);
    mono_time_update(mono_time);
    fill_small_public_announce(rng, &announce, overflow_chat_id);
    ck_assert(gca_add_announce(mem, mono_time, list, &announce) != nullptr);
    ck_assert(list->live_chats == 2);
    ck_assert(count_live_chats(list) == 2);
    cleanup_gca(list, overflow_chat_id);
    ck_assert(list->live_chats == 1);
    cleanup_gca(list, existing_chat_id);
    ck_assert(list->live_chats == 0);

    kill_gca(list);
    mono_time_free(mem, mono_time);
}

static void test_gca_announce_response_size(void)
{
    const Memory  *mem = os_memory();
    ck_assert(mem != nullptr);
    const Random  *rng = os_random();
    ck_assert(rng != nullptr);
    const Network *ns  = os_network();
    ck_assert(ns != nullptr);

    /* ------------------------------------------------------------------ */
    /* Server node: Onion_Announce with GCA callback registered.          */
    /* ------------------------------------------------------------------ */
    uint32_t srv_idx = 1;
    uint32_t cli_idx = 2;

    Logger *srv_log = logger_new(mem);
    ck_assert(srv_log != nullptr);
    logger_callback_log(srv_log, print_debug_logger, nullptr, &srv_idx);

    Mono_Time *srv_mono = mono_time_new(mem, nullptr, nullptr);
    ck_assert(srv_mono != nullptr);
    mono_time_update(srv_mono);

    IP ip = get_loopback();

    Networking_Core *srv_net = new_networking_ex(
                                   srv_log, mem, ns, &ip, 36700,
                                   36700 + (TOX_PORTRANGE_TO - TOX_PORTRANGE_FROM), nullptr);
    ck_assert(srv_net != nullptr);

    DHT *srv_dht = new_dht(srv_log, mem, rng, ns, srv_mono, srv_net, true, false);
    ck_assert(srv_dht != nullptr);

    Onion *srv_onion = new_onion(srv_log, mem, srv_mono, rng, srv_dht, srv_net);
    ck_assert(srv_onion != nullptr);

    Onion_Announce *srv_onion_a = new_onion_announce(
                                      srv_log, mem, rng, srv_mono, srv_dht, srv_net);
    ck_assert(srv_onion_a != nullptr);

    GC_Announces_List *gca_list = new_gca_list(mem);
    ck_assert(gca_list != nullptr);

    gca_onion_init(gca_list, srv_onion_a);

    /* Pre-fill the GCA list with GCA_MAX_SENT_ANNOUNCES full-size IPv6
     * announces so the server returns a maximally-populated response. */
    uint8_t chat_pk[ENC_PUBLIC_KEY_SIZE];
    random_bytes(rng, chat_pk, sizeof(chat_pk));

    for (uint32_t i = 0; i < GCA_MAX_SENT_ANNOUNCES; ++i) {
        GC_Public_Announce ann;
        fill_max_public_announce(rng, &ann, chat_pk);
        mono_time_update(srv_mono);
        GC_Peer_Announce *peer_ann = gca_add_announce(mem, srv_mono, gca_list, &ann);
        ck_assert_msg(peer_ann != nullptr, "Failed to add pre-filled GCA announce %u", i);
    }

    /* Inject MAX_SENT_NODES fake LAN entries so get_close_nodes() returns
     * a full node list alongside the GCA announces. */
    for (uint32_t i = 0; i < MAX_SENT_NODES; ++i) {
        uint8_t fake_pk[CRYPTO_PUBLIC_KEY_SIZE];
        random_bytes(rng, fake_pk, sizeof(fake_pk));
        IP_Port fake_ipp;
        fake_ipp.ip.family         = net_family_ipv4();
        fake_ipp.ip.ip.v4.uint8[0] = 10;
        fake_ipp.ip.ip.v4.uint8[1] = 0;
        fake_ipp.ip.ip.v4.uint8[2] = 0;
        fake_ipp.ip.ip.v4.uint8[3] = (uint8_t)(i + 1);
        fake_ipp.port              = net_htons(33445 + i);
        addto_lists(srv_dht, &fake_ipp, fake_pk);
    }

    /* ------------------------------------------------------------------ */
    /* Client node: raw Networking_Core with a RECV_3 capture handler.    */
    /* ------------------------------------------------------------------ */
    Logger *cli_log = logger_new(mem);
    ck_assert(cli_log != nullptr);
    logger_callback_log(cli_log, print_debug_logger, nullptr, &cli_idx);

    Mono_Time *cli_mono = mono_time_new(mem, nullptr, nullptr);
    ck_assert(cli_mono != nullptr);

    Networking_Core *cli_net = new_networking_ex(
                                   cli_log, mem, ns, &ip, 36701,
                                   36701 + (TOX_PORTRANGE_TO - TOX_PORTRANGE_FROM), nullptr);
    ck_assert(cli_net != nullptr);

    Recv3_State state = {false, 0, {0}};
    networking_registerhandler(cli_net, NET_PACKET_ONION_RECV_3,
                               handle_recv_3, &state);

    /* ------------------------------------------------------------------ */
    /* Build a GCA announce request and send it directly to the server.   */
    /* ------------------------------------------------------------------ */

    /* Use a small IPv4-only public announce as the gc_data payload so that
     * gc_data_length fits within the GCA_ANNOUNCE_MAX_SIZE limit. */
    GC_Public_Announce my_ann;
    fill_small_public_announce(rng, &my_ann, chat_pk);

    uint8_t gc_data[GCA_PUBLIC_ANNOUNCE_MAX_SIZE];
    const int gc_data_len = gca_pack_public_announce(
                                srv_log, gc_data, sizeof(gc_data), &my_ann);
    ck_assert_msg(gc_data_len > 0, "Failed to pack public announce");
    ck_assert_msg((uint16_t)gc_data_len <= GCA_ANNOUNCE_MAX_SIZE,
                  "gc_data_len %d exceeds GCA_ANNOUNCE_MAX_SIZE", gc_data_len);

    uint8_t cli_pk[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t cli_sk[CRYPTO_SECRET_KEY_SIZE];
    crypto_new_keypair(rng, cli_pk, cli_sk);

    uint8_t data_pk[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t data_sk[CRYPTO_SECRET_KEY_SIZE];
    crypto_new_keypair(rng, data_pk, data_sk);

    const uint8_t zeroes[ONION_PING_ID_SIZE] = {0};
    const uint64_t sendback = 0x0102030405060708ULL;

    const IP_Port srv_ipp = {ip, net_port(srv_net)};
    const uint64_t index_before_invalid = gca_list->root_announces->index;
    const GC_Announces state_before_invalid = *gca_list->root_announces;
    send_gca_request_and_wait(
        mem, rng, dht_get_self_public_key(srv_dht), cli_pk, cli_sk, zeroes, data_pk,
        sendback, gc_data, (uint16_t)gc_data_len, cli_net, srv_net, cli_mono, srv_mono,
        &srv_ipp, &state);
    ck_assert(gca_list->live_chats == 1);
    ck_assert(gca_list->root_announces->index == index_before_invalid);
    ck_assert(memcmp(gca_list->root_announces, &state_before_invalid,
                     sizeof(state_before_invalid)) == 0);

    /* The ONION_RECV_3 packet layout:
     *   [1 byte type] [ONION_RETURN_3 bytes return path] [payload bytes] */
    ck_assert_msg(state.length > (uint16_t)(1 + ONION_RETURN_3),
                  "RECV_3 packet too short to contain any payload: %u", state.length);

    const uint16_t resp_len = state.length - (uint16_t)(1 + ONION_RETURN_3);

    ck_assert_msg(resp_len >= ONION_ANNOUNCE_RESPONSE_MIN_SIZE,
                  "announce response too small: %u (min %u)",
                  resp_len, (unsigned int)ONION_ANNOUNCE_RESPONSE_MIN_SIZE);

    ck_assert_msg(resp_len <= GCA_ANNOUNCE_RESPONSE_MAX_SIZE,
                  "announce response too large: %u (max %u)",
                  resp_len, (unsigned int)GCA_ANNOUNCE_RESPONSE_MAX_SIZE);

    printf("GCA announce response payload: %u bytes "
           "(min: %u, max: %u)\n",
           resp_len,
           (unsigned int)ONION_ANNOUNCE_RESPONSE_MIN_SIZE,
           (unsigned int)GCA_ANNOUNCE_RESPONSE_MAX_SIZE);

    uint8_t invalid_plain[MAX_UDP_PACKET_SIZE];
    const int invalid_plain_len = decrypt_gca_response(
                                      mem, &state, dht_get_self_public_key(srv_dht), cli_sk,
                                      invalid_plain, sizeof(invalid_plain));
    ck_assert(invalid_plain_len > 1 + ONION_PING_ID_SIZE + 1);
    ck_assert(invalid_plain[0] == 0);
    uint8_t valid_ping_id[ONION_PING_ID_SIZE];
    memcpy(valid_ping_id, invalid_plain + 1, sizeof(valid_ping_id));

    send_gca_request_and_wait(
        mem, rng, dht_get_self_public_key(srv_dht), cli_pk, cli_sk, valid_ping_id, data_pk,
        sendback, gc_data, (uint16_t)gc_data_len, cli_net, srv_net, cli_mono, srv_mono,
        &srv_ipp, &state);
    ck_assert(gca_list->live_chats == 1);
    ck_assert(gca_list->root_announces->index == index_before_invalid + 1);

    uint8_t valid_plain[MAX_UDP_PACKET_SIZE];
    const int valid_plain_len = decrypt_gca_response(
                                    mem, &state, dht_get_self_public_key(srv_dht), cli_sk,
                                    valid_plain, sizeof(valid_plain));
    ck_assert(valid_plain_len == invalid_plain_len);
    ck_assert(valid_plain[0] == 2);
    const uint16_t lookup_offset = 1 + ONION_PING_ID_SIZE + 1;
    ck_assert(memcmp(valid_plain + lookup_offset, invalid_plain + lookup_offset,
                     valid_plain_len - lookup_offset) == 0);

    uint8_t new_chat_id[CHAT_ID_SIZE];
    random_bytes(rng, new_chat_id, sizeof(new_chat_id));
    GC_Public_Announce invalid_new_chat;
    fill_small_public_announce(rng, &invalid_new_chat, new_chat_id);
    uint8_t invalid_new_data[GCA_PUBLIC_ANNOUNCE_MAX_SIZE];
    const int invalid_new_data_len = gca_pack_public_announce(
                                         srv_log, invalid_new_data, sizeof(invalid_new_data), &invalid_new_chat);
    ck_assert(invalid_new_data_len > 0);
    send_gca_request_and_wait(
        mem, rng, dht_get_self_public_key(srv_dht), cli_pk, cli_sk, zeroes, data_pk,
        sendback, invalid_new_data, (uint16_t)invalid_new_data_len,
        cli_net, srv_net, cli_mono, srv_mono, &srv_ipp, &state);
    ck_assert(gca_list->live_chats == 1);
    GC_Announce no_announces[GCA_MAX_SENT_ANNOUNCES];
    ck_assert(gca_get_announces(gca_list, no_announces, GCA_MAX_SENT_ANNOUNCES,
                                new_chat_id, invalid_new_chat.base_announce.peer_public_key) == 0);

    /* ------------------------------------------------------------------ */
    /* Cleanup (reverse order of creation).                               */
    /* ------------------------------------------------------------------ */
    networking_registerhandler(cli_net, NET_PACKET_ONION_RECV_3, nullptr, nullptr);
    kill_networking(cli_net);
    mono_time_free(mem, cli_mono);
    logger_kill(cli_log);

    kill_gca(gca_list);
    kill_onion_announce(srv_onion_a);
    kill_onion(srv_onion);
    kill_dht(srv_dht);
    kill_networking(srv_net);
    mono_time_free(mem, srv_mono);
    logger_kill(srv_log);
}

static void basic_gca_announce_tests(void)
{
    test_client_group_retry_contract();
    test_gca_live_chat_cap();
    test_gca_announce_response_size();
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    basic_gca_announce_tests();
    return 0;
}
