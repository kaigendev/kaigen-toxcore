/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2026 The TokTok team.
 * Copyright © 2014 Tox project.
 */

#ifndef C_TOXCORE_TOXCORE_TCP_CLIENT_INTERNAL_H
#define C_TOXCORE_TOXCORE_TCP_CLIENT_INTERNAL_H

#include <assert.h>

#include "TCP_client.h"
#include "TCP_common.h"
#include "ccompat.h"

typedef struct TCP_Client_Conn {
    // TODO(iphydf): Add an enum for this.
    uint8_t status; /* 0 if not used, 1 if other is offline, 2 if other is online. */
    uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE];
    uint32_t number;
} TCP_Client_Conn;

struct TCP_Client_Connection {
    TCP_Connection con;
    TCP_Client_Status status;
    uint8_t self_public_key[CRYPTO_PUBLIC_KEY_SIZE]; /* our public key */
    uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE]; /* public key of the server */
    IP_Port ip_port; /* The ip and port of the server */
    TCP_Proxy_Info proxy_info;
    uint8_t recv_nonce[CRYPTO_NONCE_SIZE]; /* Nonce of received packets. */
    uint16_t next_packet_length;

    uint8_t temp_secret_key[CRYPTO_SECRET_KEY_SIZE];

    uint64_t kill_at;

    uint64_t last_pinged;
    uint64_t ping_id;

    uint64_t ping_response_id;
    uint64_t ping_request_id;

    TCP_Client_Conn connections[NUM_CLIENT_CONNECTIONS];
    tcp_routing_response_cb *_Nullable response_callback;
    void *_Nullable response_callback_object;
    tcp_routing_status_cb *_Nullable status_callback;
    void *_Nullable status_callback_object;
    tcp_routing_data_cb *_Nullable data_callback;
    void *_Nullable data_callback_object;
    tcp_oob_data_cb *_Nullable oob_data_callback;
    void *_Nullable oob_data_callback_object;

    tcp_onion_response_cb *_Nullable onion_callback;
    void *_Nullable onion_callback_object;

    forwarded_response_cb *_Nullable forwarded_response_callback;
    void *_Nullable forwarded_response_callback_object;

    /* Can be used by user. */
    void *_Nullable custom_object;
    uint32_t custom_uint;
};

/** Attach one owner aggregate to a newly created, still-empty client queue. */
static inline void tcp_client_connection_attach_priority_queue_account(
    TCP_Client_Connection *_Nonnull con, TCP_Priority_Queue_Account *_Nonnull account)
{
    assert(con != nullptr);
    assert(account != nullptr);
    assert(con->con.priority_queue_account == nullptr);
    assert(con->con.priority_queue_start == nullptr);
    assert(con->con.priority_queue_end == nullptr);
    assert(con->con.priority_queue_items == 0);
    assert(con->con.priority_queue_bytes == 0);
    con->con.priority_queue_account = account;
}

#endif /* C_TOXCORE_TOXCORE_TCP_CLIENT_INTERNAL_H */
