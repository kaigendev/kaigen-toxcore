/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2026 The TokTok team.
 * Copyright © 2013 Tox project.
 */

#ifndef C_TOXCORE_TOXCORE_NET_CRYPTO_BUFFER_H
#define C_TOXCORE_TOXCORE_NET_CRYPTO_BUFFER_H

#include <assert.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "attributes.h"
#include "ccompat.h"
#include "mem.h"
#include "net_crypto.h"

#define CRYPTO_RECV_BUFFER_MAX_BYTES ((size_t)8U * 1024U * 1024U)

typedef struct Buffered_Packet {
    uint16_t length;
    uint8_t data[];
} Buffered_Packet;

typedef struct Receive_Packets_Array {
    Buffered_Packet *_Nullable buffer[CRYPTO_PACKET_BUFFER_SIZE];
    uint32_t buffer_start;
    uint32_t buffer_end; /* packet numbers in array: `{buffer_start, buffer_end)` */
    size_t retained_bytes;
} Receive_Packets_Array;

typedef enum Receive_Packet_Add_Result {
    RECEIVE_PACKET_ADD_OK = 0,
    RECEIVE_PACKET_ADD_INVALID = -1,
    RECEIVE_PACKET_ADD_ALLOCATION_FAILED = -2,
    RECEIVE_PACKET_ADD_BYTE_LIMIT = -3,
} Receive_Packet_Add_Result;

static inline size_t receive_packet_allocation_size(uint16_t length)
{
    const size_t header_size = offsetof(Buffered_Packet, data);

    if ((size_t)length > SIZE_MAX - header_size) {
        return 0;
    }

    return header_size + length;
}

static inline uint32_t receive_packets_array_size(const Receive_Packets_Array *_Nonnull array)
{
    return array->buffer_end - array->buffer_start;
}

static inline bool receive_packets_array_accept_in_order(
    Receive_Packets_Array *_Nonnull array, uint32_t number)
{
    if (number != array->buffer_start
            || array->buffer[number % CRYPTO_PACKET_BUFFER_SIZE] != nullptr) {
        return false;
    }

    if (array->buffer_start == array->buffer_end) {
        array->buffer_end = number + 1;
    }

    ++array->buffer_start;
    return true;
}

static inline Receive_Packet_Add_Result receive_packets_array_add(
    const Memory *_Nonnull mem, Receive_Packets_Array *_Nonnull array, uint32_t number,
    const uint8_t *_Nonnull data, uint16_t length)
{
    if (length == 0 || length > MAX_CRYPTO_DATA_SIZE
            || number - array->buffer_start >= CRYPTO_PACKET_BUFFER_SIZE) {
        return RECEIVE_PACKET_ADD_INVALID;
    }

    const uint32_t num = number % CRYPTO_PACKET_BUFFER_SIZE;

    if (array->buffer[num] != nullptr) {
        return RECEIVE_PACKET_ADD_INVALID;
    }

    const size_t allocation_size = receive_packet_allocation_size(length);

    if (allocation_size == 0 || allocation_size > UINT32_MAX) {
        return RECEIVE_PACKET_ADD_INVALID;
    }

    if (allocation_size > CRYPTO_RECV_BUFFER_MAX_BYTES
            || array->retained_bytes > CRYPTO_RECV_BUFFER_MAX_BYTES - allocation_size) {
        return RECEIVE_PACKET_ADD_BYTE_LIMIT;
    }

    Buffered_Packet *new_packet = (Buffered_Packet *)mem_alloc(mem, (uint32_t)allocation_size);

    if (new_packet == nullptr) {
        return RECEIVE_PACKET_ADD_ALLOCATION_FAILED;
    }

    new_packet->length = length;
    memcpy(new_packet->data, data, length);
    array->buffer[num] = new_packet;
    array->retained_bytes += allocation_size;

    if (number - array->buffer_start >= receive_packets_array_size(array)) {
        array->buffer_end = number + 1;
    }

    return RECEIVE_PACKET_ADD_OK;
}

static inline int64_t receive_packets_array_pop(
    const Memory *_Nonnull mem, Receive_Packets_Array *_Nonnull array,
    uint8_t *_Nonnull data, uint16_t *_Nonnull length)
{
    if (array->buffer_end == array->buffer_start) {
        return -1;
    }

    const uint32_t num = array->buffer_start % CRYPTO_PACKET_BUFFER_SIZE;
    Buffered_Packet *packet = array->buffer[num];

    if (packet == nullptr) {
        return -1;
    }

    *length = packet->length;
    memcpy(data, packet->data, packet->length);

    const size_t allocation_size = receive_packet_allocation_size(packet->length);

    if (allocation_size == 0 || array->retained_bytes < allocation_size) {
        assert(false);
        return -1;
    }

    const uint32_t id = array->buffer_start;
    ++array->buffer_start;
    array->buffer[num] = nullptr;
    array->retained_bytes -= allocation_size;
    mem_delete(mem, packet);
    return id;
}

static inline int receive_packets_array_clear(
    const Memory *_Nonnull mem, Receive_Packets_Array *_Nonnull array)
{
    uint32_t i;
    bool accounting_valid = true;

    for (i = array->buffer_start; i != array->buffer_end; ++i) {
        const uint32_t num = i % CRYPTO_PACKET_BUFFER_SIZE;
        Buffered_Packet *packet = array->buffer[num];

        if (packet != nullptr) {
            const size_t allocation_size = receive_packet_allocation_size(packet->length);

            if (allocation_size == 0 || array->retained_bytes < allocation_size) {
                assert(false);
                accounting_valid = false;
                array->retained_bytes = 0;
            } else {
                array->retained_bytes -= allocation_size;
            }

            mem_delete(mem, packet);
            array->buffer[num] = nullptr;
        }
    }

    array->buffer_start = i;

    if (array->retained_bytes != 0) {
        assert(false);
        accounting_valid = false;
        array->retained_bytes = 0;
    }

    if (!accounting_valid) {
        return -1;
    }

    return 0;
}

static inline int receive_packets_array_set_end(
    Receive_Packets_Array *_Nonnull array, uint32_t number)
{
    if (number - array->buffer_start > CRYPTO_PACKET_BUFFER_SIZE) {
        return -1;
    }

    if (number - array->buffer_end > CRYPTO_PACKET_BUFFER_SIZE) {
        return -1;
    }

    array->buffer_end = number;
    return 0;
}

static inline int receive_packets_array_generate_request(
    uint8_t *_Nonnull data, uint16_t length, const Receive_Packets_Array *_Nonnull array)
{
    if (length == 0) {
        return -1;
    }

    data[0] = PACKET_ID_REQUEST;

    uint16_t cur_len = 1;

    if (array->buffer_start == array->buffer_end) {
        return cur_len;
    }

    if (length <= cur_len) {
        return cur_len;
    }

    uint32_t n = 1;

    for (uint32_t i = array->buffer_start; i != array->buffer_end; ++i) {
        const uint32_t num = i % CRYPTO_PACKET_BUFFER_SIZE;

        if (array->buffer[num] == nullptr) {
            data[cur_len] = n;
            n = 0;
            ++cur_len;

            if (length <= cur_len) {
                return cur_len;
            }
        } else if (n == 255) {
            data[cur_len] = 0;
            n = 0;
            ++cur_len;

            if (length <= cur_len) {
                return cur_len;
            }
        }

        ++n;
    }

    return cur_len;
}

#ifdef C_TOXCORE_NET_CRYPTO_BUFFER_TESTING
int nc_testonly_handle_lossless_packet(
    Net_Crypto *_Nonnull c, int crypt_connection_id, uint32_t packet_number,
    const uint8_t *_Nonnull data, uint16_t length, void *_Nullable userdata);

size_t nc_testonly_receive_retained_bytes(
    const Net_Crypto *_Nonnull c, int crypt_connection_id);
#endif /* C_TOXCORE_NET_CRYPTO_BUFFER_TESTING */

#endif /* C_TOXCORE_TOXCORE_NET_CRYPTO_BUFFER_H */
