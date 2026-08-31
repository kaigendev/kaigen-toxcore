#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../testing/misc_tools.h"
#include "../toxcore/DHT.h"
#include "../toxcore/crypto_core.h"
#include "../toxcore/logger.h"
#include "../toxcore/mem.h"
#include "../toxcore/mono_time.h"
#include "../toxcore/net_crypto_buffer.h"
#include "../toxcore/net_profile.h"
#include "../toxcore/network.h"
#include "../toxcore/os_memory.h"
#include "../toxcore/os_network.h"
#include "../toxcore/os_random.h"
#include "auto_test_support.h"
#include "check_compat.h"

typedef union Allocation_Header {
    size_t size;
    uint64_t alignment;
} Allocation_Header;

typedef struct Tracking_Memory {
    Memory mem;
    uint32_t allocation_count;
    uint32_t fail_on_allocation;
    uint32_t live_allocations;
    size_t live_bytes;
    uint32_t last_size;
} Tracking_Memory;

static void *tracking_malloc(void *object, uint32_t size)
{
    Tracking_Memory *state = (Tracking_Memory *)object;
    ++state->allocation_count;

    if (state->allocation_count == state->fail_on_allocation) {
        return nullptr;
    }

    Allocation_Header *allocation = (Allocation_Header *)malloc(sizeof(Allocation_Header) + size);

    if (allocation == nullptr) {
        return nullptr;
    }

    allocation->size = size;
    ++state->live_allocations;
    state->live_bytes += size;
    state->last_size = size;
    return allocation + 1;
}

static void *tracking_realloc(void *object, void *ptr, uint32_t size)
{
    Tracking_Memory *state = (Tracking_Memory *)object;
    ++state->allocation_count;

    if (state->allocation_count == state->fail_on_allocation) {
        return nullptr;
    }

    if (ptr == nullptr) {
        return tracking_malloc(object, size);
    }

    Allocation_Header *old_allocation = (Allocation_Header *)ptr - 1;
    const size_t old_size = old_allocation->size;
    Allocation_Header *new_allocation = (Allocation_Header *)realloc(
                                            old_allocation, sizeof(Allocation_Header) + size);

    if (new_allocation == nullptr) {
        return nullptr;
    }

    new_allocation->size = size;
    state->live_bytes -= old_size;
    state->live_bytes += size;
    state->last_size = size;
    return new_allocation + 1;
}

static void tracking_dealloc(void *object, void *ptr)
{
    Tracking_Memory *state = (Tracking_Memory *)object;

    if (ptr != nullptr) {
        Allocation_Header *allocation = (Allocation_Header *)ptr - 1;
        ck_assert(state->live_allocations > 0);
        ck_assert(state->live_bytes >= allocation->size);
        --state->live_allocations;
        state->live_bytes -= allocation->size;
        free(allocation);
    }
}

static const Memory_Funcs tracking_memory_funcs = {
    tracking_malloc,
    tracking_realloc,
    tracking_dealloc,
};

static void tracking_memory_init(Tracking_Memory *state)
{
    memset(state, 0, sizeof(*state));
    state->mem.funcs = &tracking_memory_funcs;
    state->mem.user_data = state;
}

static void fill_packet(uint8_t *data, uint16_t length, uint8_t seed)
{
    for (uint16_t i = 0; i < length; ++i) {
        data[i] = (uint8_t)(seed + i);
    }
}

static void test_proportional_lengths_holes_duplicates_and_order(void)
{
    Tracking_Memory memory;
    tracking_memory_init(&memory);
    Receive_Packets_Array array = {0};
    uint8_t maximum[MAX_CRYPTO_DATA_SIZE];
    uint8_t output[MAX_CRYPTO_DATA_SIZE];
    uint16_t output_length = 0;
    fill_packet(maximum, sizeof(maximum), 11);

    ck_assert(CRYPTO_PACKET_BUFFER_SIZE == 32768);
    ck_assert(receive_packet_allocation_size(1) == offsetof(Buffered_Packet, data) + 1);
    ck_assert(receive_packet_allocation_size(MAX_CRYPTO_DATA_SIZE)
              == offsetof(Buffered_Packet, data) + MAX_CRYPTO_DATA_SIZE);

    ck_assert(receive_packets_array_add(
                  &memory.mem, &array, 2, maximum, sizeof(maximum)) == RECEIVE_PACKET_ADD_OK);
    ck_assert(memory.last_size == receive_packet_allocation_size(MAX_CRYPTO_DATA_SIZE));
    ck_assert(array.buffer_end == 3);
    ck_assert(array.retained_bytes == memory.last_size);

    const uint32_t allocation_count = memory.allocation_count;
    ck_assert(receive_packets_array_add(
                  &memory.mem, &array, 2, maximum, sizeof(maximum)) == RECEIVE_PACKET_ADD_INVALID);
    ck_assert(memory.allocation_count == allocation_count);
    ck_assert(receive_packets_array_pop(&memory.mem, &array, output, &output_length) == -1);

    const uint8_t minimum[] = {PACKET_ID_RANGE_LOSSLESS_START};
    ck_assert(receive_packets_array_add(
                  &memory.mem, &array, 0, minimum, sizeof(minimum)) == RECEIVE_PACKET_ADD_OK);
    ck_assert(memory.last_size == receive_packet_allocation_size(1));
    ck_assert(receive_packets_array_pop(&memory.mem, &array, output, &output_length) == 0);
    ck_assert(output_length == sizeof(minimum));
    ck_assert(memcmp(output, minimum, sizeof(minimum)) == 0);
    ck_assert(receive_packets_array_pop(&memory.mem, &array, output, &output_length) == -1);

    const uint8_t middle[] = {PACKET_ID_RANGE_LOSSLESS_START + 1, 4, 5, 6};
    ck_assert(receive_packets_array_add(
                  &memory.mem, &array, 1, middle, sizeof(middle)) == RECEIVE_PACKET_ADD_OK);
    ck_assert(receive_packets_array_pop(&memory.mem, &array, output, &output_length) == 1);
    ck_assert(output_length == sizeof(middle));
    ck_assert(memcmp(output, middle, sizeof(middle)) == 0);
    ck_assert(receive_packets_array_pop(&memory.mem, &array, output, &output_length) == 2);
    ck_assert(output_length == sizeof(maximum));
    ck_assert(memcmp(output, maximum, sizeof(maximum)) == 0);
    ck_assert(array.retained_bytes == 0);
    ck_assert(memory.live_allocations == 0);

    ck_assert(receive_packets_array_add(
                  &memory.mem, &array, array.buffer_start + CRYPTO_PACKET_BUFFER_SIZE,
                  minimum, sizeof(minimum)) == RECEIVE_PACKET_ADD_INVALID);
    ck_assert(memory.live_allocations == 0);
}

static void test_all_legal_payload_lengths(void)
{
    Tracking_Memory memory;
    tracking_memory_init(&memory);
    Receive_Packets_Array array = {0};
    uint8_t packet[MAX_CRYPTO_DATA_SIZE];
    uint8_t output[MAX_CRYPTO_DATA_SIZE];
    uint16_t output_length = 0;

    ck_assert(MAX_CRYPTO_DATA_SIZE <= UINT16_MAX);
    for (uint32_t length = 1; length <= MAX_CRYPTO_DATA_SIZE; ++length) {
        const uint16_t packet_length = (uint16_t)length;
        fill_packet(packet, packet_length, (uint8_t)length);
        packet[0] = PACKET_ID_RANGE_LOSSLESS_START;
        const uint32_t packet_number = array.buffer_start;

        ck_assert(receive_packets_array_add(
                      &memory.mem, &array, packet_number,
                      packet, packet_length) == RECEIVE_PACKET_ADD_OK);
        ck_assert(memory.last_size == receive_packet_allocation_size(packet_length));
        ck_assert(array.retained_bytes == receive_packet_allocation_size(packet_length));
        ck_assert(receive_packets_array_pop(
                      &memory.mem, &array, output, &output_length) == packet_number);
        ck_assert(output_length == packet_length);
        ck_assert(memcmp(output, packet, packet_length) == 0);
        ck_assert(array.retained_bytes == 0);
        ck_assert(memory.live_allocations == 0);
    }
}

static void test_wraparound(void)
{
    Tracking_Memory memory;
    tracking_memory_init(&memory);
    Receive_Packets_Array array = {0};
    array.buffer_start = UINT32_MAX - 1;
    array.buffer_end = UINT32_MAX - 1;
    const uint8_t packet[] = {PACKET_ID_RANGE_LOSSLESS_START, 9};
    uint8_t output[MAX_CRYPTO_DATA_SIZE];
    uint16_t output_length;
    const uint32_t numbers[] = {UINT32_MAX - 1, UINT32_MAX, 0};

    for (size_t i = 0; i < sizeof(numbers) / sizeof(numbers[0]); ++i) {
        ck_assert(receive_packets_array_add(
                      &memory.mem, &array, numbers[i], packet, sizeof(packet)) == RECEIVE_PACKET_ADD_OK);
    }

    ck_assert(receive_packets_array_size(&array) == 3);

    for (size_t i = 0; i < sizeof(numbers) / sizeof(numbers[0]); ++i) {
        const int64_t number = receive_packets_array_pop(&memory.mem, &array, output, &output_length);
        ck_assert((uint32_t)number == numbers[i]);
        ck_assert(output_length == sizeof(packet));
        ck_assert(memcmp(output, packet, sizeof(packet)) == 0);
    }

    ck_assert(array.retained_bytes == 0);
    ck_assert(memory.live_allocations == 0);
}

static void test_request_bytes_and_callback_cleanup(void)
{
    Tracking_Memory memory;
    tracking_memory_init(&memory);
    Receive_Packets_Array array = {0};
    const uint8_t packet[] = {PACKET_ID_RANGE_LOSSLESS_START, 7, 8};
    const uint32_t present[] = {0, 2, 5};

    ck_assert(receive_packets_array_set_end(&array, 6) == 0);

    for (size_t i = 0; i < sizeof(present) / sizeof(present[0]); ++i) {
        ck_assert(receive_packets_array_add(
                      &memory.mem, &array, present[i], packet, sizeof(packet)) == RECEIVE_PACKET_ADD_OK);
    }

    uint8_t request[16] = {0};
    const uint8_t expected[] = {PACKET_ID_REQUEST, 2, 2, 1};
    const int request_length = receive_packets_array_generate_request(request, sizeof(request), &array);
    ck_assert(request_length == sizeof(expected));
    ck_assert(memcmp(request, expected, sizeof(expected)) == 0);

    uint8_t delivered[MAX_CRYPTO_DATA_SIZE];
    uint16_t delivered_length;
    ck_assert(receive_packets_array_pop(&memory.mem, &array, delivered, &delivered_length) == 0);
    ck_assert(delivered_length == sizeof(packet));
    ck_assert(memcmp(delivered, packet, sizeof(packet)) == 0);

    /* Simulate a connection-data callback killing its connection. The popped
     * payload must already be detached, and cleanup must free every remainder. */
    ck_assert(receive_packets_array_clear(&memory.mem, &array) == 0);
    ck_assert(memory.live_allocations == 0);
    ck_assert(memcmp(delivered, packet, sizeof(packet)) == 0);
}

static void test_allocation_failure(void)
{
    Tracking_Memory memory;
    tracking_memory_init(&memory);
    memory.fail_on_allocation = 1;
    Receive_Packets_Array array = {0};
    const uint8_t packet[] = {PACKET_ID_RANGE_LOSSLESS_START, 1};

    ck_assert(receive_packets_array_add(
                  &memory.mem, &array, 0, packet, sizeof(packet)) == RECEIVE_PACKET_ADD_ALLOCATION_FAILED);
    ck_assert(array.buffer_start == 0);
    ck_assert(array.buffer_end == 0);
    ck_assert(array.retained_bytes == 0);
    ck_assert(memory.live_allocations == 0);
}

static void test_exact_cap_gap_recovery_isolation_and_reconnect(void)
{
    Tracking_Memory memory;
    tracking_memory_init(&memory);
    Receive_Packets_Array offender = {0};
    Receive_Packets_Array other = {0};
    uint8_t maximum[MAX_CRYPTO_DATA_SIZE];
    fill_packet(maximum, sizeof(maximum), 29);
    const uint8_t small[] = {PACKET_ID_RANGE_LOSSLESS_START};

    ck_assert(receive_packets_array_add(
                  &memory.mem, &other, 0, small, sizeof(small)) == RECEIVE_PACKET_ADD_OK);

    const size_t maximum_size = receive_packet_allocation_size(MAX_CRYPTO_DATA_SIZE);
    const uint32_t maximum_count = 6100;
    const size_t repeated_bytes = (size_t)maximum_count * maximum_size;
    ck_assert(repeated_bytes < CRYPTO_RECV_BUFFER_MAX_BYTES);
    const size_t final_size = CRYPTO_RECV_BUFFER_MAX_BYTES - repeated_bytes;
    ck_assert(final_size > offsetof(Buffered_Packet, data));
    const uint16_t final_length = (uint16_t)(final_size - offsetof(Buffered_Packet, data));
    ck_assert(final_length == 1106);

    ck_assert(receive_packets_array_set_end(&offender, maximum_count + 2) == 0);

    for (uint32_t number = 1; number <= maximum_count; ++number) {
        ck_assert(receive_packets_array_add(
                      &memory.mem, &offender, number, maximum, sizeof(maximum)) == RECEIVE_PACKET_ADD_OK);
    }

    ck_assert(receive_packets_array_add(
                  &memory.mem, &offender, maximum_count + 1,
                  maximum, final_length) == RECEIVE_PACKET_ADD_OK);
    ck_assert(offender.retained_bytes == CRYPTO_RECV_BUFFER_MAX_BYTES);

    const uint32_t allocations_at_cap = memory.allocation_count;
    ck_assert(receive_packets_array_add(
                  &memory.mem, &offender, maximum_count + 2,
                  small, sizeof(small)) == RECEIVE_PACKET_ADD_BYTE_LIMIT);
    ck_assert(memory.allocation_count == allocations_at_cap);
    ck_assert(offender.retained_bytes == CRYPTO_RECV_BUFFER_MAX_BYTES);
    ck_assert(other.retained_bytes == receive_packet_allocation_size(sizeof(small)));

    /* An honest gap-filler at buffer_start is delivered without retaining a
     * new allocation, so a queue exactly at the cap can still make progress. */
    ck_assert(receive_packets_array_accept_in_order(&offender, 0));
    ck_assert(memory.allocation_count == allocations_at_cap);

    uint8_t output[MAX_CRYPTO_DATA_SIZE];
    uint16_t output_length;

    for (uint32_t number = 1; number <= maximum_count + 1; ++number) {
        ck_assert((uint32_t)receive_packets_array_pop(
                      &memory.mem, &offender, output, &output_length) == number);
    }

    ck_assert(offender.retained_bytes == 0);
    ck_assert(receive_packets_array_pop(&memory.mem, &other, output, &output_length) == 0);
    ck_assert(output_length == sizeof(small));
    ck_assert(memcmp(output, small, sizeof(small)) == 0);
    ck_assert(memory.live_allocations == 0);

    ck_assert(receive_packets_array_add(
                  &memory.mem, &offender, offender.buffer_start,
                  small, sizeof(small)) == RECEIVE_PACKET_ADD_OK);
    ck_assert(receive_packets_array_clear(&memory.mem, &offender) == 0);
    ck_assert(offender.retained_bytes == 0);
    ck_assert(memory.live_allocations == 0);
}

#define TEST_CONNECTION_CAPACITY 8
#define TEST_CONNECT_TIMEOUT_MS 10000

typedef struct Crypto_Test_Node {
    const Memory *mem;
    const Random *rng;
    const Network *ns;
    Logger *log;
    Mono_Time *mono_time;
    Networking_Core *net;
    DHT *dht;
    Net_Profile *tcp_profile;
    Net_Crypto *crypto;
    IP_Port ip_port;
    int accepted_ids[TEST_CONNECTION_CAPACITY];
    uint32_t accepted_count;
    bool connected[TEST_CONNECTION_CAPACITY];
    uint32_t received_count;
    uint8_t first_received_ids[64];
    bool kill_on_next_data;
    int kill_connection_id;
} Crypto_Test_Node;

static int crypto_test_status_callback(
    void *object, int id, bool status, void *userdata)
{
    (void)userdata;
    Crypto_Test_Node *node = (Crypto_Test_Node *)object;

    if ((uint32_t)id < TEST_CONNECTION_CAPACITY) {
        node->connected[id] = status;
    }

    return 0;
}

static int crypto_test_data_callback(
    void *object, int id, const uint8_t *data, uint16_t length, void *userdata)
{
    (void)userdata;
    Crypto_Test_Node *node = (Crypto_Test_Node *)object;
    ck_assert(length > 0);

    if (node->received_count < sizeof(node->first_received_ids)) {
        node->first_received_ids[node->received_count] = data[0];
    }

    ++node->received_count;

    if (node->kill_on_next_data && id == node->kill_connection_id) {
        node->kill_on_next_data = false;
        ck_assert(crypto_kill(node->crypto, id) == 0);
    }

    return 0;
}

static void crypto_test_install_callbacks(Crypto_Test_Node *node, int id)
{
    ck_assert(id >= 0);
    ck_assert((uint32_t)id < TEST_CONNECTION_CAPACITY);
    ck_assert(connection_status_handler(
                  node->crypto, id, crypto_test_status_callback, node, id) == 0);
    ck_assert(connection_data_handler(
                  node->crypto, id, crypto_test_data_callback, node, id) == 0);
}

static int crypto_test_new_connection_callback(void *object, const New_Connection *new_connection)
{
    Crypto_Test_Node *node = (Crypto_Test_Node *)object;
    const int id = accept_crypto_connection(node->crypto, new_connection);

    if (id < 0) {
        return -1;
    }

    ck_assert(node->accepted_count < TEST_CONNECTION_CAPACITY);
    node->accepted_ids[node->accepted_count++] = id;
    crypto_test_install_callbacks(node, id);
    return 0;
}

static void crypto_test_node_init(Crypto_Test_Node *node, uint16_t first_port)
{
    memset(node, 0, sizeof(*node));
    node->mem = os_memory();
    node->rng = os_random();
    node->ns = os_network();
    ck_assert(node->mem != nullptr);
    ck_assert(node->rng != nullptr);
    ck_assert(node->ns != nullptr);

    node->log = logger_new(node->mem);
    ck_assert(node->log != nullptr);
    node->mono_time = mono_time_new(node->mem, nullptr, nullptr);
    ck_assert(node->mono_time != nullptr);

    IP loopback = {0};
    loopback.family = net_family_ipv4();
    loopback.ip.v4 = get_ip4_loopback();
    unsigned int error = 0;
    node->net = new_networking_ex(
                    node->log, node->mem, node->ns, &loopback,
                    first_port, first_port + 32, &error);
    ck_assert_msg(node->net != nullptr, "loopback networking setup failed: %u", error);

    node->dht = new_dht(
                    node->log, node->mem, node->rng, node->ns,
                    node->mono_time, node->net, true, true);
    ck_assert(node->dht != nullptr);
    node->tcp_profile = netprof_new(node->log, node->mem);
    ck_assert(node->tcp_profile != nullptr);
    const TCP_Proxy_Info proxy_info = {{{{0}}}};
    node->crypto = new_net_crypto(
                       node->log, node->mem, node->rng, node->ns,
                       node->mono_time, node->net, node->dht,
                       &auto_test_dht_funcs, &proxy_info, node->tcp_profile);
    ck_assert(node->crypto != nullptr);
    new_connection_handler(
        node->crypto, crypto_test_new_connection_callback, node);

    node->ip_port.ip = loopback;
    node->ip_port.port = net_port(node->net);
}

static void crypto_test_node_kill(Crypto_Test_Node *node)
{
    kill_net_crypto(node->crypto);
    netprof_kill(node->mem, node->tcp_profile);
    kill_dht(node->dht);
    kill_networking(node->net);
    mono_time_free(node->mem, node->mono_time);
    logger_kill(node->log);
    memset(node, 0, sizeof(*node));
}

static void crypto_test_iterate(Crypto_Test_Node *const *nodes, size_t count)
{
    for (size_t i = 0; i < count; ++i) {
        Crypto_Test_Node *node = nodes[i];
        mono_time_update(node->mono_time);
        networking_poll(node->net, node);
        do_net_crypto(node->crypto, node);
        do_dht(node->dht);
    }
}

static bool crypto_test_connection_live(const Crypto_Test_Node *node, int id)
{
    return crypto_connection_status(node->crypto, id, nullptr, nullptr);
}

static int crypto_test_connect(
    Crypto_Test_Node *from, Crypto_Test_Node *to,
    Crypto_Test_Node *const *nodes, size_t node_count, int *incoming_id)
{
    const uint32_t accepted_before = to->accepted_count;
    const int outgoing_id = new_crypto_connection(
                                from->crypto, nc_get_self_public_key(to->crypto),
                                dht_get_self_public_key(to->dht));
    ck_assert(outgoing_id >= 0);
    crypto_test_install_callbacks(from, outgoing_id);
    ck_assert(set_direct_ip_port(
                  from->crypto, outgoing_id, &to->ip_port, true) == 0);

    for (uint32_t elapsed = 0; elapsed < TEST_CONNECT_TIMEOUT_MS; ++elapsed) {
        crypto_test_iterate(nodes, node_count);

        if (to->accepted_count > accepted_before) {
            const int accepted_id = to->accepted_ids[accepted_before];

            if (crypto_test_connection_live(from, outgoing_id)
                    && crypto_test_connection_live(to, accepted_id)
                    && from->connected[outgoing_id]
                    && to->connected[accepted_id]) {
                *incoming_id = accepted_id;
                return outgoing_id;
            }
        }

        c_sleep(1);
    }

    ck_abort_msg("loopback crypto connection timed out");
    return -1;
}

static void crypto_test_send_and_wait(
    Crypto_Test_Node *from, int from_id, Crypto_Test_Node *to,
    Crypto_Test_Node *const *nodes, size_t node_count, uint8_t marker)
{
    const uint32_t received_before = to->received_count;
    const uint8_t packet[] = {PACKET_ID_RANGE_LOSSLESS_START, marker};
    ck_assert(write_cryptpacket(
                  from->crypto, from_id, packet, sizeof(packet), false) >= 0);

    for (uint32_t elapsed = 0; elapsed < TEST_CONNECT_TIMEOUT_MS; ++elapsed) {
        crypto_test_iterate(nodes, node_count);

        if (to->received_count == received_before + 1) {
            return;
        }

        c_sleep(1);
    }

    ck_abort_msg("loopback crypto data timed out");
}

static void test_connection_lifecycle(void)
{
    Crypto_Test_Node sender;
    Crypto_Test_Node receiver;
    Crypto_Test_Node control;
    crypto_test_node_init(&sender, 47600);
    crypto_test_node_init(&receiver, 47600);
    crypto_test_node_init(&control, 47600);
    Crypto_Test_Node *nodes[] = {&sender, &receiver, &control};

    int receiver_sender_id;
    int sender_id = crypto_test_connect(
                        &sender, &receiver, nodes,
                        sizeof(nodes) / sizeof(nodes[0]), &receiver_sender_id);
    int receiver_control_id;
    const int control_id = crypto_test_connect(
                               &control, &receiver, nodes,
                               sizeof(nodes) / sizeof(nodes[0]), &receiver_control_id);
    ck_assert(crypto_test_connection_live(&receiver, receiver_control_id));

    const uint32_t callback_order_start = receiver.received_count;
    ck_assert(callback_order_start + 3 <= sizeof(receiver.first_received_ids));
    const uint8_t callback_zero[] = {PACKET_ID_RANGE_LOSSLESS_START, 40};
    const uint8_t callback_one[] = {PACKET_ID_RANGE_LOSSLESS_START + 1, 41};
    const uint8_t callback_two[] = {PACKET_ID_RANGE_LOSSLESS_START + 2, 42};
    ck_assert(nc_testonly_handle_lossless_packet(
                  receiver.crypto, receiver_sender_id, 2,
                  callback_two, sizeof(callback_two), nullptr) == 0);
    ck_assert(receiver.received_count == callback_order_start);
    ck_assert(nc_testonly_handle_lossless_packet(
                  receiver.crypto, receiver_sender_id, 0,
                  callback_zero, sizeof(callback_zero), nullptr) == 0);
    ck_assert(receiver.received_count == callback_order_start + 1);
    ck_assert(nc_testonly_handle_lossless_packet(
                  receiver.crypto, receiver_sender_id, 1,
                  callback_one, sizeof(callback_one), nullptr) == 0);
    ck_assert(receiver.received_count == callback_order_start + 3);
    ck_assert(receiver.first_received_ids[callback_order_start]
              == PACKET_ID_RANGE_LOSSLESS_START);
    ck_assert(receiver.first_received_ids[callback_order_start + 1]
              == PACKET_ID_RANGE_LOSSLESS_START + 1);
    ck_assert(receiver.first_received_ids[callback_order_start + 2]
              == PACKET_ID_RANGE_LOSSLESS_START + 2);
    ck_assert(nc_testonly_receive_retained_bytes(
                  receiver.crypto, receiver_sender_id) == 0);

    /* The direct packet injection advances only the receiver-side packet
     * number. Recreate the synthetic pair before subsequent transport tests. */
    ck_assert(crypto_kill(sender.crypto, sender_id) == 0);
    ck_assert(crypto_kill(receiver.crypto, receiver_sender_id) == 0);
    sender_id = crypto_test_connect(
                    &sender, &receiver, nodes,
                    sizeof(nodes) / sizeof(nodes[0]), &receiver_sender_id);

    const uint8_t queued[] = {PACKET_ID_RANGE_LOSSLESS_START, 21};
    ck_assert(nc_testonly_handle_lossless_packet(
                  receiver.crypto, receiver_sender_id, 1,
                  queued, sizeof(queued), nullptr) == 0);
    ck_assert(nc_testonly_receive_retained_bytes(
                  receiver.crypto, receiver_sender_id)
              == receive_packet_allocation_size(sizeof(queued)));

    receiver.kill_on_next_data = true;
    receiver.kill_connection_id = receiver_sender_id;
    const uint8_t delivered[] = {PACKET_ID_RANGE_LOSSLESS_START + 1, 22};
    ck_assert(nc_testonly_handle_lossless_packet(
                  receiver.crypto, receiver_sender_id, 0,
                  delivered, sizeof(delivered), nullptr) == -1);
    ck_assert(!crypto_test_connection_live(&receiver, receiver_sender_id));
    ck_assert(nc_testonly_receive_retained_bytes(
                  receiver.crypto, receiver_sender_id) == SIZE_MAX);
    ck_assert(crypto_test_connection_live(&receiver, receiver_control_id));
    ck_assert(crypto_test_connection_live(&control, control_id));
    crypto_test_send_and_wait(
        &control, control_id, &receiver, nodes,
        sizeof(nodes) / sizeof(nodes[0]), 31);

    /* The private injection above advances only the receiver's packet-number
     * state, so its best-effort kill acknowledgement is intentionally not a
     * valid remote packet. Close the synthetic peer explicitly before the
     * reconnect check. The exact-cap case below keeps both sides aligned and
     * verifies the real remote disconnect path. */
    ck_assert(crypto_kill(sender.crypto, sender_id) == 0);
    sender_id = crypto_test_connect(
                    &sender, &receiver, nodes,
                    sizeof(nodes) / sizeof(nodes[0]), &receiver_sender_id);

    uint8_t maximum[MAX_CRYPTO_DATA_SIZE];
    fill_packet(maximum, sizeof(maximum), PACKET_ID_RANGE_LOSSLESS_START);
    maximum[0] = PACKET_ID_RANGE_LOSSLESS_START;
    const uint8_t minimum[] = {PACKET_ID_RANGE_LOSSLESS_START};
    const size_t maximum_size = receive_packet_allocation_size(MAX_CRYPTO_DATA_SIZE);
    const uint32_t maximum_count = 6100;
    const uint16_t final_length = (uint16_t)(
                                      CRYPTO_RECV_BUFFER_MAX_BYTES
                                      - (size_t)maximum_count * maximum_size
                                      - offsetof(Buffered_Packet, data));

    for (uint32_t number = 1; number <= maximum_count; ++number) {
        ck_assert(nc_testonly_handle_lossless_packet(
                      receiver.crypto, receiver_sender_id, number,
                      maximum, sizeof(maximum), nullptr) == 0);
    }

    ck_assert(nc_testonly_handle_lossless_packet(
                  receiver.crypto, receiver_sender_id, maximum_count + 1,
                  maximum, final_length, nullptr) == 0);
    ck_assert(nc_testonly_receive_retained_bytes(
                  receiver.crypto, receiver_sender_id)
              == CRYPTO_RECV_BUFFER_MAX_BYTES);

    const uint32_t received_before_recovery = receiver.received_count;
    ck_assert(nc_testonly_handle_lossless_packet(
                  receiver.crypto, receiver_sender_id, 0,
                  minimum, sizeof(minimum), nullptr) == 0);
    ck_assert(crypto_test_connection_live(&receiver, receiver_sender_id));
    ck_assert(nc_testonly_receive_retained_bytes(
                  receiver.crypto, receiver_sender_id) == 0);
    ck_assert(receiver.received_count - received_before_recovery == maximum_count + 2);

    const uint32_t buffer_start = maximum_count + 2;

    for (uint32_t offset = 1; offset <= maximum_count; ++offset) {
        ck_assert(nc_testonly_handle_lossless_packet(
                      receiver.crypto, receiver_sender_id, buffer_start + offset,
                      maximum, sizeof(maximum), nullptr) == 0);
    }

    ck_assert(nc_testonly_handle_lossless_packet(
                  receiver.crypto, receiver_sender_id, buffer_start + maximum_count + 1,
                  maximum, final_length, nullptr) == 0);
    ck_assert(nc_testonly_receive_retained_bytes(
                  receiver.crypto, receiver_sender_id)
              == CRYPTO_RECV_BUFFER_MAX_BYTES);
    ck_assert(nc_testonly_handle_lossless_packet(
                  receiver.crypto, receiver_sender_id, buffer_start + maximum_count + 2,
                  minimum, sizeof(minimum), nullptr) == 1);
    ck_assert(!crypto_test_connection_live(&receiver, receiver_sender_id));
    ck_assert(!receiver.connected[receiver_sender_id]);
    ck_assert(crypto_test_connection_live(&receiver, receiver_control_id));
    ck_assert(crypto_test_connection_live(&control, control_id));
    crypto_test_send_and_wait(
        &control, control_id, &receiver, nodes,
        sizeof(nodes) / sizeof(nodes[0]), 32);

    /* The capacity path is injected below the encrypted transport layer. Its
     * contract is the local offender-only teardown above; remote kill-packet
     * delivery remains covered by the ordinary connection regressions. */
    ck_assert(crypto_kill(sender.crypto, sender_id) == 0);
    sender_id = crypto_test_connect(
                    &sender, &receiver, nodes,
                    sizeof(nodes) / sizeof(nodes[0]), &receiver_sender_id);
    const uint32_t received_before_reconnect = receiver.received_count;
    ck_assert(write_cryptpacket(
                  sender.crypto, sender_id, maximum, sizeof(maximum), false) >= 0);

    for (uint32_t elapsed = 0;
            elapsed < TEST_CONNECT_TIMEOUT_MS
            && receiver.received_count == received_before_reconnect; ++elapsed) {
        crypto_test_iterate(nodes, sizeof(nodes) / sizeof(nodes[0]));
        c_sleep(1);
    }

    ck_assert(receiver.received_count == received_before_reconnect + 1);
    ck_assert(crypto_test_connection_live(&receiver, receiver_sender_id));
    ck_assert(crypto_test_connection_live(&receiver, receiver_control_id));

    crypto_test_node_kill(&sender);
    crypto_test_node_kill(&control);
    crypto_test_node_kill(&receiver);
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);
    test_proportional_lengths_holes_duplicates_and_order();
    test_all_legal_payload_lengths();
    test_wraparound();
    test_request_bytes_and_callback_cleanup();
    test_allocation_failure();
    test_exact_cap_gap_recovery_isolation_and_reconnect();
    test_connection_lifecycle();
    return 0;
}
