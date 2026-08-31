#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../toxcore/TCP_client_internal.h"
#include "../toxcore/TCP_common.h"
#include "../toxcore/logger.h"
#include "../toxcore/mem.h"
#include "../toxcore/os_memory.h"
#include "../toxcore/os_random.h"
#include "auto_test_support.h"
#include "check_compat.h"

typedef struct Send_State {
    int first_result;
    bool use_first_result;
    bool send_all;
    uint32_t calls;
} Send_State;

static int controlled_send(void *object, Socket sock, const uint8_t *data, size_t length)
{
    (void)sock;
    (void)data;
    Send_State *state = (Send_State *)object;
    ++state->calls;

    if (state->use_first_result) {
        state->use_first_result = false;
        return state->first_result;
    }

    return state->send_all ? (int)length : 0;
}

static const Network_Funcs controlled_network_funcs = {
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    controlled_send,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
};

typedef struct Failing_Memory {
    Memory mem;
    uint32_t allocation_count;
    uint32_t fail_on_allocation;
    uint32_t live_allocations;
} Failing_Memory;

static void *failing_malloc(void *object, uint32_t size)
{
    Failing_Memory *state = (Failing_Memory *)object;
    ++state->allocation_count;

    if (state->allocation_count == state->fail_on_allocation) {
        return nullptr;
    }

    void *ptr = malloc(size);

    if (ptr != nullptr) {
        ++state->live_allocations;
    }

    return ptr;
}

static void *failing_realloc(void *object, void *ptr, uint32_t size)
{
    Failing_Memory *state = (Failing_Memory *)object;
    ++state->allocation_count;

    if (state->allocation_count == state->fail_on_allocation) {
        return nullptr;
    }

    void *new_ptr = realloc(ptr, size);

    if (new_ptr != nullptr && ptr == nullptr) {
        ++state->live_allocations;
    }

    return new_ptr;
}

static void failing_dealloc(void *object, void *ptr)
{
    Failing_Memory *state = (Failing_Memory *)object;

    if (ptr != nullptr) {
        ck_assert(state->live_allocations > 0);
        --state->live_allocations;
    }

    free(ptr);
}

static const Memory_Funcs failing_memory_funcs = {
    failing_malloc,
    failing_realloc,
    failing_dealloc,
};

static void init_connection(TCP_Connection *con, const Memory *mem, const Network *ns)
{
    memset(con, 0, sizeof(*con));
    con->mem = mem;
    con->rng = os_random();
    con->ns = ns;
    memset(con->shared_key, 0x42, sizeof(con->shared_key));
    memset(con->sent_nonce, 0x12, sizeof(con->sent_nonce));
}

static void attach_account(TCP_Connection *con, TCP_Priority_Queue_Account *account)
{
    ck_assert(con->priority_queue_account == nullptr);
    ck_assert(con->priority_queue_start == nullptr);
    ck_assert(con->priority_queue_end == nullptr);
    ck_assert(con->priority_queue_items == 0);
    ck_assert(con->priority_queue_bytes == 0);
    con->priority_queue_account = account;
}

static void assert_queue_accounting(const TCP_Connection *con)
{
    uint32_t items = 0;
    uint32_t bytes = 0;
    const TCP_Priority_List *last = nullptr;

    for (const TCP_Priority_List *p = con->priority_queue_start; p != nullptr; p = p->next) {
        ++items;
        bytes += p->size;
        last = p;
    }

    ck_assert(items == con->priority_queue_items);
    ck_assert(bytes == con->priority_queue_bytes);
    ck_assert(last == con->priority_queue_end);

    if (con->priority_queue_account != nullptr) {
        ck_assert(con->priority_queue_account->bytes >= con->priority_queue_bytes);
    }
}

static void test_internal_client_account_attachment(void)
{
    const Memory *mem = os_memory();
    ck_assert(mem != nullptr);
    Send_State send_state = {0, false, false, 0};
    const Network ns = {&controlled_network_funcs, &send_state};
    Logger *logger = logger_new(mem);
    ck_assert(logger != nullptr);
    TCP_Client_Connection client = {0};
    TCP_Priority_Queue_Account account = {0};
    init_connection(&client.con, mem, &ns);

    tcp_client_connection_attach_priority_queue_account(&client, &account);
    ck_assert(client.con.priority_queue_account == &account);
    const uint8_t packet[] = {TCP_PACKET_PING};
    ck_assert(write_packet_tcp_secure_connection(logger, &client.con,
              packet, sizeof(packet), true) == 1);
    ck_assert(account.bytes == client.con.priority_queue_bytes);
    ck_assert(account.bytes > 0);
    tcp_connection_wipe_priority_queue(&client.con);
    ck_assert(account.bytes == 0);
    logger_kill(logger);
}

static void test_partial_send_and_cleanup(void)
{
    const Memory *mem = os_memory();
    ck_assert(mem != nullptr);
    Send_State send_state = {5, true, false, 0};
    const Network ns = {&controlled_network_funcs, &send_state};
    TCP_Connection con;
    init_connection(&con, mem, &ns);
    TCP_Priority_Queue_Account account = {0};
    attach_account(&con, &account);
    Logger *logger = logger_new(mem);
    ck_assert(logger != nullptr);

    uint8_t expected_nonce[CRYPTO_NONCE_SIZE];
    memcpy(expected_nonce, con.sent_nonce, sizeof(expected_nonce));
    const uint8_t first[] = {TCP_PACKET_PING, 1, 2, 3};
    const uint8_t second[] = {TCP_PACKET_PONG, 4, 5, 6};

    ck_assert(write_packet_tcp_secure_connection(logger, &con, first, sizeof(first), true) == 1);
    increment_nonce(expected_nonce);
    ck_assert(memcmp(con.sent_nonce, expected_nonce, sizeof(expected_nonce)) == 0);
    ck_assert(con.priority_queue_items == 1);
    ck_assert(con.priority_queue_start->sent == 5);
    ck_assert(account.bytes == con.priority_queue_bytes);
    const uint32_t retained_after_partial_send = account.bytes;
    send_state.first_result = 3;
    send_state.use_first_result = true;
    ck_assert(send_pending_data(logger, &con) == -1);
    ck_assert(con.priority_queue_start->sent == 8);
    ck_assert(account.bytes == retained_after_partial_send);
    ck_assert(con.priority_queue_bytes == retained_after_partial_send);

    ck_assert(write_packet_tcp_secure_connection(logger, &con, second, sizeof(second), true) == 1);
    increment_nonce(expected_nonce);
    ck_assert(memcmp(con.sent_nonce, expected_nonce, sizeof(expected_nonce)) == 0);
    ck_assert(con.priority_queue_items == 2);
    ck_assert(con.priority_queue_start->next == con.priority_queue_end);
    ck_assert(account.bytes > retained_after_partial_send);
    ck_assert(account.bytes == con.priority_queue_bytes);
    assert_queue_accounting(&con);

    send_state.send_all = true;
    ck_assert(send_pending_data(logger, &con) == 0);
    ck_assert(con.priority_queue_start == nullptr);
    ck_assert(con.priority_queue_end == nullptr);
    ck_assert(con.priority_queue_items == 0);
    ck_assert(con.priority_queue_bytes == 0);
    ck_assert(account.bytes == 0);
    assert_queue_accounting(&con);

    tcp_connection_wipe_priority_queue(&con);
    ck_assert(account.bytes == 0);
    logger_kill(logger);
}

static void test_item_cap_nonce_and_reconnect(void)
{
    const Memory *mem = os_memory();
    ck_assert(mem != nullptr);
    Send_State send_state = {0, false, false, 0};
    const Network ns = {&controlled_network_funcs, &send_state};
    TCP_Connection con;
    init_connection(&con, mem, &ns);
    TCP_Priority_Queue_Account account = {0};
    attach_account(&con, &account);
    Logger *logger = logger_new(mem);
    ck_assert(logger != nullptr);
    const uint8_t packet[] = {TCP_PACKET_PING};
    uint8_t expected_nonce[CRYPTO_NONCE_SIZE];
    memcpy(expected_nonce, con.sent_nonce, sizeof(expected_nonce));

    for (uint32_t i = 0; i < TCP_PRIORITY_QUEUE_MAX_ITEMS; ++i) {
        ck_assert(write_packet_tcp_secure_connection(logger, &con, packet, sizeof(packet), true) == 1);
        increment_nonce(expected_nonce);
    }

    ck_assert(con.priority_queue_items == TCP_PRIORITY_QUEUE_MAX_ITEMS);
    ck_assert(account.bytes == con.priority_queue_bytes);
    assert_queue_accounting(&con);
    ck_assert(write_packet_tcp_secure_connection(logger, &con, packet, sizeof(packet), true) == -1);
    increment_nonce(expected_nonce);
    ck_assert(memcmp(con.sent_nonce, expected_nonce, sizeof(expected_nonce)) == 0);
    ck_assert(con.priority_queue_fatal);
    ck_assert(con.priority_queue_items == TCP_PRIORITY_QUEUE_MAX_ITEMS);
    ck_assert(account.bytes == con.priority_queue_bytes);

    const uint32_t calls_after_fatal = send_state.calls;
    ck_assert(write_packet_tcp_secure_connection(logger, &con, packet, sizeof(packet), true) == -1);
    ck_assert(memcmp(con.sent_nonce, expected_nonce, sizeof(expected_nonce)) == 0);
    ck_assert(send_state.calls == calls_after_fatal);

    const uint32_t retained_after_fatal = account.bytes;
    ck_assert(write_packet_tcp_secure_connection(logger, &con, packet, sizeof(packet), false) == 0);
    ck_assert(memcmp(con.sent_nonce, expected_nonce, sizeof(expected_nonce)) == 0);
    ck_assert(send_state.calls == calls_after_fatal);
    ck_assert(account.bytes == retained_after_fatal);
    ck_assert(con.priority_queue_bytes == retained_after_fatal);
    ck_assert(con.priority_queue_fatal);

    tcp_connection_wipe_priority_queue(&con);
    ck_assert(con.priority_queue_items == 0);
    ck_assert(con.priority_queue_bytes == 0);
    ck_assert(account.bytes == 0);
    ck_assert(con.priority_queue_fatal);
    tcp_connection_wipe_priority_queue(&con);
    ck_assert(account.bytes == 0);

    TCP_Connection reconnected;
    init_connection(&reconnected, mem, &ns);
    attach_account(&reconnected, &account);
    ck_assert(write_packet_tcp_secure_connection(logger, &reconnected, packet, sizeof(packet), true) == 1);
    ck_assert(!reconnected.priority_queue_fatal);
    ck_assert(reconnected.priority_queue_items == 1);
    ck_assert(account.bytes == reconnected.priority_queue_bytes);
    tcp_connection_wipe_priority_queue(&reconnected);
    ck_assert(account.bytes == 0);
    logger_kill(logger);
}

static void test_byte_cap(void)
{
    const Memory *mem = os_memory();
    ck_assert(mem != nullptr);
    Send_State send_state = {0, false, false, 0};
    const Network ns = {&controlled_network_funcs, &send_state};
    TCP_Connection con;
    init_connection(&con, mem, &ns);
    TCP_Priority_Queue_Account account = {0};
    attach_account(&con, &account);
    Logger *logger = logger_new(mem);
    ck_assert(logger != nullptr);
    uint8_t packet[MAX_PACKET_SIZE - CRYPTO_MAC_SIZE] = {TCP_PACKET_PING};

    while (con.priority_queue_bytes + sizeof(uint16_t) + sizeof(packet) + CRYPTO_MAC_SIZE
            <= TCP_PRIORITY_QUEUE_MAX_BYTES) {
        ck_assert(write_packet_tcp_secure_connection(logger, &con, packet, sizeof(packet), true) == 1);
    }

    ck_assert(con.priority_queue_items < TCP_PRIORITY_QUEUE_MAX_ITEMS);
    ck_assert(con.priority_queue_bytes <= TCP_PRIORITY_QUEUE_MAX_BYTES);
    ck_assert(account.bytes == con.priority_queue_bytes);
    ck_assert(write_packet_tcp_secure_connection(logger, &con, packet, sizeof(packet), true) == -1);
    ck_assert(con.priority_queue_fatal);
    ck_assert(account.bytes == con.priority_queue_bytes);
    assert_queue_accounting(&con);
    tcp_connection_wipe_priority_queue(&con);
    ck_assert(account.bytes == 0);
    logger_kill(logger);
}

static void test_allocation_failure_is_fatal(void)
{
    for (uint32_t fail_on = 3; fail_on <= 4; ++fail_on) {
        Failing_Memory memory = {
            {&failing_memory_funcs, nullptr},
            0,
            fail_on,
            0,
        };
        memory.mem.user_data = &memory;
        Send_State send_state = {0, false, false, 0};
        const Network ns = {&controlled_network_funcs, &send_state};
        TCP_Connection con;
        init_connection(&con, &memory.mem, &ns);
        TCP_Priority_Queue_Account account = {0};
        attach_account(&con, &account);
        Logger *logger = logger_new(os_memory());
        ck_assert(logger != nullptr);
        const uint8_t packet[] = {TCP_PACKET_PING, 7};
        uint8_t expected_nonce[CRYPTO_NONCE_SIZE];
        memcpy(expected_nonce, con.sent_nonce, sizeof(expected_nonce));

        ck_assert(write_packet_tcp_secure_connection(logger, &con, packet, sizeof(packet), true) == -1);
        increment_nonce(expected_nonce);
        ck_assert(memcmp(con.sent_nonce, expected_nonce, sizeof(expected_nonce)) == 0);
        ck_assert(con.priority_queue_fatal);
        ck_assert(con.priority_queue_items == 0);
        ck_assert(con.priority_queue_bytes == 0);
        ck_assert(con.priority_queue_start == nullptr);
        ck_assert(con.priority_queue_end == nullptr);
        ck_assert(account.bytes == 0);
        ck_assert(memory.allocation_count == fail_on);
        ck_assert(memory.live_allocations == 0);
        logger_kill(logger);
    }
}

static void test_global_account_exact_cap_and_recovery(void)
{
    const Memory *mem = os_memory();
    ck_assert(mem != nullptr);
    Send_State send_state = {0, false, false, 0};
    const Network ns = {&controlled_network_funcs, &send_state};
    Logger *logger = logger_new(mem);
    ck_assert(logger != nullptr);

    enum {
        OWNER_CONNECTION_COUNT = TCP_PRIORITY_QUEUE_GLOBAL_MAX_BYTES / TCP_PRIORITY_QUEUE_MAX_BYTES,
    };
    TCP_Client_Connection siblings[OWNER_CONNECTION_COUNT];
    TCP_Priority_Queue_Account account = {0};
    uint8_t packet[MAX_PACKET_SIZE - CRYPTO_MAC_SIZE - sizeof(uint16_t)] = {TCP_PACKET_PING};
    const uint32_t retained_frame_bytes = sizeof(uint16_t) + sizeof(packet) + CRYPTO_MAC_SIZE;

    ck_assert(retained_frame_bytes * TCP_PRIORITY_QUEUE_MAX_ITEMS == TCP_PRIORITY_QUEUE_MAX_BYTES);
    ck_assert(OWNER_CONNECTION_COUNT * TCP_PRIORITY_QUEUE_MAX_BYTES
              == TCP_PRIORITY_QUEUE_GLOBAL_MAX_BYTES);

    for (uint32_t i = 0; i < OWNER_CONNECTION_COUNT; ++i) {
        memset(&siblings[i], 0, sizeof(siblings[i]));
        init_connection(&siblings[i].con, mem, &ns);
        tcp_client_connection_attach_priority_queue_account(&siblings[i], &account);

        for (uint32_t item = 0; item < TCP_PRIORITY_QUEUE_MAX_ITEMS; ++item) {
            ck_assert(write_packet_tcp_secure_connection(logger, &siblings[i].con,
                      packet, sizeof(packet), true) == 1);
        }

        ck_assert(siblings[i].con.priority_queue_items == TCP_PRIORITY_QUEUE_MAX_ITEMS);
        ck_assert(siblings[i].con.priority_queue_bytes == TCP_PRIORITY_QUEUE_MAX_BYTES);
        ck_assert(!siblings[i].con.priority_queue_fatal);
        assert_queue_accounting(&siblings[i].con);
    }

    ck_assert(account.bytes == TCP_PRIORITY_QUEUE_GLOBAL_MAX_BYTES);

    TCP_Client_Connection offender = {0};
    init_connection(&offender.con, mem, &ns);
    tcp_client_connection_attach_priority_queue_account(&offender, &account);
    uint8_t expected_nonce[CRYPTO_NONCE_SIZE];
    memcpy(expected_nonce, offender.con.sent_nonce, sizeof(expected_nonce));

    ck_assert(write_packet_tcp_secure_connection(logger, &offender.con,
              packet, sizeof(packet), true) == -1);
    increment_nonce(expected_nonce);
    ck_assert(memcmp(offender.con.sent_nonce, expected_nonce, sizeof(expected_nonce)) == 0);
    ck_assert(offender.con.priority_queue_fatal);
    ck_assert(offender.con.priority_queue_items == 0);
    ck_assert(offender.con.priority_queue_bytes == 0);
    ck_assert(account.bytes == TCP_PRIORITY_QUEUE_GLOBAL_MAX_BYTES);

    for (uint32_t i = 0; i < OWNER_CONNECTION_COUNT; ++i) {
        ck_assert(!siblings[i].con.priority_queue_fatal);
    }

    ck_assert(write_packet_tcp_secure_connection(logger, &offender.con,
              packet, sizeof(packet), true) == -1);
    ck_assert(memcmp(offender.con.sent_nonce, expected_nonce, sizeof(expected_nonce)) == 0);
    ck_assert(account.bytes == TCP_PRIORITY_QUEUE_GLOBAL_MAX_BYTES);
    const uint32_t calls_after_global_fatal = send_state.calls;
    ck_assert(write_packet_tcp_secure_connection(logger, &offender.con,
              packet, sizeof(packet), false) == 0);
    ck_assert(memcmp(offender.con.sent_nonce, expected_nonce, sizeof(expected_nonce)) == 0);
    ck_assert(send_state.calls == calls_after_global_fatal);
    ck_assert(account.bytes == TCP_PRIORITY_QUEUE_GLOBAL_MAX_BYTES);

    for (uint32_t i = 0; i < OWNER_CONNECTION_COUNT; ++i) {
        ck_assert(!siblings[i].con.priority_queue_fatal);
    }

    tcp_connection_wipe_priority_queue(&siblings[0].con);
    ck_assert(account.bytes == TCP_PRIORITY_QUEUE_GLOBAL_MAX_BYTES - TCP_PRIORITY_QUEUE_MAX_BYTES);
    tcp_connection_wipe_priority_queue(&siblings[0].con);
    ck_assert(account.bytes == TCP_PRIORITY_QUEUE_GLOBAL_MAX_BYTES - TCP_PRIORITY_QUEUE_MAX_BYTES);

    TCP_Client_Connection replacement = {0};
    init_connection(&replacement.con, mem, &ns);
    tcp_client_connection_attach_priority_queue_account(&replacement, &account);

    for (uint32_t item = 0; item < TCP_PRIORITY_QUEUE_MAX_ITEMS; ++item) {
        ck_assert(write_packet_tcp_secure_connection(logger, &replacement.con,
                  packet, sizeof(packet), true) == 1);
    }

    ck_assert(replacement.con.priority_queue_bytes == TCP_PRIORITY_QUEUE_MAX_BYTES);
    ck_assert(!replacement.con.priority_queue_fatal);
    ck_assert(account.bytes == TCP_PRIORITY_QUEUE_GLOBAL_MAX_BYTES);

    tcp_connection_wipe_priority_queue(&replacement.con);

    for (uint32_t i = 1; i < OWNER_CONNECTION_COUNT; ++i) {
        tcp_connection_wipe_priority_queue(&siblings[i].con);
    }

    tcp_connection_wipe_priority_queue(&offender.con);
    ck_assert(account.bytes == 0);
    logger_kill(logger);
}

static void test_global_account_corruption_guard(void)
{
    const Memory *mem = os_memory();
    ck_assert(mem != nullptr);
    Send_State send_state = {0, false, false, 0};
    const Network ns = {&controlled_network_funcs, &send_state};
    Logger *logger = logger_new(mem);
    ck_assert(logger != nullptr);
    TCP_Priority_Queue_Account account = {TCP_PRIORITY_QUEUE_GLOBAL_MAX_BYTES + 1U};
    TCP_Connection con;
    init_connection(&con, mem, &ns);
    attach_account(&con, &account);
    const uint8_t packet[] = {TCP_PACKET_PING};
    uint8_t expected_nonce[CRYPTO_NONCE_SIZE];
    memcpy(expected_nonce, con.sent_nonce, sizeof(expected_nonce));

    ck_assert(write_packet_tcp_secure_connection(logger, &con, packet, sizeof(packet), true) == -1);
    increment_nonce(expected_nonce);
    ck_assert(memcmp(con.sent_nonce, expected_nonce, sizeof(expected_nonce)) == 0);
    ck_assert(con.priority_queue_fatal);
    ck_assert(con.priority_queue_start == nullptr);
    ck_assert(con.priority_queue_bytes == 0);
    ck_assert(account.bytes == TCP_PRIORITY_QUEUE_GLOBAL_MAX_BYTES + 1U);

    tcp_connection_wipe_priority_queue(&con);
    ck_assert(account.bytes == TCP_PRIORITY_QUEUE_GLOBAL_MAX_BYTES + 1U);
    account.bytes = 0;
    logger_kill(logger);
}

static void test_separate_accounts_are_independent(void)
{
    const Memory *mem = os_memory();
    ck_assert(mem != nullptr);
    Send_State send_state = {0, false, false, 0};
    const Network ns = {&controlled_network_funcs, &send_state};
    Logger *logger = logger_new(mem);
    ck_assert(logger != nullptr);
    TCP_Priority_Queue_Account first_account = {0};
    TCP_Priority_Queue_Account second_account = {0};
    TCP_Connection first;
    TCP_Connection second;
    init_connection(&first, mem, &ns);
    init_connection(&second, mem, &ns);
    attach_account(&first, &first_account);
    attach_account(&second, &second_account);
    const uint8_t packet[] = {TCP_PACKET_PING, 1};

    ck_assert(write_packet_tcp_secure_connection(logger, &first, packet, sizeof(packet), true) == 1);
    ck_assert(write_packet_tcp_secure_connection(logger, &second, packet, sizeof(packet), true) == 1);
    ck_assert(first_account.bytes == first.priority_queue_bytes);
    ck_assert(second_account.bytes == second.priority_queue_bytes);

    send_state.send_all = true;
    ck_assert(send_pending_data(logger, &first) == 0);
    ck_assert(first_account.bytes == 0);
    ck_assert(second_account.bytes == second.priority_queue_bytes);
    ck_assert(second_account.bytes > 0);

    tcp_connection_wipe_priority_queue(&second);
    ck_assert(second_account.bytes == 0);
    logger_kill(logger);
}

static void test_null_account_behavior_is_unchanged(void)
{
    const Memory *mem = os_memory();
    ck_assert(mem != nullptr);
    Send_State send_state = {0, false, false, 0};
    const Network ns = {&controlled_network_funcs, &send_state};
    Logger *logger = logger_new(mem);
    ck_assert(logger != nullptr);
    TCP_Connection con;
    init_connection(&con, mem, &ns);
    const uint8_t packet[] = {TCP_PACKET_PONG, 2};

    ck_assert(con.priority_queue_account == nullptr);
    ck_assert(write_packet_tcp_secure_connection(logger, &con, packet, sizeof(packet), true) == 1);
    ck_assert(con.priority_queue_items == 1);
    ck_assert(con.priority_queue_bytes > 0);
    send_state.send_all = true;
    ck_assert(send_pending_data(logger, &con) == 0);
    ck_assert(con.priority_queue_items == 0);
    ck_assert(con.priority_queue_bytes == 0);
    ck_assert(con.priority_queue_account == nullptr);
    tcp_connection_wipe_priority_queue(&con);
    logger_kill(logger);
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);
    test_internal_client_account_attachment();
    test_partial_send_and_cleanup();
    test_item_cap_nonce_and_reconnect();
    test_byte_cap();
    test_allocation_failure_is_fatal();
    test_global_account_exact_cap_and_recovery();
    test_global_account_corruption_guard();
    test_separate_accounts_are_independent();
    test_null_account_behavior_is_unchanged();
    return 0;
}
