#include "../testing/support/public/simulated_environment.hh"
#include "../toxcore/DHT_test_util.hh"
#include "../toxcore/net_crypto.h"
#include "../toxcore/net_profile.h"
#include "../toxcore/network.h"
#include "../toxcore/test_util.hh"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <memory>
#include <vector>

namespace {

using tox::test::Packet;
using tox::test::SimulatedEnvironment;

constexpr std::uint16_t kAlicePort = 33445;
constexpr std::uint16_t kBobPort = 33446;
constexpr std::uint64_t kConnectTimeoutMs = 5000;
constexpr std::uint64_t kRetransmitTimeoutMs = 5000;

class TestNode {
public:
    TestNode(SimulatedEnvironment &env, std::uint16_t port)
        : dht_wrapper_(env, port)
        , net_profile_(netprof_new(dht_wrapper_.logger(), &dht_wrapper_.node().c_memory),
              [mem = &dht_wrapper_.node().c_memory](Net_Profile *profile) {
                  netprof_kill(mem, profile);
              })
        , net_crypto_(nullptr, [](Net_Crypto *crypto) { kill_net_crypto(crypto); })
    {
        TCP_Proxy_Info proxy_info = {{0}, TCP_PROXY_NONE};
        net_crypto_.reset(new_net_crypto(dht_wrapper_.logger(), &dht_wrapper_.node().c_memory,
            &dht_wrapper_.node().c_random, &dht_wrapper_.node().c_network,
            dht_wrapper_.mono_time(), dht_wrapper_.networking(), dht_wrapper_.get_dht(),
            &WrappedMockDHT::funcs, &proxy_info, REQUIRE_NOT_NULL(net_profile_.get())));
        new_connection_handler(
            REQUIRE_NOT_NULL(net_crypto_.get()), &TestNode::new_connection_callback, this);
    }

    ~TestNode() = default;

    const std::uint8_t *real_public_key() const
    {
        return nc_get_self_public_key(REQUIRE_NOT_NULL(net_crypto_.get()));
    }

    const std::uint8_t *dht_public_key() const { return dht_wrapper_.dht_public_key(); }

    IP_Port ip_port() const { return dht_wrapper_.get_ip_port(); }

    void poll()
    {
        dht_wrapper_.poll();
        do_net_crypto(REQUIRE_NOT_NULL(net_crypto_.get()), nullptr);
    }

    int connect_to(TestNode &other)
    {
        const int id = new_crypto_connection(REQUIRE_NOT_NULL(net_crypto_.get()),
            other.real_public_key(), other.dht_public_key());
        if (id == -1) {
            return -1;
        }

        const IP_Port address = other.ip_port();
        set_direct_ip_port(REQUIRE_NOT_NULL(net_crypto_.get()), id, &address, true);
        setup_connection_callbacks(id);
        return id;
    }

    bool send_data(int connection_id, const std::vector<std::uint8_t> &data)
    {
        return !data.empty()
            && write_cryptpacket(REQUIRE_NOT_NULL(net_crypto_.get()), connection_id, data.data(),
                   data.size(), false)
                != -1;
    }

    bool is_connected(int connection_id) const
    {
        return connection_id >= 0
            && connection_id < static_cast<int>(connections_.size())
            && connections_[connection_id].connected;
    }

    int accepted_connection_id() const { return last_accepted_id_; }

    const std::vector<std::uint8_t> &last_received_data(int connection_id) const
    {
        if (connection_id < 0 || connection_id >= static_cast<int>(connections_.size())) {
            return empty_data_;
        }
        return connections_[connection_id].received_data;
    }

private:
    struct ConnectionState {
        bool connected = false;
        std::vector<std::uint8_t> received_data;
    };

    void setup_connection_callbacks(int id)
    {
        if (id >= static_cast<int>(connections_.size())) {
            connections_.resize(id + 1);
        }
        connection_status_handler(REQUIRE_NOT_NULL(net_crypto_.get()), id,
            &TestNode::connection_status_callback, this, id);
        connection_data_handler(REQUIRE_NOT_NULL(net_crypto_.get()), id,
            &TestNode::connection_data_callback, this, id);
    }

    static int new_connection_callback(
        void *object, const New_Connection *new_connection)
    {
        auto *self = static_cast<TestNode *>(object);
        const int id = accept_crypto_connection(
            REQUIRE_NOT_NULL(self->net_crypto_.get()), new_connection);
        if (id == -1) {
            return -1;
        }

        self->last_accepted_id_ = id;
        self->setup_connection_callbacks(id);
        return 0;
    }

    static int connection_status_callback(
        void *object, int id, bool status, void *)
    {
        auto *self = static_cast<TestNode *>(object);
        if (id >= 0 && id < static_cast<int>(self->connections_.size())) {
            self->connections_[id].connected = status;
        }
        return 0;
    }

    static int connection_data_callback(
        void *object, int id, const std::uint8_t *data, std::uint16_t length, void *)
    {
        auto *self = static_cast<TestNode *>(object);
        if (id >= 0 && id < static_cast<int>(self->connections_.size())) {
            self->connections_[id].received_data.assign(data, data + length);
        }
        return 0;
    }

    WrappedMockDHT dht_wrapper_;
    std::vector<ConnectionState> connections_{128};
    int last_accepted_id_ = -1;
    std::vector<std::uint8_t> empty_data_;
    std::unique_ptr<Net_Profile, std::function<void(Net_Profile *)>> net_profile_;
    std::unique_ptr<Net_Crypto, void (*)(Net_Crypto *)> net_crypto_;
};

int fail(const char *message)
{
    std::fprintf(stderr, "FAIL: %s\n", message);
    return EXIT_FAILURE;
}

}  // namespace

int main()
{
    std::size_t alice_to_bob_data_packets = 0;
    std::size_t dropped_packets = 0;
    SimulatedEnvironment env{12345};
    TestNode alice(env, kAlicePort);
    TestNode bob(env, kBobPort);

    const int alice_connection_id = alice.connect_to(bob);
    if (alice_connection_id == -1) {
        return fail("Alice could not create the crypto connection");
    }

    const std::uint64_t connect_start = env.clock().current_time_ms();
    int bob_connection_id = -1;
    while (env.clock().current_time_ms() - connect_start < kConnectTimeoutMs) {
        alice.poll();
        bob.poll();
        env.advance_time(10);

        bob_connection_id = bob.accepted_connection_id();
        if (alice.is_connected(alice_connection_id) && bob_connection_id != -1
            && bob.is_connected(bob_connection_id)) {
            break;
        }
    }

    if (!alice.is_connected(alice_connection_id) || bob_connection_id == -1
        || !bob.is_connected(bob_connection_id)) {
        return fail("crypto connection was not established within 5000 ms of virtual time");
    }

    env.simulation().net().add_filter([&](Packet &packet) {
        const bool alice_to_bob = net_ntohs(packet.from.port) == kAlicePort
            && net_ntohs(packet.to.port) == kBobPort;
        if (alice_to_bob && !packet.data.empty()
            && packet.data[0] == NET_PACKET_CRYPTO_DATA) {
            ++alice_to_bob_data_packets;
            if (alice_to_bob_data_packets == 1) {
                ++dropped_packets;
                return false;
            }
        }
        return true;
    });

    const std::vector<std::uint8_t> message = {161, 'R', 'e', 't', 'r', 'y'};
    if (!alice.send_data(alice_connection_id, message)) {
        return fail("Alice could not queue the test message");
    }
    if (dropped_packets != 1 || alice_to_bob_data_packets != 1) {
        return fail("the first Alice-to-Bob NET_PACKET_CRYPTO_DATA was not dropped exactly once");
    }

    const std::uint64_t retransmit_start = env.clock().current_time_ms();
    bool exact_message_received = false;
    while (env.clock().current_time_ms() - retransmit_start < kRetransmitTimeoutMs) {
        alice.poll();
        bob.poll();
        env.advance_time(50);

        if (bob.last_received_data(bob_connection_id) == message) {
            exact_message_received = true;
            break;
        }
    }

    if (dropped_packets != 1) {
        return fail("more than one Alice-to-Bob data packet was dropped");
    }
    if (alice_to_bob_data_packets < 2) {
        return fail("Alice never emitted a data packet after the forced loss");
    }
    if (!exact_message_received) {
        return fail("Bob did not receive the exact message after retransmission within 5000 ms");
    }

    std::printf("PASS: dropped exactly one first Alice-to-Bob NET_PACKET_CRYPTO_DATA "
                "and received the exact message after retransmission\n");
    return EXIT_SUCCESS;
}
