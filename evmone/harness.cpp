#include <cstdint>
#include <evmc/mocked_host.hpp>
#include <evmc/instructions.h>
#include <evmone/evmone.h>
#include <evmone/tracing.hpp>
#include <evmone/vm.hpp>
#include <test/state/host.hpp>
// #include <test/state/mpt_hash.hpp>
#include <test/utils/bytecode.hpp>
#include <test/utils/utils.hpp>

#include <cstring>
#include <iostream>
#include <limits>
#include "assert.h"

#include "/src/geth/libgeth.h"


class FuzzHost : public evmc::MockedHost {
public:
    // hash256 state_root;

    evmc::Result call(const evmc_message& msg) noexcept override {
        auto result = MockedHost::call(msg);
        // std::cout << "ONE RESULT: " << result.status_code << std::endl;
        if (result.status_code != EVMC_SUCCESS) 
            result.gas_refund = msg.gas;
        // std::cout << "ONE GAS REFUND CALL: " << result.gas_refund << std::endl;
        // state_root = evmone::state::mpt_hash()
        return result;
    }

    /*evmone::hash256 stateRoot() {
        auto stateRoot = evmone::state::mpt_hash(storage);
        return stateRoot;
    }*/
};

void printBytesAsHex(std::string name, uint8_t *data, ssize_t size) {
    std::cout << name << ": " << data << std::endl;
    for(size_t i = 0; i < size; i++) {
	    // std::cout << data[i];
        printf("%02X", data[i]);
    }
    std::cout << std::endl;
}

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv) {
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t data_size) noexcept {
    uint8_t *data2 = (uint8_t *)malloc(data_size);
    memcpy((void*)data2, (void*)data, data_size);

    // std::cout << "Execution of geth: " << std::endl;
    GoSlice goData = {(void *) data, (long long) data_size, (long long) data_size};
    GoInt gas = Fuzz(goData);

    // TODO: Create VM outside of TESTONINPUT Function
    // auto host = FuzzHost{};
    auto host = evmc::MockedHost{};
    auto vm = evmc::VM{evmc_create_evmone()};
    // auto host = evmone::state::Host{};
    // evmone::VM *vm = new evmone::VM{};
    // auto tracer = new evmone::Tracer{};
    // vm->add_tracer(tracer);
    // printf("Activating tracing %d\n", vm.set_option("trace", ""));

    evmc_tx_context ctx = host.get_tx_context();
    // std::cout << "Tx context: " << ctx.block_timestamp << std::endl;

    evmc_address addr = {{0, 1, 2}};
    evmc_message msg{};
    msg.flags = 0;
    msg.depth = 0; // 1024
    // msg.gas = 9223372036854775806;
    msg.gas = 1000;
    msg.sender = addr;
    msg.recipient = addr;
    // printBytesAsHex("ONE ADDR in harness", addr.bytes, 20);

    // EIP-2929
    host.access_account(msg.sender);
    host.access_account(msg.recipient);

    // Touch precompiled addr
    evmc_address pre_addr = {{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}};
    for (int i=0; i < 9; i++) {
        host.access_account(pre_addr);
        pre_addr.bytes[19] += 1;
    }

    host.tx_context.tx_gas_price = evmc::uint256be{100000000000000}; // = 0x5af3107a4000
    host.tx_context.tx_origin = addr;
    host.tx_context.block_coinbase = evmc_address{{0, 0, 0}};
    host.tx_context.block_number = 12965000; // london
    host.tx_context.block_timestamp = 0;
    host.tx_context.block_gas_limit = 7992222;
    host.tx_context.chain_id = evmc::uint256be{1};

    evmc::Result result = vm.execute(host, EVMC_LONDON, msg, data2, data_size);
    // evmone::hash256 stateRoot = host::stateRoot();
    // printBytesAsHex("StateRoot", stateRoot, sizeof(stateRoot));
    free((void *)data2);

    // std::cout << "Execution results in GETH: ";
    // std::cout << "Gas Used: " << 9223372036854775806 - gas << ", ";
    // std::cout << "Gas Left: " << gas << std::endl;

    // std::cout << "Execution results in EVMONE: ";
    // // std::cout << "Status: " << result.status_code << ", ";
    // std::cout << "Gas Used: " << 9223372036854775806 - result.gas_left << ", ";
    // std::cout << "Gas Left: " << result.gas_left << std::endl;

    if (result.status_code != EVMC_SUCCESS) {
        result.gas_left = msg.gas;
    }

    if (result.gas_left == gas && gas > 0) {
        // std::cout << "Gas was the same! GETH: " << gas << ", EVMONE: " << result.gas_left << std::endl;
        return 0;
    }

    if (result.gas_left != gas) {
        std::cout << "Not the same Gas! GETH: " << gas << ", EVMONE: " << result.gas_left << std::endl; 
        // assert(false);
        return 1;
    } 

    // TODO: add again later
    //else {
    //    std::cout << "Gas was the same! GETH: " << gas << ", EVMONE: " << result.gas_left << std::endl;
    //    return 0;
    //}

    return 0;
}
