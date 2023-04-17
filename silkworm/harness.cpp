#include <cstdint>
#include <evmc/mocked_host.hpp>
#include <evmc/instructions.h>
#include <evmone/evmone.h>
#include <evmone/tracing.hpp>
#include <evmone/vm.hpp>
// #include <test/state/host.hpp>
// #include <test/utils/bytecode.hpp>
// #include <test/utils/utils.hpp>
#include <silkworm/core/execution/evm.hpp>
#include <silkworm/core/state/in_memory_state.hpp>

#include <cstring>
#include <iostream>
#include <limits>

#include "/src/geth/libgeth.h"

#define GAS 1000

// void printBytesAsHex(std::string name, uint8_t *data, ssize_t size) {
//     std::cout << name << ": " << data << std::endl;
//     for(size_t i = 0; i < size; i++) {
// 	    // std::cout << data[i];
//         printf("%02X", data[i]);
//     }
//     std::cout << std::endl;
// }

extern "C" {
    int* get_debug_mode();
}

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv) {
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t data_size) noexcept {
    int* debug_mode = get_debug_mode();

    uint8_t *data2 = (uint8_t *)malloc(data_size);
    memcpy((void*)data2, (void*)data, data_size);

    // std::basic_string<uint8_t> data2(data, data_size);

    GoSlice goData = {(void *) data, (long long) data_size, (long long) data_size};
    GoInt debug = *debug_mode;
    GoInt gas = Fuzz(goData, debug);

    // TODO: Create VM outside of TESTONINPUT Function
    // auto vm = evmc::VM{evmc_create_evmone()};
    // auto vm = silkworm::EVM{};
    silkworm::Block block{};
    block.header.number = 12965000;

    // evmc::address from{0x0001020000000000000000000000000000000000_address};
    // evmc::address to{0x0001020000000000000000000000000000000000_address};
    // evmc_address addr = evmc_address{{0, 0, 0}};
    // intx::uint256 value{10'200'000'000'000'000};

    silkworm::InMemoryState db;
    silkworm::IntraBlockState state{db};
    silkworm::EVM vm{block, state, silkworm::kMainnetConfig};
    silkworm::EvmHost host{vm};
    // silkworm::Bytes code{data2};

    // const evmc_message message{
    //     .kind = contract_creation ? EVMC_CREATE : EVMC_CALL,
    //     .gas = static_cast<int64_t>(gas),
    //     .recipient = destination,
    //     .sender = *txn.from,
    //     .input_data = txn.data.data(),
    //     .input_size = txn.data.size(),
    //     .value = intx::be::store<evmc::uint256be>(txn.value),
    //     .code_address = destination,
    // }

    // silkworm::Transaction txn{};
    // txn.from = addr;
    // txn.to = addr;
    // txn.value = value;
    // txn.data = code;
    // txn.gas_limit = 1000;
    // // msg.flags = 0;
    // // msg.depth = 0; // 1024    

    evmc_address addr = {{0, 1, 2}};
    evmc_message msg{};
    msg.flags = 0;
    msg.depth = 0; // 1024
    // msg.gas = 9223372036854775806;
    msg.gas = 1000;
    msg.sender = addr;
    msg.recipient = addr;
    
    // silkworm::EvmHost host{*vm};
    // auto host = evmone::state::Host{};
    // evmone::VM *vm = new evmone::VM{};
    
    // TODO: change to new API
    if (*debug_mode)
        auto tracer = new evmone::Tracer{};
        vm->add_tracer(tracer);
        // printf("evmone trace: %d\n", vm.set_option("trace", ""));

    // printf("TEST\n");
    // evmc_tx_context context = host.get_tx_context();
    // printf("TEST\n");
    // context.tx_gas_price = evmc::uint256be{100000000000000}; // = 0x5af3107a4000
    // printf("TEST\n");
    // context.tx_origin = addr;
    // printf("TEST\n");
    // context.block_coinbase = evmc_address{{0, 0, 0}};
    // printf("TEST\n");
    // context.block_number = 12965000; // london
    // printf("TEST\n");
    // context.block_timestamp = 0;
    // printf("TEST\n");
    // context.block_gas_limit = 7992222;
    // printf("TEST\n");
    // context.chain_id = evmc::uint256be{1};
    // printf("TEST\n");

    // silkworm::CallResult result{vm.execute(txn, GAS)};
    evmc::Result result = host.call(msg);

    // evmc::Result result = vm.execute(host, EVMC_LONDON, msg, data2, data_size);
    // TODO: where Fork id, data and data size?
    // evmc::Result result = host.call(msg);
    // evmone::hash256 stateRoot = host::stateRoot();
    // printBytesAsHex("StateRoot", stateRoot, sizeof(stateRoot));
    //
    free((void *)data2);

    if (result.status_code != EVMC_SUCCESS) {
        result.gas_left = GAS;
    }

    if (result.gas_left == gas && gas > 0) {
        return 0;
    }

    if (result.gas_left != gas) {
        // std::cout << "Not the same Gas! GETH: " << gas << ", EVMONE: " << result.gas_left << std::endl; 
        return 1;
    } 

    return 0;
}
