#include <iostream>
#include <limits>

#include <evmc/mocked_host.hpp>
#include <evmc/instructions.h>
#include <evmone/evmone.h>
#include <evmone/tracing.hpp>
#include <evmone/vm.hpp>

#include <silkworm/core/execution/evm.hpp>
#include <silkworm/core/state/in_memory_state.hpp>
#include <silkworm/core/state/intra_block_state.hpp>
#include <silkworm/core/common/cast.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/common/base.hpp>

#include <signal.h>
#include <unistd.h>
#include <atomic>

// Add this line at the beginning of the file
extern "C" void __llvm_profile_dump(void);

// // #include <atomic>
// // 
// // std::atomic<bool> profile_dumped(false);
// // 
// // extern "C" void sigterm_handler(int sig) {
// //     if (!profile_dumped.exchange(true)) {
// //         __llvm_profile_dump();
// //     }
// //     _exit(sig);
// // }
// 
// // Add this signal handler function
// extern "C" void sigint_handler(int sig) {
//     std::cerr << "Signal handler triggered with signal " << sig << std::endl;
//     __llvm_profile_dump();
//     _exit(sig);
// }
// 
// // Add this function at the end of the file
// extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
//     // signal(SIGINT, sigint_handler);
//     // signal(SIGTERM, sigterm_handler);
//     // signal(SIGKILL, sigint_handler);
//     // atexit(__llvm_profile_dump);
//     return 0;
// }


std::atomic<bool> profile_dumped(false);
std::atomic<bool> handler_executed(false);

extern "C" void sigterm_handler(int sig) {
    std::cerr << "Signal handler triggered with signal " << sig << std::endl;
    
    if (!handler_executed.exchange(true)) {
        if (!profile_dumped.exchange(true)) {
            std::cerr << "Dumping profile data..." << std::endl;
            __llvm_profile_dump();
        }
        _exit(sig);
    } else {
        std::cerr << "Signal handler already executed, skipping..." << std::endl;
    }
}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    std::cerr << "Initializing fuzzer..." << std::endl;
    signal(SIGTERM, sigterm_handler);
    return 0;
}

// #include <silkworm/silkrpc/core/evm_trace.hpp>

#include "geth/libgeth.h"

#define GAS 1000

extern "C" {
    int* get_debug_mode();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t data_size) noexcept {
    int* debug_mode = get_debug_mode();

    uint8_t *data2 = (uint8_t *)malloc(data_size);
    memcpy((void*)data2, (void*)data, data_size);

    GoSlice goData = {(void *) data, (long long) data_size, (long long) data_size};
    GoInt debug = *debug_mode;
    GoInt gas = Fuzz(goData, debug);
    
    evmc_address addr = {{0, 1, 2}};

    silkworm::Block block{};
    block.header.number = 12965000;

    silkworm::InMemoryState db;
    silkworm::IntraBlockState state{db};
    // std::cout << silkworm::to_hex(db.state_root_hash()) << std::endl;

    silkworm::ByteView code_bytes{data, data_size};
    state.set_nonce(addr, 0);
    state.set_balance(addr, intx::uint256(0));
    state.set_code(addr, code_bytes);
    
    silkworm::EVM vm{block, state, silkworm::kMainnetConfig};
    silkworm::EvmHost host{vm};

    silkworm::Transaction txn{};
    txn.from = addr;
    txn.to = addr;

    
    // TODO: change to new API
    // if (*debug_mode) {
    //     auto tracer = new silkworm::rpc::trace::VmTraceTracer{};
    //     vm.add_tracer(tracer);
    // }

    silkworm::CallResult result{vm.execute(txn, GAS)};
    
    // std::cout << silkworm::to_hex(db.state_root_hash()) << std::endl;

    free((void *)data2);

    if (result.status != EVMC_SUCCESS) {
        result.gas_left = GAS;
    }

    if (result.gas_left == gas && gas > 0) {
        return 0;
    }

    if (result.gas_left != gas) {
        std::cout << "Not the same Gas! GETH: " << gas << ", EVMONE: " << result.gas_left << std::endl; 
        return 1;
    } 

    return 0;
}
