#include <iostream>
#include <limits>

#include <evmc/mocked_host.hpp>
#include <evmc/instructions.h>
#include <evmone/evmone.h>
#include <evmone/tracing.hpp>
#include <evmone/vm.hpp>
#include <evmone/instructions_traits.hpp>

#include <silkworm/core/execution/evm.hpp>
#include <silkworm/core/state/in_memory_state.hpp>
#include <silkworm/core/state/intra_block_state.hpp>
#include <silkworm/core/common/cast.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/common/base.hpp>
#include <silkworm/core/execution/evm.hpp>

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

class TestTracer : public silkworm::EvmTracer {
  public:
    explicit TestTracer(std::optional<evmc::address> contract_address = std::nullopt,
                        std::optional<evmc::bytes32> key = std::nullopt)
        : contract_address_(contract_address), key_(key), rev_{}, msg_{} {}

    std::string get_name(uint8_t opcode) {
        // TODO: Create constexpr tables of names (maybe even per revision).
        const auto name = evmone::instr::traits[opcode].name;
        return (name != nullptr) ? name : "0x" + evmc::hex(opcode);
    }

    void output_stack(const intx::uint256* stack_top, int stack_height) {
        std::cout << R"(,"stack":[)";
        const auto stack_end = stack_top + 1;
        const auto stack_begin = stack_end - stack_height;
        for (auto it = stack_begin; it != stack_end; ++it)
        {
            if (it != stack_begin)
                std::cout << ',';
            std::cout << R"("0x)" << to_string(*it, 16) << '"';
        }
        std::cout << ']';
    }

    void on_execution_start(evmc_revision rev, const evmc_message& msg, evmone::bytes_view bytecode) noexcept override {
        execution_start_called_ = true;
        rev_ = rev;
        msg_ = msg;
        bytecode_ = silkworm::Bytes{bytecode};

        std::cout << "{";
        std::cout << R"("depth":)" << msg.depth;
        std::cout << R"(,"rev":")" << rev << '"';
        std::cout << R"(,"static":)" << (((msg.flags & EVMC_STATIC) != 0) ? "true" : "false");
        std::cout << "}\n";
    }
    void on_instruction_start(uint32_t pc, const intx::uint256* stack_top, int stack_height,
                              const evmone::ExecutionState& state,
                              const silkworm::IntraBlockState& intra_block_state) noexcept override {
        pc_stack_.push_back(pc);
        memory_size_stack_[pc] = state.memory.size();
        if (contract_address_) {
            storage_stack_[pc] =
                intra_block_state.get_current_storage(contract_address_.value(), key_.value_or(evmc::bytes32{}));
        }

        evmc_address addr = {{0, 1, 2}};
        auto opcode = intra_block_state.get_code(addr)[pc];

        std::cout << "{";
        std::cout << R"("pc":)" << std::dec << pc;
        std::cout << R"(,"op":)" << std::dec << int{opcode};
        std::cout << R"(,"opName":")" << get_name(opcode) << '"';
        std::cout << R"(,"gas":)" << std::hex << "0x" << state.gas_left;
        output_stack(stack_top, stack_height);

        // Full memory can be dumped as evmc::hex({state.memory.data(), state.memory.size()}),
        // but this should not be done by default. Adding --tracing=+memory option would be nice.
        std::cout << R"(,"memorySize":)" << std::dec << state.memory.size();

        std::cout << "}\n";
    }
    void on_execution_end(const evmc_result& res, const silkworm::IntraBlockState& intra_block_state) noexcept override {
        execution_end_called_ = true;
        const auto gas_left = static_cast<uint64_t>(res.gas_left);
        const auto gas_refund = static_cast<uint64_t>(res.gas_refund);
        result_ = {res.status_code, gas_left, gas_refund, {res.output_data, res.output_size}};
        if (contract_address_ && !pc_stack_.empty()) {
            const auto pc = pc_stack_.back();
            storage_stack_[pc] =
                intra_block_state.get_current_storage(contract_address_.value(), key_.value_or(evmc::bytes32{}));
        }
    }

    void on_creation_completed(const evmc_result& /*result*/, const silkworm::IntraBlockState& /*intra_block_state*/) noexcept override {
        creation_completed_called_ = true;
    }

    void on_precompiled_run(const evmc_result& /*result*/, int64_t /*gas*/,
                            const silkworm::IntraBlockState& /*intra_block_state*/) noexcept override {}
    void on_reward_granted(const silkworm::CallResult& /*result*/,
                           const silkworm::IntraBlockState& /*intra_block_state*/) noexcept override {}

    [[nodiscard]] bool execution_start_called() const { return execution_start_called_; }
    [[nodiscard]] bool execution_end_called() const { return execution_end_called_; }
    [[nodiscard]] bool creation_completed_called() const { return creation_completed_called_; }
    [[nodiscard]] const silkworm::Bytes& bytecode() const { return bytecode_; }
    [[nodiscard]] const evmc_revision& rev() const { return rev_; }
    [[nodiscard]] const evmc_message& msg() const { return msg_; }
    [[nodiscard]] const std::vector<uint32_t>& pc_stack() const { return pc_stack_; }
    [[nodiscard]] const std::map<uint32_t, std::size_t>& memory_size_stack() const { return memory_size_stack_; }
    [[nodiscard]] const std::map<uint32_t, evmc::bytes32>& storage_stack() const { return storage_stack_; }
    [[nodiscard]] const silkworm::CallResult& result() const { return result_; }

  private:
    bool execution_start_called_{false};
    bool execution_end_called_{false};
    bool creation_completed_called_{false};
    std::optional<evmc::address> contract_address_;
    std::optional<evmc::bytes32> key_;
    evmc_revision rev_;
    evmc_message msg_;
    silkworm::Bytes bytecode_;
    std::vector<uint32_t> pc_stack_;
    std::map<uint32_t, std::size_t> memory_size_stack_;
    std::map<uint32_t, evmc::bytes32> storage_stack_;
    silkworm::CallResult result_;
};

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    std::cerr << "Initializing fuzzer..." << std::endl;
    signal(SIGTERM, sigterm_handler);
    return 0;
}

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
    
    silkworm::EVM evm{block, state, silkworm::kMainnetConfig};
    silkworm::EvmHost host{evm};

    silkworm::Transaction txn{};
    txn.from = addr;
    txn.to = addr;
    
    // TODO: change to new API
    if (*debug_mode) {
        printf("EVMONE Trace:\n");
        TestTracer tracer;
        evm.add_tracer(tracer);
    }

    silkworm::CallResult result{evm.execute(txn, GAS)};
    
    // std::cout << silkworm::to_hex(db.state_root_hash()) << std::endl;
 
    free((void *)data2);

    if (result.status != EVMC_SUCCESS) {
        // std::cout << "EVMC NO SUCCESS: " << result.status << std::endl;
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
