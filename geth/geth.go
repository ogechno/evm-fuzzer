package main

import "C"

import (
	"fmt"
	"math/big"
    "encoding/hex"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params"
)

// var caller = common.HexToAddress("2122334455667788991011121314151617181920")
var caller = common.HexToAddress("0001020000000000000000000000000000000000")
// var addr = common.HexToAddress("1122334455667788991011121314151617181920")
var addr = common.HexToAddress("0001020000000000000000000000000000000000")
var londonBlock = big.NewInt(12_965_000);

func build_vm_config() vm.Config {

//	tracer, err := tracers.New("", new(tracers.Context))
    // tracer := logger.NewStructLogger(&logger.Config{
	// 	Debug: false,
	// 	//DisableStorage: true,
	// 	//EnableMemory: false,
	// 	//EnableReturnData: false,
	// })
	config := vm.Config{
		Debug: false,
		Tracer:                  nil, // tracer,
		EnablePreimageRecording: false,
	}
	return config
}

func build_state_db(bytecode []byte) vm.StateDB {
	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	statedb.SetBalance(addr, big.NewInt(int64(0)))
	statedb.SetCode(addr, bytecode)
	statedb.SetNonce(addr, 0)

	return statedb
}

func build_context() vm.BlockContext {
	transfer := func(db vm.StateDB, sender, recipient common.Address, amount *big.Int) {}
    initialCall := true
    canTransfer := func(db vm.StateDB, address common.Address, amount *big.Int) bool {
		if initialCall {
			initialCall = false
			return true
		}
		return core.CanTransfer(db, address, amount)
	}
    vmTestBlockHash := func(n uint64) common.Hash {
	    return common.BytesToHash(crypto.Keccak256([]byte(big.NewInt(int64(n)).String())))
    }

    context := vm.BlockContext{
		CanTransfer: canTransfer,
		Transfer:    transfer,
		GetHash:     vmTestBlockHash,
        Coinbase:    common.BytesToAddress(make([]byte, 20)),
		BlockNumber: londonBlock,
        // Time: big.NewInt(time.Now().Unix()),
        Time: new(big.Int).SetUint64(0),
		GasLimit:    7992222,
		Difficulty:  new(big.Int).SetUint64(0),
        BaseFee:     big.NewInt(params.InitialBaseFee),
	}
	return context
}

func build_txContext() vm.TxContext {
	txContext := vm.TxContext{
		Origin:   caller,
		GasPrice: new(big.Int).SetUint64(0x5af3107a4000),
	}
	return txContext
}

//export ExecuteTestcase
// returns gas left
func ExecuteTestcase(bytecode []byte) uint64 {
    // gas := uint64(9223372036854775806)
    gas := uint64(1000)
    // fmt.Printf("The Code: %v\n", bytecode)

	vmctx := build_context()
	txContext := build_txContext()
	statedb := build_state_db(bytecode)
	vmConfig := build_vm_config()

    // TODO: Maybe do ones in inititlize
	evm := vm.NewEVM(vmctx, txContext, statedb, params.MainnetChainConfig, vmConfig)
    // fmt.Printf("Chain Config: %v\n", params.MainnetChainConfig.IsLondon(londonBlock))
    // fmt.Printf("Chain Config: %v\n", params.MainnetChainConfig.Rules(londonBlock, false).IsLondon)

    if rules := params.MainnetChainConfig.Rules(londonBlock, evm.Context.Random != nil); rules.IsBerlin {
		statedb.PrepareAccessList(caller, &addr, vm.ActivePrecompiles(rules), nil)
	}
    
	var emptyInput []byte
    // TODO: Maybe also Fuzz Create and Execute
	_, leftOver, err := evm.Call(vm.AccountRef(caller), addr, emptyInput, gas, big.NewInt(int64(0)))

	//TODO: work with the output of evm.Call
	if err != nil {
		// fmt.Printf("GETH Error: %s\n", err) 
        // fmt.Printf("GETH Gas Return is: %d\n", gas)
		return gas // Bad input, ignore unless more coverage
	} else {
		// fmt.Printf("leftOver: %d\n", leftOver)
        // fmt.Printf("Gas used: %d\n", gas - leftOver)
		return leftOver
	}
}

//export Fuzz
func Fuzz(data []byte) uint64 {
    leftGas := ExecuteTestcase(data)
	return leftGas
}

func main() {
    code := []byte{48, 49}
    hexcode := hex.EncodeToString(code)
    fmt.Println("Hexcode: %v", hexcode)
    ExecuteTestcase(code)
}
