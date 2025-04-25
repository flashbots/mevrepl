package mev

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
)

type SendMevBundleResponse struct {
	BundleHash common.Hash `json:"bundleHash"`
}

type SimulateBundleResponse struct {
	Success         bool             `json:"success"`
	Error           string           `json:"error,omitempty"`
	StateBlock      hexutil.Uint64   `json:"stateBlock"`
	MevGasPrice     hexutil.Big      `json:"mevGasPrice"`
	Profit          hexutil.Big      `json:"profit"`
	RefundableValue hexutil.Big      `json:"refundableValue"`
	GasUsed         hexutil.Uint64   `json:"gasUsed"`
	BodyLogs        []SimMevBodyLogs `json:"logs,omitempty"`
	ExecError       string           `json:"execError,omitempty"`
	Revert          hexutil.Bytes    `json:"revert,omitempty"`
}

type SimMevBodyLogs struct {
	TxLogs     []*types.Log     `json:"txLogs,omitempty"`
	BundleLogs []SimMevBodyLogs `json:"bundleLogs,omitempty"`
}

type Hint struct {
	Hash        common.Hash     `json:"hash"`
	Txs         []TxHint        `json:"txs"`
	Logs        []Log           `json:"logs"`
	MevGasPrice *hexutil.Big    `json:"mevGasPrice,omitempty"`
	GasUsed     *hexutil.Uint64 `json:"gasUsed,omitempty"`
}

type TxHint struct {
	Hash                 *common.Hash        `json:"hash,omitempty"`
	To                   *common.Address     `json:"to,omitempty"`
	FunctionSelector     *hexutil.Bytes      `json:"functionSelector,omitempty"`
	CallData             *hexutil.Bytes      `json:"callData,omitempty"`
	ChainID              *hexutil.Big        `json:"chainId,omitempty"`
	Value                *hexutil.Big        `json:"value,omitempty"`
	AccessList           []types.AccessTuple `json:"accessList,omitempty"`
	Nonce                *hexutil.Uint64     `json:"nonce,omitempty"`
	MaxPriorityFeePerGas *hexutil.Big        `json:"maxPriorityFeePerGas,omitempty"`
	MaxFeePerGas         *hexutil.Big        `json:"maxFeePerGas,omitempty"`
	Gas                  *hexutil.Uint64     `json:"gas,omitempty"`
	Type                 *hexutil.Uint64     `json:"type,omitempty"`
	From                 *common.Address     `json:"from,omitempty"`
}

type Log struct {
	// address of the contract that generated the event
	Address common.Address `json:"address"`
	// list of topics provided by the contract.
	Topics []common.Hash `json:"topics"`
	// supplied by the contract, usually ABI-encoded
	Data hexutil.Bytes `json:"data"`
}

type TxStatus struct {
	Status         string      `json:"status"`
	Hash           common.Hash `json:"hash"`
	MaxBlockNumber uint64      `json:"maxBlockNumber"`
	FastMode       bool        `json:"fastMode"`
	IsRevert       bool        `json:"isRevert"`
	SeenInMempool  bool        `json:"seenInMempool"`
}
