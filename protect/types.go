package protect

import (
	"encoding/json"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
)

type SendMevBundleResponse struct {
	BundleHash common.Hash `json:"bundleHash"`
	Smart      bool        `json:"smart,omitempty"`
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

type CallBundleArgs struct {
	Txs              []string `json:"txs"`              // Array[String], A list of signed transactions to execute in an atomic bundle
	BlockNumber      string   `json:"blockNumber"`      // String, a hex encoded block number for which this bundle is valid on
	StateBlockNumber string   `json:"stateBlockNumber"` // String, either a hex encoded number or a block tag for which state to base this simulation on. Can use "latest"
	Timestamp        *uint64  `json:"timestamp"`        // (Optional) Number, the timestamp to use for this bundle simulation, in seconds since the unix epoch
}

type SendPrivateTxArgs struct {
	Tx             string          `json:"tx"`             // String, raw signed transaction
	MaxBlockNumber json.RawMessage `json:"maxBlockNumber"` // Hex-encoded number string, optional. Highest block number in which the transaction should be included. For backwards compatibility can be an int.
	// Preferences    PrivateTxPreferences `json:"preferences"`
}

type SendBundleArgs struct {
	Txs               []string      // Array[String], A list of signed transactions to execute in an atomic bundle
	BlockNumber       string        // String, a hex encoded block number for which this bundle is valid on
	ReplacementUuid   string        // (Optional) uuid-formatted String, used to replace previous bundles
	MinTimestamp      *uint64       // (Optional) Number, the minimum timestamp for which this bundle is valid, in seconds since the unix epoch
	MaxTimestamp      *uint64       // (Optional) Number, the maximum timestamp for which this bundle is valid, in seconds since the unix epoch
	RevertingTxHashes []common.Hash // (Optional) Array[String], A list of tx hashes that are allowed to revert
	Builders          []string
}

type TxPrivacyPreferences struct {
	Builders       []string `json:"builders,omitempty"`
	AllowBob       bool     `json:"allowBob,omitempty"`
	MempoolRPC     string   `json:"mempoolRpc"`
	AuctionTimeout uint64   `json:"auctionTimeout,omitempty"`
}

type PrivateTxPreferences struct {
	Privacy TxPrivacyPreferences `json:"privacy"`
	// Validity   TxValidityPreferences `json:"validity"`
	Fast       bool `json:"fast"` // NOTE: it does nothing when set directly, it is only used for reporting by rpc-endpoint
	CanRevert  bool `json:"canRevert"`
	BlockRange int  `json:"blockRange"`
}

type CancelPrivateTxArgs struct {
	TxHash common.Hash // String, transaction hash of private tx to be cancelled
}

type CancelETHBundleArgs struct {
	ReplacementUuid string // uuid-formatted String, all bundles provided with that uuid will be cancelled
	Builders        []string
}
