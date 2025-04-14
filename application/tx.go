package application

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"log"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/flashbots/go-utils/rpctypes"
	"golang.org/x/crypto/sha3"
)

type SendMevBundleResponse struct {
	BundleHash common.Hash `json:"bundleHash"`
}

var WETH = common.HexToAddress("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")

func (mc *MevClient) CreateWrapETH(value *big.Int, priorityFee *big.Int, sender *ecdsa.PrivateKey) (*types.Transaction, error) {
	key := mc.key
	if sender != nil {
		key = sender
	}
	lastBlock, err := mc.publicRPC.BlockByNumber(context.Background(), nil)
	if err != nil {
		return nil, fmt.Errorf("error querying block by number: %w", err)
	}

	address := crypto.PubkeyToAddress(key.PublicKey)
	nonce, err := mc.flashbotsRPC.PendingNonceAt(context.Background(), address)
	if err != nil {
		return nil, fmt.Errorf("error querying pending nonce: %w", err)
	}

	signer := types.LatestSignerForChainID(mc.chainID)
	gasPrice := lastBlock.BaseFee()
	baseFeeFuture := new(big.Int).Mul(gasPrice, big.NewInt(110))
	baseFeeFuture = new(big.Int).Div(baseFeeFuture, big.NewInt(100))

	gasLimit := 29000

	var gasTipCap *big.Int
	if priorityFee != nil {
		gasTipCap = priorityFee
	} else {
		gasTipCap = big.NewInt(1)
	}
	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   mc.chainID,
		Nonce:     nonce,
		GasFeeCap: baseFeeFuture,
		GasTipCap: gasTipCap,
		Gas:       uint64(gasLimit),
		To:        &WETH,
		Value:     value,
	})

	tx1, err := types.SignTx(tx, signer, key)
	if err != nil {
		return nil, err
	}
	return tx1, nil
}

func (mc *MevClient) SendBackrun(ctx context.Context, originalTx *types.Transaction, sender *ecdsa.PrivateKey) (*SendMevBundleResponse, error) {
	blockNumber, err := mc.flashbotsRPC.BlockNumber(context.Background())
	if err != nil {
		return nil, err
	}
	backrunTx, err := mc.CreateWrapETH(big.NewInt(11), big.NewInt(15), sender)
	if err != nil {
		return nil, err
	}
	backrunTxBytes, err := backrunTx.MarshalBinary()
	if err != nil {
		log.Fatal(err)
	}
	inclusion := rpctypes.MevBundleInclusion{
		BlockNumber: hexutil.Uint64(blockNumber + 1),
		MaxBlock:    hexutil.Uint64(blockNumber + 10),
	}

	// originalTx *types.Transaction
	matchingHasher := sha3.NewLegacyKeccak256()
	matchingHasher.Write(originalTx.Hash().Bytes()[:])
	matchingHash := common.BytesToHash(matchingHasher.Sum(nil))

	sba := &rpctypes.MevSendBundleArgs{
		Version:   "v0.1",
		Inclusion: inclusion,
		Body: []rpctypes.MevBundleBody{
			{
				Hash: &matchingHash,
			},
			{
				Tx:         (*hexutil.Bytes)(&backrunTxBytes),
				RevertMode: rpctypes.RevertModeDrop,
			},
		},
		//Privacy: &rpctypes.Me{},
	}
	var decoded SendMevBundleResponse
	err = mc.flashbotsRelay.CallFor(ctx, &decoded, "mev_sendBundle", sba)
	if err != nil {
		return nil, err
	}

	return &decoded, nil
}

func (mc *MevClient) SendPrivateTx(ctx context.Context, tx *types.Transaction) error {
	return mc.flashbotsRPC.SendTransaction(ctx, tx)
}
