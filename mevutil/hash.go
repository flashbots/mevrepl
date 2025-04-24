package mevutil

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"golang.org/x/crypto/sha3"
)

// DoubleTxHash makes a keccak256 hash of original txHash
//
// For more details:
// https://docs.flashbots.net/flashbots-mev-share/searchers/event-stream#understanding-double-hash
func DoubleTxHash(txHash common.Hash) (common.Hash, error) {
	h, err := keccak256(txHash.Bytes())
	if err != nil {
		return [32]byte{}, fmt.Errorf("failed to make keccak256 error %w", err)
	}

	return common.BytesToHash(h), nil
}

func keccak256(data []byte) ([]byte, error) {
	h := sha3.NewLegacyKeccak256()
	if _, err := h.Write(data); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}
