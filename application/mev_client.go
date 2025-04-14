package application

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/flashbots/go-utils/rpcclient"
	"github.com/flashbots/go-utils/signature"
)

type MevClient struct {
	publicRPC      *ethclient.Client
	flashbotsRPC   *ethclient.Client
	flashbotsRelay rpcclient.RPCClient
	chainID        *big.Int
	key            *ecdsa.PrivateKey
}

func ConstructMevClient(privateKey *ecdsa.PrivateKey, network string, urlConfig string) (*MevClient, error) {
	if network != "mainnet" && network != "sepolia" {
		return nil, errors.New("invalid network")
	}
	if network == "mainnet" {
		publicRPC := "https://eth.llamarpc.com"
		publicClient, err := ethclient.Dial(publicRPC)
		if err != nil {
			return nil, err
		}

		flashbotsRPC := "https://rpc.flashbots.net/" + urlConfig
		flashbotsClient, err := ethclient.Dial(flashbotsRPC)
		if err != nil {
			return nil, err
		}
		signer := signature.NewSigner(privateKey)

		rpcCl := rpcclient.NewClientWithOpts("https://relay.flashbots.net", &rpcclient.RPCClientOpts{Signer: &signer})

		chainID, err := publicClient.ChainID(context.Background())
		if err != nil {
			return nil, err
		}

		return &MevClient{
			publicRPC:      publicClient,
			flashbotsRPC:   flashbotsClient,
			chainID:        chainID,
			flashbotsRelay: rpcCl,
			key:            privateKey,
		}, nil
	}
	publicRPC := "https://eth-sepolia.public.blastapi.io"
	publicClient, err := ethclient.Dial(publicRPC)
	if err != nil {
		return nil, err
	}

	flashbotsRPC := "https://rpc-sepolia.flashbots.net/" + urlConfig
	flashbotsClient, err := ethclient.Dial(flashbotsRPC)
	if err != nil {
		return nil, err
	}
	signer := signature.NewSigner(privateKey)

	rpcCl := rpcclient.NewClientWithOpts("https://relay-sepolia.flashbots.net", &rpcclient.RPCClientOpts{Signer: &signer})

	chainID, err := publicClient.ChainID(context.Background())
	if err != nil {
		return nil, err
	}

	return &MevClient{
		publicRPC:      publicClient,
		flashbotsRPC:   flashbotsClient,
		chainID:        chainID,
		flashbotsRelay: rpcCl,
		key:            privateKey,
	}, nil

}
