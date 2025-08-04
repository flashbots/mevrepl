package mev

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/flashbots/go-utils/rpcclient"
	"github.com/flashbots/go-utils/rpctypes"
	"github.com/flashbots/go-utils/signature"
)

const (
	SepoliaNetwork = "sepolia"
	Mainnet        = "mainnet"

	SepoliaChainID = 11155111
	MainnetChainID = 1
)

const (
	defaultAPIVersion     = "v0.1"
	defaultValidityBlocks = 25
)

const (
	FlashbotsMainnetRPC      = "https://rpc.flashbots.net"
	FlashbotsMainnetRelay    = "http://localhost:8080/api"
	FlashbotsMainnetMEVShare = "https://mev-share.flashbots.net"
	FlashbotsMainnetProtect  = "https://protect.flashbots.net"

	FlashbotsSepoliaRPC      = "https://rpc-sepolia.flashbots.net"
	FlashbotsSepoliaRelay    = "https://relay-sepolia.flashbots.net"
	FlashbotsSepoliaMEVShare = "https://mev-share-sepolia.flashbots.net"
	FlashbotsSepoliaProtect  = "https://protect-sepolia.flashbots.net"
)

var ErrUnsupportedNetwork = errors.New("unsupported network")

type BundleOpts struct {
	ValidityBlocks uint64
}

type Client struct {
	ChainID *big.Int

	FlashbotsRPC   *ethclient.Client
	FlashbotsRelay rpcclient.RPCClient

	FlashbotsMEVShareURL string
	FlashbotsProtectURL  string

	key *ecdsa.PrivateKey

	httpClient *http.Client
}

func ConstructClient(privateKey *ecdsa.PrivateKey, network string, chainID *big.Int, sendTxOpts string, httpClient *http.Client) (*Client, error) {
	var (
		flashbotsRPCURL      string
		flashbotsRelayURL    string
		flashbotsMEVShareURL string
		flashbotsProtectURL  string
	)
	switch network {
	case Mainnet:
		flashbotsRPCURL = FlashbotsMainnetRPC
		flashbotsRelayURL = FlashbotsMainnetRelay
		flashbotsMEVShareURL = FlashbotsMainnetMEVShare
		flashbotsProtectURL = FlashbotsMainnetProtect
	case SepoliaNetwork:
		flashbotsRPCURL = FlashbotsSepoliaRPC
		flashbotsRelayURL = FlashbotsSepoliaRelay
		flashbotsMEVShareURL = FlashbotsSepoliaMEVShare
		flashbotsProtectURL = FlashbotsSepoliaProtect
	default:
		return nil, ErrUnsupportedNetwork
	}

	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	flashbotsRPCClient, err := ethclient.Dial(flashbotsRPCURL + "/" + sendTxOpts)
	if err != nil {
		return nil, err
	}

	signer := signature.NewSigner(privateKey)
	relayClient := rpcclient.NewClientWithOpts(flashbotsRelayURL, &rpcclient.RPCClientOpts{Signer: &signer})

	return &Client{
		FlashbotsRPC:         flashbotsRPCClient,
		ChainID:              chainID,
		FlashbotsRelay:       relayClient,
		key:                  privateKey,
		FlashbotsMEVShareURL: flashbotsMEVShareURL,
		FlashbotsProtectURL:  flashbotsProtectURL,
		httpClient:           httpClient,
	}, nil
}

func (c *Client) CreateBundle(originalHash common.Hash, block uint64, opts *BundleOpts, backrunTxs ...*types.Transaction) (*rpctypes.MevSendBundleArgs, error) {
	if len(backrunTxs) == 0 {
		return nil, nil
	}

	if opts == nil {
		opts = &BundleOpts{ValidityBlocks: defaultValidityBlocks}
	}

	// todo: think about this part
	inclusion := rpctypes.MevBundleInclusion{
		BlockNumber: hexutil.Uint64(block + 1),
		MaxBlock:    hexutil.Uint64(block + opts.ValidityBlocks),
	}

	bundle := &rpctypes.MevSendBundleArgs{
		Version:   defaultAPIVersion,
		Inclusion: inclusion,
		Body: []rpctypes.MevBundleBody{
			{
				Hash: &originalHash,
			},
		},
		// Privacy: nil,
	}

	for _, tx := range backrunTxs {
		binaryTx, err := tx.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal binary tx: tx_hash: %v error %w", tx.Hash(), err)
		}
		bundle.Body = append(bundle.Body, rpctypes.MevBundleBody{
			Tx:         (*hexutil.Bytes)(&binaryTx),
			RevertMode: rpctypes.RevertModeFail,
		})
	}

	return bundle, nil
}

func (c *Client) SendBundle(ctx context.Context, bundle *rpctypes.MevSendBundleArgs) (*SendMevBundleResponse, error) {
	var bundleResp SendMevBundleResponse
	err := c.FlashbotsRelay.CallFor(ctx, &bundleResp, "mev_sendBundle", bundle)
	if err != nil {
		return nil, fmt.Errorf("failed to call mev_sendBundle error %w", err)
	}

	return &bundleResp, nil
}

func (c *Client) SimulateBundle(ctx context.Context, bundle *rpctypes.MevSendBundleArgs) (*SimulateBundleResponse, error) {
	var bundleSimResp SimulateBundleResponse
	err := c.FlashbotsRelay.CallFor(ctx, &bundleSimResp, "mev_simBundle", bundle)
	if err != nil {
		return nil, fmt.Errorf("failed to call mev_sendBundle error %w", err)
	}

	return &bundleSimResp, nil
}

func (c *Client) CancelBundle(ctx context.Context, hash common.Hash) error {
	err := c.FlashbotsRelay.CallFor(ctx, &hash, "mev_cancelBundleByHash")
	if err != nil {
		return fmt.Errorf("failed to call mev_cancelBundleByHash error %w", err)
	}

	return nil
}

func (c *Client) SendPrivateTx(ctx context.Context, tx *types.Transaction) error {
	return c.FlashbotsRPC.SendTransaction(ctx, tx)
}

func (c *Client) SendPrivateRelayTx(ctx context.Context, tx *types.Transaction) (hexutil.Bytes, error) {
	var resp hexutil.Bytes

	bts, err := tx.MarshalBinary()
	if err != nil {
		return nil, err
	}
	rtx := (*hexutil.Bytes)(&bts)
	err = c.FlashbotsRelay.CallFor(ctx, &resp, "eth_sendPrivateRawTransaction", rtx)
	return resp, err
}

func (c *Client) GetTxStatus(ctx context.Context, txHash common.Hash) (TxStatus, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.FlashbotsProtectURL+"/tx/"+txHash.String(), nil)
	if err != nil {
		panic(fmt.Errorf("failed to create http request error %w", err))
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return TxStatus{}, fmt.Errorf("failed to send protect txStatus request error %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return TxStatus{}, fmt.Errorf("request failed. Status not 200")
	}

	var txStatus TxStatus
	if err := json.NewDecoder(resp.Body).Decode(&txStatus); err != nil {
		return TxStatus{}, fmt.Errorf("failed to unmarshal txStatus error %w", err)
	}

	return txStatus, nil
}
