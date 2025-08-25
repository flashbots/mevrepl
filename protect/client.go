package protect

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
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
	FlashbotsMainnetRelay    = "https://relay.flashbots.net"
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

type ClientOpts struct {
	RPCOpts          string
	HTTPClient       *http.Client
	FlashbotsRPC     string
	FlashbotsRelay   string
	FlashbotsProtect string
}

func ConstructClient(privateKey *ecdsa.PrivateKey, network string, opts *ClientOpts) (*Client, error) {
	if opts == nil {
		opts = &ClientOpts{
			RPCOpts:    "fast",
			HTTPClient: http.DefaultClient,
		}
	}
	var (
		flashbotsRPCURL      string
		flashbotsRelayURL    string
		flashbotsMEVShareURL string
		flashbotsProtectURL  string

		chainID *big.Int
	)
	switch network {
	case Mainnet:
		flashbotsRPCURL = FlashbotsMainnetRPC
		flashbotsRelayURL = FlashbotsMainnetRelay
		flashbotsMEVShareURL = FlashbotsMainnetMEVShare
		flashbotsProtectURL = FlashbotsMainnetProtect
		chainID = big.NewInt(MainnetChainID)
	case SepoliaNetwork:
		flashbotsRPCURL = FlashbotsSepoliaRPC
		flashbotsRelayURL = FlashbotsSepoliaRelay
		flashbotsMEVShareURL = FlashbotsSepoliaMEVShare
		flashbotsProtectURL = FlashbotsSepoliaProtect
		chainID = big.NewInt(SepoliaChainID)
	default:
		return nil, ErrUnsupportedNetwork
	}

	if opts.FlashbotsProtect != "" {
		flashbotsProtectURL = opts.FlashbotsProtect
	}

	if opts.FlashbotsRPC != "" {
		flashbotsRPCURL = opts.FlashbotsRPC
	}

	if opts.FlashbotsRelay != "" {
		flashbotsRelayURL = opts.FlashbotsRelay
	}

	if opts.HTTPClient == nil {
		opts.HTTPClient = http.DefaultClient
	}

	flashbotsRPCClient, err := ethclient.Dial(flashbotsRPCURL + "/" + opts.RPCOpts)
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
		httpClient:           opts.HTTPClient,
	}, nil
}

func (c *Client) CreateMEVBundle(originalHash common.Hash, block uint64, opts *BundleOpts, backrunTxs ...*types.Transaction) (*rpctypes.MevSendBundleArgs, error) {
	if len(backrunTxs) == 0 {
		return nil, nil
	}

	if opts == nil {
		opts = &BundleOpts{ValidityBlocks: defaultValidityBlocks}
	}

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

func (c *Client) SendMEVBundle(ctx context.Context, bundle *rpctypes.MevSendBundleArgs) (*SendMevBundleResponse, error) {
	var bundleResp SendMevBundleResponse
	err := c.FlashbotsRelay.CallFor(ctx, &bundleResp, "mev_sendBundle", bundle)
	if err != nil {
		return nil, fmt.Errorf("failed to call mev_sendBundle error %w", err)
	}

	return &bundleResp, nil
}

func (c *Client) SendEthBundle(ctx context.Context, bundle *SendBundleArgs) (*SendMevBundleResponse, error) {
	var bundleResp SendMevBundleResponse
	err := c.FlashbotsRelay.CallFor(ctx, &bundleResp, "eth_sendBundle", bundle)
	if err != nil {
		return nil, fmt.Errorf("failed to call mev_sendBundle error %w", err)
	}

	return &bundleResp, nil

}

func (c *Client) SimulateMEVBundle(ctx context.Context, bundle *rpctypes.MevSendBundleArgs) (*SimulateBundleResponse, error) {
	var bundleSimResp SimulateBundleResponse
	err := c.FlashbotsRelay.CallFor(ctx, &bundleSimResp, "mev_simBundle", bundle)
	if err != nil {
		return nil, fmt.Errorf("failed to call mev_sendBundle error %w", err)
	}

	return &bundleSimResp, nil
}

func (c *Client) CancelMEVBundle(ctx context.Context, hash common.Hash) error {
	err := c.FlashbotsRelay.CallFor(ctx, &hash, "mev_cancelBundleByHash")
	if err != nil {
		return fmt.Errorf("failed to call mev_cancelBundleByHash error %w", err)
	}

	return nil
}

func (c *Client) SendPrivateTx(ctx context.Context, tx *types.Transaction) error {
	return c.FlashbotsRPC.SendTransaction(ctx, tx)
}

func (c *Client) CancelEthBundle(ctx context.Context, cancelArgs CancelETHBundleArgs) error {
	resp, err := c.FlashbotsRelay.Call(ctx, "eth_cancelBundle", cancelArgs)
	if err != nil {
		return fmt.Errorf("failed to call eth_cancelBundle %w", err)
	}

	slog.Info("Cancel eth bundle response", "response", resp.Result)
	if resp.Error != nil {
		err = errors.New(resp.Error.Message)
	}

	return err

}

func (c *Client) SendPrivateRawRelayTx(ctx context.Context, tx *types.Transaction, builders ...string) (hexutil.Bytes, error) {
	var resp hexutil.Bytes

	bts, err := tx.MarshalBinary()
	if err != nil {
		return nil, err
	}
	rtx := (*hexutil.Bytes)(&bts)
	prefs := PrivateTxPreferences{
		Privacy: TxPrivacyPreferences{
			Builders: builders,
		},
	}
	err = c.FlashbotsRelay.CallFor(ctx, &resp, "eth_sendPrivateRawTransaction", rtx, &prefs)
	return resp, err
}

func (c *Client) SendPrivateRelayTx(ctx context.Context, tx *types.Transaction) (hexutil.Bytes, error) {
	var resp hexutil.Bytes

	bts, err := tx.MarshalBinary()
	if err != nil {
		return nil, err
	}
	rtx := (*hexutil.Bytes)(&bts)

	args := SendPrivateTxArgs{
		Tx: rtx.String(),
	}

	err = c.FlashbotsRelay.CallFor(ctx, &resp, "eth_sendPrivateTransaction", args)
	return resp, err

}

func (c *Client) SetFeeRefundRecipient(ctx context.Context, signer common.Address, deligateAddr common.Address) error {
	res, err := c.FlashbotsRelay.Call(ctx, "flashbots_setFeeRefundRecipient", signer, deligateAddr)
	if err != nil {
		return err
	}

	slog.Info("Set fee refund recipient response", "response", res.Result)
	return nil
}

func (c *Client) CallEthBundle(ctx context.Context, args *CallBundleArgs) error {
	resp, err := c.FlashbotsRelay.Call(ctx, "eth_callBundle", args)
	if err != nil {
		return fmt.Errorf("failed to call eth_callBundle %w", err)
	}

	if resp.Error != nil {
		slog.Error("ETH call bundle", "err", resp.Error.Message)
	} else {
		slog.Info("ETH call bundle", "simRes", resp.Result)
	}

	return nil
}

func (c *Client) CancelPrivateRelayTx(ctx context.Context, txHash common.Hash) error {
	resp, err := c.FlashbotsRelay.Call(ctx, "eth_cancelPrivateTransaction", CancelPrivateTxArgs{TxHash: txHash})
	if err != nil {
		return fmt.Errorf("failed to call eth_cancelPrivateTransaction %w", err)
	}

	if resp.Error != nil {
		slog.Error("ETH cancel private transaction", "err", resp.Error.Message)
	} else {

		slog.Info("ETH cancel private transaction", "res", resp.Result)
	}

	return nil
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
