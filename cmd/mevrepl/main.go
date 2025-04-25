package main

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/flashbots/mevrepl/mev"
	"github.com/flashbots/mevrepl/mevutil"
	"github.com/urfave/cli/v2"
)

var (
	errHintNotFound          = errors.New("hint hash not found")
	errUnsupportedTestTxType = errors.New("unsupported test-tx-type")
)

type TestTxType string

const (
	WethWrap   TestTxType = "weth-wrap"
	BuilderTip TestTxType = "builder-tip"
	FakeTx     TestTxType = "fake-tx"
)

var (
	txFlags = []cli.Flag{
		&cli.StringFlag{
			Name:    "eth-amount",
			Aliases: []string{"a"},
		},
		&cli.StringFlag{
			Name:    "tx-type",
			Aliases: []string{"tt"},
			Usage: "--tt weth-wrap. " +
				"--tt builder-tip. " +
				"--tt fake-tx (send failed tx -> send bundle matching failed tx (Test case))",
		},
	}

	txStatusFlags = []cli.Flag{
		&cli.StringFlag{
			Name: "tx-hash",
		},
	}
)

func main() {
	logLevel := slog.LevelInfo
	if ll := os.Getenv("LOG_LEVEL"); ll != "" {
		if ll == "DEBUG" {
			logLevel = slog.LevelDebug
		}
	}

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel})))

	privKey1 := os.Getenv("FLASHBOTS_ETH_PRIVATE_KEY")
	if privKey1 == "" {
		panic("FLASHBOTS_ETH_PRIVATE_KEY must be provided")
	}

	alice, err := crypto.HexToECDSA(privKey1)
	if err != nil {
		panic(fmt.Errorf("failed to parse secp256k1 private key error %w", err))
	}

	var (
		priorityFee *big.Int
		chainID     *big.Int

		network      = os.Getenv("NETWORK")
		publicRPCURL = os.Getenv("PUBLIC_RPC")

		builderAddr          common.Address
		wethAddr             common.Address
		checkAndSendContract common.Address
	)

	switch network {
	case "", mev.SepoliaNetwork:
		network = mev.SepoliaNetwork
		priorityFee = big.NewInt(1e5)
		if publicRPCURL == "" {
			publicRPCURL = "https://eth-sepolia.public.blastapi.io"
		}
		chainID = big.NewInt(mev.SepoliaChainID)

		builderAddr = common.HexToAddress("0x13cb6ae34a13a0977f4d7101ebc24b87bb23f0d5")
		wethAddr = common.HexToAddress("0xfFf9976782d46CC05630D1f6eBAb18b2324d6B14")
		checkAndSendContract = common.HexToAddress("0xB0D90094d296DA87485C623a7f42d245A74036a0")
	case mev.Mainnet:
		if publicRPCURL == "" {
			publicRPCURL = "https://eth.llamarpc.com"
		}
		priorityFee = big.NewInt(1e8)
		chainID = big.NewInt(mev.MainnetChainID)

		builderAddr = common.HexToAddress("0xdadB0d80178819F2319190D340ce9A924f783711")
		wethAddr = common.HexToAddress("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")
		checkAndSendContract = common.HexToAddress("0xC4595E3966e0Ce6E3c46854647611940A09448d3")
	default:
		panic("unsupported network")
	}

	ethClient, err := ethclient.Dial(publicRPCURL)
	if err != nil {
		panic(fmt.Errorf("failed to init public RPC client error %w", err))
	}

	mevClient, err := mev.ConstructClient(alice, network, chainID, "fast?hint=full", nil)
	if err != nil {
		panic(fmt.Errorf("failed to construct mev client error %w", err))
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGQUIT, syscall.SIGTERM)
	defer cancel()

	mevTest := &MEVTest{
		mevClient:            mevClient,
		ethClient:            ethClient,
		alice:                alice,
		network:              network,
		builderAddr:          builderAddr,
		wethAddr:             wethAddr,
		checkAndSendContract: checkAndSendContract,
	}

	app := &cli.App{
		Name:        "mevrepl",
		Description: "Command line based repl test toolkit",
	}

	// This command sends a test private transaction using the Flashbots Protect RPC endpoint.
	//
	// Flashbots Protect allows users to submit transactions privately, bypassing the public mempool.
	// This helps protect against frontrunning, sandwich attacks, and other forms of MEV exploitation.
	//
	// Transactions sent through this endpoint are only included if they succeed (i.e., no reverts),
	// ensuring that failed transactions do not appear on-chain.
	//
	// This command uses a test transaction for illustrative purposes only. It is intended
	// as a minimal example to demonstrate how to interact with the Protect RPC.
	//
	// For details, see: https://docs.flashbots.net/flashbots-protect/overview
	sendPrivateTxCmd := &cli.Command{
		Name:        "send-private-tx",
		Aliases:     []string{"stx"},
		Description: "send private test tx on flashbots rpc endpoint",
		Flags:       txFlags,
		Action: func(cCtx *cli.Context) error {
			ethAmountStr := cCtx.String("eth-amount")
			txTypeStr := TestTxType(cCtx.String("tx-type"))
			toAddr, err := mevTest.parseToAddr(txTypeStr)
			if err != nil {
				return err
			}

			ethAmount, err := mevTest.getEthValue(ethAmountStr)
			if err != nil {
				return err
			}

			_, err = mevTest.SendPrivateSimpleTx(ctx, ethAmount, toAddr, priorityFee)
			if err != nil {
				return fmt.Errorf("faield to execute send-private-tx error %w", err)
			}

			return nil
		},
	}

	// This command is for the test goals. Sends fake tx which must fail
	sendFakeTxCmd := &cli.Command{
		Name:        "send-fake-tx",
		Aliases:     []string{"sft"},
		Description: "send fake tx which must fail on flashbots rpc endpoint",
		Flags:       txFlags,
		Action: func(cCtx *cli.Context) error {
			tx, err := mevTest.SendFakeTx(ctx, nil, priorityFee)
			if err != nil {
				return fmt.Errorf("faield to execute send-private-tx error %w", err)
			}

			slog.Info("Send fake tx which must fail", "tx_hash", tx.Hash())

			return nil
		},
	}

	// This command calls Flashbots Protect Transaction Status API and logs info txStatus
	//
	// For details, see: https://docs.flashbots.net/flashbots-protect/additional-documentation/status-api
	txStatusCmd := &cli.Command{
		Name:        "tx-status",
		Aliases:     []string{"ts"},
		Description: "query check tx status on Flashbots Protect endpoint",
		Flags:       txStatusFlags,
		Action: func(cCtx *cli.Context) error {
			txHash := cCtx.String("tx-hash")
			if txHash == "" {
				return errors.New("txHash expected")
			}

			txStatus, err := mevTest.mevClient.GetTxStatus(ctx, common.HexToHash(txHash))
			if err != nil {
				return err
			}

			slog.Info("Received tx status", "status", txStatus)

			return nil
		},
	}

	// Flashbots provides a Server-Sent Events (SSE) stream to access MEV-Share events.
	//
	// This command connects to the MEV-Share SSE stream and listens for hint events.
	// The target hintHash is a keccak256 hash of the original transaction hash.
	// For more information, see:
	// https://docs.flashbots.net/flashbots-mev-share/searchers/event-stream#understanding-double-hash
	//
	// This tool allows searchers to subscribe to real-time MEV opportunities
	// by decoding and handling hint messages streamed from the Flashbots network.
	hintsStreamCmd := &cli.Command{
		Name:        "hints-stream",
		Aliases:     []string{"hs"},
		Description: "listen distributed MevShare events via SSE. Info log hints only",
		Action: func(cCtx *cli.Context) error {
			ch := make(chan mev.Hint)
			hintsStream, err := mev.SubscribeHints(context.Background(), mevClient.FlashbotsMEVShareURL, ch, nil)
			if err != nil {
				return err
			}
			for hint := range ch {
				slog.Info("Parsed hint", "hint", hint)
			}

			return hintsStream.Error()
		},
	}

	// This command demonstrates a simple MEV backrun flow using the Flashbots MEV-Share network.
	//
	// The example flow includes the following steps:
	// 1. Send a private transaction to the network.
	// 2. Subscribe to the MEV-Share SSE stream and listen for incoming hints.
	// 3. When a received hintHash matches the original transaction, send a backrun transaction.
	//
	// This tool serves as a minimal working example for understanding and testing
	// basic backrun logic.
	backrunCmd := &cli.Command{
		Name:        "backrun",
		Aliases:     []string{"br"},
		Description: "backrun tx based on the MevShare events",
		Flags:       txFlags,
		Action: func(cCtx *cli.Context) error {
			rawKeyY := os.Getenv("FLASHBOTS_ETH_PRIVATE_KEY_2")
			if rawKeyY == "" {
				return errors.New("FLASHBOTS_ETH_PRIVATE_KEY_2 must be provided")
			}

			ethAmountStr := cCtx.String("eth-amount")
			txTypeStr := TestTxType(cCtx.String("tx-type"))
			toAddr, err := mevTest.parseToAddr(txTypeStr)
			if err != nil {
				return err
			}

			ethAmount, err := mevTest.getEthValue(ethAmountStr)
			if err != nil {
				return err
			}

			// 60 seconds should be enough to catch the target hint as we're listening immediately after private tx was sent
			listenCtx, stop := context.WithTimeout(ctx, time.Second*60)
			defer stop()

			ch := make(chan mev.Hint, 100)
			hintsStream, err := mev.SubscribeHints(listenCtx, mevClient.FlashbotsMEVShareURL, ch, nil)
			if err != nil {
				return err
			}
			go func() {
				<-listenCtx.Done()
				<-time.After(time.Second * 1)
				close(ch)
			}()

			currBlock, err := mevTest.ethClient.HeaderByNumber(listenCtx, nil)
			if err != nil {
				return err
			}

			now := uint64(time.Now().Unix())
			blockTime := currBlock.Time
			if blockTime > now {
				panic("invalid block timestamp")
			}
			diff := now - blockTime

			// if diff between time now and current block onchain is more than 5 sec
			// we should wait till the next block to increase chances that the backrun will be landed
			slog.Info("Computing block_diff duration", "block", currBlock.Number.Uint64(), "curr_block_diff_dur", diff)
			if diff >= 5 {
				slog.Warn("Wait till the next block")
				<-time.After(time.Second * time.Duration(diff))
			}

			var tx *types.Transaction
			if txTypeStr == FakeTx {
				tx, err = mevTest.SendFakeTx(ctx, nil, priorityFee)
			} else {
				tx, err = mevTest.SendPrivateSimpleTx(ctx, big.NewInt(1), toAddr, priorityFee)

			}
			if err != nil {
				return fmt.Errorf("faield to send tx error %w", err)
			}

			privKey2, err := crypto.HexToECDSA(rawKeyY)
			if err != nil {
				return fmt.Errorf("failed to parse secp256k1 private key error %w", err)
			}

			matchHash, err := mevutil.DoubleTxHash(tx.Hash())
			if err != nil {
				return err
			}

			for hint := range ch {
				if matchHash == hint.Hash {
					bundleResp, err := mevTest.SendTestBackrun(ctx, matchHash, priorityFee, ethAmount, privKey2)
					if err != nil {
						return fmt.Errorf("failed to send backrun error %w", err)
					}

					slog.Info("Backrun sent", "bundle", bundleResp.BundleHash.String())

					for range time.NewTicker(time.Second * 2).C {
						txStatus, err := mevTest.mevClient.GetTxStatus(ctx, tx.Hash())
						if err != nil {
							slog.Warn("Failed to get tx status", "erorr", err)
							continue
						}

						slog.Info("Received tx status", "tx", tx.Hash(), "status", txStatus.Status)
						if txStatus.Status == "INCLUDED" || txStatus.Status == "FAILED" {
							break
						}
					}

					return hintsStream.Error()
				}
			}

			return errHintNotFound
		},
	}

	app.Commands = append(app.Commands, sendPrivateTxCmd, sendFakeTxCmd, txStatusCmd, hintsStreamCmd, backrunCmd)

	if err := app.Run(os.Args); err != nil {
		panic(err)
	}
}

type MEVTest struct {
	alice                *ecdsa.PrivateKey
	mevClient            *mev.Client
	ethClient            *ethclient.Client
	network              string
	builderAddr          common.Address
	wethAddr             common.Address
	checkAndSendContract common.Address
}

func (mt *MEVTest) getEthValue(value string) (*big.Int, error) {
	ethAmount := new(big.Int).SetUint64(1)
	if value != "" {
		if _, ok := ethAmount.SetString(value, 10); !ok {
			return nil, fmt.Errorf("failed to parse ethAmount from string base: 10 value: %v", value)
		}
	}

	return ethAmount, nil
}

func (mt *MEVTest) parseToAddr(txType TestTxType) (common.Address, error) {
	switch txType {
	case WethWrap, FakeTx, "":
		return mt.wethAddr, nil
	case BuilderTip:
		return mt.builderAddr, nil

	default:
		return common.Address{}, errUnsupportedTestTxType
	}
}

func (mt *MEVTest) ethTransfer(ctx context.Context, value *big.Int, priorityFee *big.Int, sender *ecdsa.PrivateKey, to common.Address) (*types.Transaction, error) {
	key := mt.alice
	if sender != nil {
		key = sender
	}

	currBlock, err := mt.mevClient.FlashbotsRPC.BlockByNumber(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get block error %w", err)
	}

	address := crypto.PubkeyToAddress(key.PublicKey)
	nonce, err := mt.mevClient.FlashbotsRPC.PendingNonceAt(ctx, address)
	if err != nil {
		return nil, fmt.Errorf("failed to get pending nonce: %w", err)
	}

	signer := types.LatestSignerForChainID(mt.mevClient.ChainID)
	gasPrice := currBlock.BaseFee()
	baseFeeFuture := new(big.Int).Mul(gasPrice, big.NewInt(150))
	baseFeeFuture = new(big.Int).Div(baseFeeFuture, big.NewInt(100))

	gasLimit := 50_000
	var gasTipCap *big.Int
	if priorityFee != nil {
		gasTipCap = priorityFee
	} else {
		gasTipCap = big.NewInt(1e5)
	}

	return types.SignTx(types.NewTx(&types.DynamicFeeTx{
		ChainID:   mt.mevClient.ChainID,
		Nonce:     nonce,
		GasFeeCap: baseFeeFuture,
		GasTipCap: gasTipCap,
		Gas:       uint64(gasLimit),
		To:        &to,
		Value:     value,
	}), signer, key)
}

func (mt *MEVTest) SendFakeTx(ctx context.Context, sender *ecdsa.PrivateKey, priorityFee *big.Int) (*types.Transaction, error) {
	if sender == nil {
		sender = mt.alice
	}
	currBlock, err := mt.mevClient.FlashbotsRPC.BlockByNumber(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get block error %w", err)
	}

	// builds fake call data which staticcalls always fail
	fakeCalldata, err := mt.checkAndSendMultiCallData([]common.Address{mt.wethAddr}, [][]byte{{0xFF}}, [][]byte{{0xAF}})
	if err != nil {
		return nil, err
	}

	senderAddr := crypto.PubkeyToAddress(sender.PublicKey)
	nonce, err := mt.ethClient.PendingNonceAt(ctx, senderAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to get pending nonce: %w", err)
	}

	signer := types.LatestSignerForChainID(mt.mevClient.ChainID)
	gasPrice := currBlock.BaseFee()
	baseFeeFuture := new(big.Int).Mul(gasPrice, big.NewInt(110))
	baseFeeFuture = new(big.Int).Div(baseFeeFuture, big.NewInt(100))
	gasLimit := 80_000

	var gasTipCap *big.Int
	if priorityFee != nil {
		gasTipCap = priorityFee
	} else {
		gasTipCap = big.NewInt(1e5)
	}
	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   mt.mevClient.ChainID,
		Nonce:     nonce,
		GasFeeCap: baseFeeFuture,
		GasTipCap: gasTipCap,
		Gas:       uint64(gasLimit),
		To:        &mt.checkAndSendContract,
		Value:     nil,
		Data:      fakeCalldata,
	})

	fakeTx, err := types.SignTx(tx, signer, sender)
	if err != nil {
		return nil, err
	}

	if err := mt.mevClient.SendPrivateTx(ctx, fakeTx); err != nil {
		return nil, err
	}

	return fakeTx, nil
}

func (mt *MEVTest) SendPrivateSimpleTx(ctx context.Context, eth *big.Int, to common.Address, priorityFee *big.Int) (*types.Transaction, error) {
	tx, err := mt.ethTransfer(ctx, eth, priorityFee, nil, to)
	if err != nil {
		return nil, err
	}

	if err := mt.mevClient.SendPrivateTx(ctx, tx); err != nil {
		return nil, err
	}

	slog.Info("Private tx send", "tx_hash", tx.Hash().String())
	return tx, nil
}

func (mt *MEVTest) checkAndSendMultiCallData(addrs []common.Address, payloads [][]byte, results [][]byte) ([]byte, error) {
	checkAndSendABI, err := abi.JSON(strings.NewReader(mevutil.FlashbotsCheckAndSendABI))
	if err != nil {
		return nil, err
	}

	calldata, err := checkAndSendABI.Pack("checkBytesAndSendMulti", addrs, payloads, results)
	if err != nil {
		return nil, fmt.Errorf("failed to pack checkBytesAndSend calldata error %w", err)
	}

	return calldata, nil
}

func (mt *MEVTest) SendTestBackrun(ctx context.Context, originalTx common.Hash, priorityFee *big.Int, payableAmount *big.Int, sender *ecdsa.PrivateKey) (*mev.SendMevBundleResponse, error) {
	currBlock, err := mt.mevClient.FlashbotsRPC.BlockByNumber(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get block error %w", err)
	}

	if payableAmount == nil {
		if mt.network == mev.SepoliaNetwork {
			payableAmount = big.NewInt(5e16)
		} else {
			payableAmount = big.NewInt(2e15)
		}
	}

	calldata, err := mt.checkAndSendMultiCallData([]common.Address{}, [][]byte{}, [][]byte{})
	if err != nil {
		return nil, err
	}

	senderAddr := crypto.PubkeyToAddress(sender.PublicKey)
	nonce, err := mt.ethClient.PendingNonceAt(ctx, senderAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to get pending nonce: %w", err)
	}

	signer := types.LatestSignerForChainID(mt.mevClient.ChainID)
	gasPrice := currBlock.BaseFee()
	baseFeeFuture := new(big.Int).Mul(gasPrice, big.NewInt(110))
	baseFeeFuture = new(big.Int).Div(baseFeeFuture, big.NewInt(100))
	gasLimit := 80_000

	var gasTipCap *big.Int
	if priorityFee != nil {
		gasTipCap = priorityFee
	} else {
		gasTipCap = big.NewInt(1e5)
	}
	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   mt.mevClient.ChainID,
		Nonce:     nonce,
		GasFeeCap: baseFeeFuture,
		GasTipCap: gasTipCap,
		Gas:       uint64(gasLimit),
		To:        &mt.checkAndSendContract,
		Value:     payableAmount,
		Data:      calldata,
	})
	backrunTx, err := types.SignTx(tx, signer, sender)
	if err != nil {
		return nil, err
	}

	bundle, err := mt.mevClient.CreateBundle(originalTx, currBlock.NumberU64(), nil, backrunTx)
	if err != nil {
		return nil, fmt.Errorf("failed to bundle tx error %w", err)
	}

	resp, err := mt.mevClient.SendBundle(ctx, bundle)
	if err != nil {
		return nil, err
	}

	slog.Info("Send backrun tx", "backrun_tx_hash", backrunTx.Hash())

	return resp, nil
}
