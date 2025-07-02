package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"math/big"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/flashbots/mevrepl/mev"
	"github.com/flashbots/mevrepl/mevutil"
	"github.com/holiman/uint256"
	"github.com/urfave/cli/v2"
)

var (
	errHintNotFound          = errors.New("hint hash not found")
	errUnsupportedTestTxType = errors.New("unsupported tx-type")
)

type TestTxType string

const (
	WethWrap   TestTxType = "weth-wrap"
	BuilderTip TestTxType = "builder-tip"
	FakeTx     TestTxType = "fake-tx"
	EIP7702Tx  TestTxType = "eip7702-tx"
	RawBatchTx TestTxType = "raw-batch-tx"
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
				"--tt fake-tx (send failed tx -> send bundle matching failed tx (Test case))" +
				"--tt eip7702-tx (send eip7702 tx)",
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

		// pectra
		batchcallAndSponsorContract common.Address
	)

	switch network {
	case "", mev.SepoliaNetwork:
		network = mev.SepoliaNetwork
		priorityFee = big.NewInt(1e5)
		if publicRPCURL == "" {
			publicRPCURL = "https://ethereum-sepolia-rpc.publicnode.com"
		}
		chainID = big.NewInt(mev.SepoliaChainID)

		builderAddr = common.HexToAddress("0x13cb6ae34a13a0977f4d7101ebc24b87bb23f0d5")
		wethAddr = common.HexToAddress("0xfFf9976782d46CC05630D1f6eBAb18b2324d6B14")
		checkAndSendContract = common.HexToAddress("0xB0D90094d296DA87485C623a7f42d245A74036a0")

		batchcallAndSponsorContract = common.HexToAddress("0x33ACD5b112a17c863beb2f37f785bAEf8a8f8369")
	case mev.Mainnet:
		if publicRPCURL == "" {
			publicRPCURL = "https://eth.llamarpc.com"
		}
		priorityFee = big.NewInt(2e9)
		chainID = big.NewInt(mev.MainnetChainID)

		builderAddr = common.HexToAddress("0xdadB0d80178819F2319190D340ce9A924f783711")
		wethAddr = common.HexToAddress("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")
		checkAndSendContract = common.HexToAddress("0xC4595E3966e0Ce6E3c46854647611940A09448d3")

		batchcallAndSponsorContract = common.HexToAddress("0x775c8D470CC8d4530b8F233322480649f4FAb758")
	default:
		panic("unsupported network")
	}

	ethClient, err := ethclient.Dial(publicRPCURL)
	if err != nil {
		panic(fmt.Errorf("failed to init public RPC client error %w", err))
	}

	mevClient, err := mev.ConstructClient(alice, network, chainID, fmt.Sprintf("fast"), nil)
	if err != nil {
		panic(fmt.Errorf("failed to construct mev client error %w", err))
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGQUIT, syscall.SIGTERM)
	defer cancel()

	mevTest := &MEVTest{
		mevClient:                   mevClient,
		ethClient:                   ethClient,
		alice:                       alice,
		network:                     network,
		builderAddr:                 builderAddr,
		wethAddr:                    wethAddr,
		checkAndSendContract:        checkAndSendContract,
		batchCallAndSponsorContract: batchcallAndSponsorContract,
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

			if txTypeStr == RawBatchTx {
				addr := crypto.PubkeyToAddress(alice.PublicKey)

				nonceAt, err := mevTest.ethClient.PendingNonceAt(ctx, addr)
				if err != nil {
					return err
				}

				tx1, err := mevTest.delegateTxWithEIP7702(ctx, nil, priorityFee, &nonceAt)
				if err != nil {
					return err
				}

				nonceAt += 2
				tx2, err := mevTest.delegateTxWithEIP7702(ctx, nil, priorityFee, &nonceAt)
				if err != nil {
					return err
				}

				if err := mevTest.mevClient.SendPrivateTx(ctx, tx1); err != nil {
					return err
				}

				if err := mevTest.mevClient.SendPrivateTx(ctx, tx2); err != nil {
					return err
				}

				slog.Info("Sent tx", "hash", tx1.Hash())
				slog.Info("Sent tx", "hash", tx2.Hash())

				return nil
			}

			// Pectra update test workflow using batch call transactions
			//
			// 1. construct and send SetCode transaction
			// 2. get tx_receipt and verify that auth set correctly
			// 3. use EOA account to execute tx batchcall
			if txTypeStr == EIP7702Tx {
				tx, err := mevTest.delegateTxWithEIP7702(ctx, nil, priorityFee, nil)
				if err != nil {
					return fmt.Errorf("failed to construct eip7702 tx error %w", err)
				}

				listenCtx, stopListen := context.WithTimeout(ctx, time.Second*60)
				defer stopListen()
				hintsC := make(chan mev.Hint, 100)
				_, err = mev.SubscribeHints(listenCtx, mevClient.FlashbotsMEVShareURL, hintsC, nil)
				if err != nil {
					return err
				}

				go func() {
					<-listenCtx.Done()
					<-time.After(time.Second * 1)
					close(hintsC)
				}()

				slog.Info("Sent eip7702-tx", "tx_hash", tx.Hash())

				if err := mevTest.mevClient.SendPrivateTx(ctx, tx); err != nil {
					return err
				}

				matchHash, err := mevutil.DoubleTxHash(tx.Hash())
				if err != nil {
					return err
				}

				rawKeyY := os.Getenv("FLASHBOTS_ETH_PRIVATE_KEY_2")
				if rawKeyY == "" {
					return errors.New("FLASHBOTS_ETH_PRIVATE_KEY_2 must be provided")
				}

				privKey2, err := crypto.HexToECDSA(rawKeyY)
				if err != nil {
					return fmt.Errorf("failed to parse secp256k1 private key error %w", err)
				}

				var found bool
				for hint := range hintsC {
					if hint.Hash == matchHash {
						bundleResp, err := mevTest.SendTestBackrun(ctx, matchHash, priorityFee, ethAmount, privKey2)
						if err != nil {
							return fmt.Errorf("failed to send backrun error %w", err)
						}

						slog.Info("Sent Bundle", "bundle_hash", bundleResp.BundleHash)
						stopListen()
						found = true
						break
					}
				}

				if !found {
					return errors.New("failed to send backrun")
				}

				txStatus, err := mevTest.getFlashbotsTxReceipt(ctx, tx.Hash())
				if err != nil {
					return err
				}

				slog.Info("Received tx status", "tx", tx.Hash(), "status", txStatus.Status)

				slog.Info("Start verify auth_list")
				// verify auth
			VerifyLoop:
				for {
					<-time.After(time.Second * 2)
					onchainTx, pending, err := mevTest.mevClient.FlashbotsRPC.TransactionByHash(ctx, tx.Hash())
					if err != nil {
						if errors.Is(err, ethereum.NotFound) {
							continue
						}
						return err
					}

					if pending {
						continue
					}

					for _, auth := range onchainTx.SetCodeAuthorizations() {
						code, err := ethClient.CodeAt(ctx, crypto.PubkeyToAddress(alice.PublicKey), nil)
						if err != nil {
							return err
						}
						delegation := types.AddressToDelegation(auth.Address)
						if string(code) != string(delegation) {
							return fmt.Errorf("code is not equal expected delegation")
						}
						break VerifyLoop
					}
				}

				batchCallABI, err := abi.JSON(strings.NewReader(mevutil.BatchCallAndSponsorABI))
				if err != nil {
					return err
				}

				calldata, err := batchCallABI.Pack("execute", []Call{
					{
						To:    wethAddr,
						Value: big.NewInt(1),
						Data:  nil,
					},
					{
						To:    builderAddr,
						Value: big.NewInt(1),
						Data:  nil,
					},
				})
				if err != nil {
					return fmt.Errorf("failed to pack batchcall error %w", err)
				}

				currBlock, err := ethClient.BlockByNumber(ctx, nil)
				if err != nil {
					return err
				}

				senderAddr := crypto.PubkeyToAddress(alice.PublicKey)
				nonce, err := ethClient.PendingNonceAt(ctx, senderAddr)
				if err != nil {
					return err
				}

				signer := types.LatestSignerForChainID(mevTest.mevClient.ChainID)
				gasPrice := currBlock.BaseFee()
				baseFeeFuture := new(big.Int).Mul(gasPrice, big.NewInt(150))
				baseFeeFuture = new(big.Int).Div(baseFeeFuture, big.NewInt(100))
				gasLimit := 180_000

				var gasTipCap *big.Int
				if priorityFee != nil {
					gasTipCap = priorityFee
				} else {
					gasTipCap = big.NewInt(1e5)
				}

				rawTx := types.NewTx(&types.DynamicFeeTx{
					ChainID:   mevTest.mevClient.ChainID,
					Nonce:     nonce,
					GasTipCap: gasTipCap,
					GasFeeCap: baseFeeFuture,
					Gas:       uint64(gasLimit),
					To:        &senderAddr,
					Value:     nil,
					Data:      calldata,
				})

				stx, err := types.SignTx(rawTx, signer, alice)
				if err != nil {
					return err
				}

				if err := mevTest.mevClient.SendPrivateTx(ctx, stx); err != nil {
					return err
				}

				slog.Info("Sent batchcall-tx", "tx_hash", stx.Hash())
				return nil
			}

			tx, err := mevTest.ethTransfer(ctx, ethAmount, priorityFee, nil, toAddr, nil)
			if err != nil {
				return fmt.Errorf("failed to construct ethTransfer tx error %w", err)
			}

			_, err = mevTest.SendPrivateSimpleTx(ctx, tx)
			if err != nil {
				return fmt.Errorf("faield to execute send-private-tx error %w", err)
			}

			txStatus, err := mevTest.getFlashbotsTxReceipt(ctx, tx.Hash())
			if err != nil {
				return err
			}

			slog.Info("Received tx status", "tx", tx, "status", txStatus.Status)

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
				tx, err = mevTest.ethTransfer(ctx, big.NewInt(1), priorityFee, nil, toAddr, nil)
				if err != nil {
					return fmt.Errorf("failed to construct ethTransfer tx error %w", err)
				}
				tx, err = mevTest.SendPrivateSimpleTx(ctx, tx)

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
					hintRaw, err := json.Marshal(hint)
					if err != nil {
						return err
					}
					log.Println("hint:", string(hintRaw))

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
	alice                       *ecdsa.PrivateKey
	mevClient                   *mev.Client
	ethClient                   *ethclient.Client
	network                     string
	builderAddr                 common.Address
	wethAddr                    common.Address
	checkAndSendContract        common.Address
	batchCallAndSponsorContract common.Address
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
	case EIP7702Tx, RawBatchTx:
		return common.Address{}, nil

	default:
		return common.Address{}, errUnsupportedTestTxType
	}
}

func (mt *MEVTest) ethTransfer(ctx context.Context, value *big.Int, priorityFee *big.Int, sender *ecdsa.PrivateKey, to common.Address, nonce *uint64) (*types.Transaction, error) {
	key := mt.alice
	if sender != nil {
		key = sender
	}

	currBlock, err := mt.mevClient.FlashbotsRPC.BlockByNumber(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get block error %w", err)
	}

	address := crypto.PubkeyToAddress(key.PublicKey)
	if nonce == nil {
		nonceAt, err := mt.mevClient.FlashbotsRPC.PendingNonceAt(ctx, address)
		if err != nil {
			return nil, fmt.Errorf("failed to get pending nonce: %w", err)
		}
		nonce = &nonceAt
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
	baseFeeFuture.Add(baseFeeFuture, gasTipCap)

	log.Println("baseFee:", baseFeeFuture.String(), "priorityFee:", gasTipCap.String())

	return types.SignTx(types.NewTx(&types.DynamicFeeTx{
		ChainID:   mt.mevClient.ChainID,
		Nonce:     *nonce,
		GasFeeCap: baseFeeFuture,
		GasTipCap: gasTipCap,
		Gas:       uint64(gasLimit),
		To:        &to,
		Value:     value,
	}), signer, key)
}

type Call struct {
	To    common.Address `json:"to"`
	Value *big.Int       `json:"value"`
	Data  []byte         `json:"data"`
}

func (mt *MEVTest) delegateTxWithEIP7702(ctx context.Context, sender *ecdsa.PrivateKey, priorityFee *big.Int, nonce *uint64) (*types.Transaction, error) {
	if sender == nil {
		sender = mt.alice
	}

	currBlock, err := mt.ethClient.BlockByNumber(ctx, nil)
	if err != nil {
		return nil, err
	}

	senderAddr := crypto.PubkeyToAddress(sender.PublicKey)
	if nonce == nil {
		nonceAt, err := mt.ethClient.PendingNonceAt(ctx, senderAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to get nonce error %w", err)
		}
		nonce = &nonceAt
	}

	//generate signature for specific contract implementation
	auth, err := types.SignSetCode(sender, types.SetCodeAuthorization{
		ChainID: *uint256.MustFromBig(mt.mevClient.ChainID),
		Address: mt.batchCallAndSponsorContract,

		Nonce: *nonce + 1,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to sign auth error %w", err)
	}

	signer := types.LatestSignerForChainID(mt.mevClient.ChainID)
	gasPrice := currBlock.BaseFee()
	baseFeeFuture := new(big.Int).Mul(gasPrice, big.NewInt(150))
	baseFeeFuture = new(big.Int).Div(baseFeeFuture, big.NewInt(100))
	gasLimit := 180_000

	var gasTipCap *big.Int
	if priorityFee != nil {
		gasTipCap = priorityFee
	} else {
		gasTipCap = big.NewInt(1e5)
	}

	rawTx := types.NewTx(&types.SetCodeTx{
		ChainID:   uint256.MustFromBig(mt.mevClient.ChainID),
		Nonce:     *nonce,
		GasTipCap: uint256.MustFromBig(gasTipCap),
		GasFeeCap: uint256.MustFromBig(baseFeeFuture),
		Gas:       uint64(gasLimit),
		To:        senderAddr,
		Value:     nil,
		Data:      []byte("hello!"),
		AuthList:  []types.SetCodeAuthorization{auth},
	})

	return types.SignTx(rawTx, signer, sender)
}

func (mt *MEVTest) getFlashbotsTxReceipt(ctx context.Context, tx common.Hash) (mev.TxStatus, error) {
	// check flashbots status endpoint
	for range time.NewTicker(time.Second * 2).C {
		txStatus, err := mt.mevClient.GetTxStatus(ctx, tx)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return mev.TxStatus{}, err
			}
			slog.Warn("Failed to get tx status", "erorr", err)
			continue
		}

		if txStatus.Status == "PENDING" {
			continue
		}

		if txStatus.Status == "INCLUDED" || txStatus.Status == "FAILED" {
			return txStatus, nil
		}

		return mev.TxStatus{}, errors.New("tx dropped")
	}

	return mev.TxStatus{}, errors.New("failed to get tx receipt")
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

func (mt *MEVTest) SendPrivateSimpleTx(ctx context.Context, tx *types.Transaction) (*types.Transaction, error) {
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
