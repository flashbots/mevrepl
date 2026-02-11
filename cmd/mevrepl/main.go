package main

import (
	"context"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"os/signal"
	"syscall"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/flashbots/mevrepl/ports"
	"github.com/flashbots/mevrepl/protect"
	"github.com/urfave/cli/v2"
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
		&cli.StringSliceFlag{
			Name:    "raw-tx",
			Aliases: []string{"rt"},
			Usage:   "hex-encoded signed raw transaction (can be specified multiple times for bundles)",
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

	var handler *ports.Handler
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGQUIT, syscall.SIGTERM)
	defer cancel()

	app := &cli.App{
		Name:        "mevrepl",
		Description: "Command line based repl test toolkit",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "network",
				Aliases: []string{"n"},
				EnvVars: []string{"NETWORK"},
				Value:   "sepolia",
				Usage:   "network to use (sepolia, mainnet, or custom name for devnet)",
			},
			&cli.Int64Flag{
				Name:    "chain-id",
				EnvVars: []string{"CHAIN_ID"},
				Usage:   "chain ID (required for custom/devnet networks, auto-set for sepolia/mainnet)",
			},
			&cli.StringFlag{
				Name:    "node-rpc",
				EnvVars: []string{"NODE_RPC"},
				Usage:   "Ethereum node RPC URL",
			},
			&cli.StringFlag{
				Name:    "flashbots-rpc",
				EnvVars: []string{"FLASHBOTS_RPC_URL"},
				Usage:   "Flashbots RPC URL",
			},
			&cli.StringFlag{
				Name:    "flashbots-relay",
				EnvVars: []string{"FLASHBOTS_RELAY_URL"},
				Usage:   "Flashbots Relay URL",
			},
			&cli.StringFlag{
				Name:    "flashbots-protect",
				EnvVars: []string{"FLASHBOTS_PROTECT_URL"},
				Usage:   "Flashbots Protect URL",
			},
			&cli.StringFlag{
				Name:    "flashbots-mevshare",
				EnvVars: []string{"FLASHBOTS_MEVSHARE_URL"},
				Usage:   "Flashbots MEV-Share URL",
			},
			&cli.StringFlag{
				Name:    "private-key",
				EnvVars: []string{"FLASHBOTS_ETH_PRIVATE_KEY"},
				Usage:   "private key for signing transactions",
			},
			&cli.StringFlag{
				Name:    "weth-addr",
				EnvVars: []string{"WETH_ADDR"},
				Usage:   "WETH contract address (auto-set for sepolia/mainnet)",
			},
			&cli.StringFlag{
				Name:    "builder-addr",
				EnvVars: []string{"BUILDER_ADDR"},
				Usage:   "builder address for tips (auto-set for sepolia/mainnet)",
			},
			&cli.StringFlag{
				Name:    "check-and-send-addr",
				EnvVars: []string{"CHECK_AND_SEND_ADDR"},
				Usage:   "CheckAndSend contract address (auto-set for sepolia/mainnet)",
			},
		},
		Before: func(cCtx *cli.Context) error {
			privKey1 := cCtx.String("private-key")
			if privKey1 == "" {
				return fmt.Errorf("private key must be provided (--private-key or FLASHBOTS_ETH_PRIVATE_KEY)")
			}

			alice, err := crypto.HexToECDSA(privKey1)
			if err != nil {
				return fmt.Errorf("failed to parse secp256k1 private key: %w", err)
			}

			flashbotsRPCURL := cCtx.String("flashbots-rpc")
			flashbotsRelayURL := cCtx.String("flashbots-relay")
			flashbotsProtectURL := cCtx.String("flashbots-protect")
			flashbotsMEVShareURL := cCtx.String("flashbots-mevshare")

			var (
				priorityFee *big.Int
				chainID     *big.Int

				network    = cCtx.String("network")
				nodeRPCURL = cCtx.String("node-rpc")

				builderAddr          common.Address
				wethAddr             common.Address
				checkAndSendContract common.Address

				batchcallAndSponsorContract common.Address
			)

			if cid := cCtx.Int64("chain-id"); cid != 0 {
				chainID = big.NewInt(cid)
			}

			switch network {
			case "", protect.SepoliaNetwork:
				network = protect.SepoliaNetwork
				priorityFee = big.NewInt(1e5)
				if nodeRPCURL == "" {
					nodeRPCURL = "https://ethereum-sepolia-rpc.publicnode.com"
				}

				builderAddr = common.HexToAddress("0x13cb6ae34a13a0977f4d7101ebc24b87bb23f0d5")
				wethAddr = common.HexToAddress("0xfFf9976782d46CC05630D1f6eBAb18b2324d6B14")
				checkAndSendContract = common.HexToAddress("0xB0D90094d296DA87485C623a7f42d245A74036a0")

				batchcallAndSponsorContract = common.HexToAddress("0x33ACD5b112a17c863beb2f37f785bAEf8a8f8369")
			case protect.Mainnet:
				if nodeRPCURL == "" {
					nodeRPCURL = "https://eth.llamarpc.com"
				}

				builderAddr = common.HexToAddress("0xdadB0d80178819F2319190D340ce9A924f783711")
				wethAddr = common.HexToAddress("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")
				checkAndSendContract = common.HexToAddress("0xC4595E3966e0Ce6E3c46854647611940A09448d3")

				batchcallAndSponsorContract = common.HexToAddress("0x775c8D470CC8d4530b8F233322480649f4FAb758")
			default:
				// custom/devnet network — validate required params
				if nodeRPCURL == "" {
					return fmt.Errorf("--node-rpc is required for custom network %q", network)
				}
				if chainID == nil {
					return fmt.Errorf("--chain-id is required for custom network %q", network)
				}
				if flashbotsRPCURL == "" {
					return fmt.Errorf("--flashbots-rpc is required for custom network %q", network)
				}
				if flashbotsRelayURL == "" {
					return fmt.Errorf("--flashbots-relay is required for custom network %q", network)
				}
			}

			// CLI overrides for contract addresses (useful for custom networks, optional for presets)
			if addr := cCtx.String("weth-addr"); addr != "" {
				wethAddr = common.HexToAddress(addr)
			}
			if addr := cCtx.String("builder-addr"); addr != "" {
				builderAddr = common.HexToAddress(addr)
			}
			if addr := cCtx.String("check-and-send-addr"); addr != "" {
				checkAndSendContract = common.HexToAddress(addr)
			}

			ethClient, err := ethclient.Dial(nodeRPCURL)
			if err != nil {
				return fmt.Errorf("failed to init public RPC client: %w", err)
			}

			prcOpts := "fast"
			mevClient, err := protect.ConstructClient(alice, network, &protect.ClientOpts{
				RPCOpts: prcOpts,

				FlashbotsRPC:      flashbotsRPCURL,
				FlashbotsRelay:    flashbotsRelayURL,
				FlashbotsProtect:  flashbotsProtectURL,
				FlashbotsMEVShare: flashbotsMEVShareURL,
				ChainID:           chainID,
			})
			if err != nil {
				return fmt.Errorf("failed to construct mev client: %w", err)
			}

			handler = &ports.Handler{
				MEVClient:                   mevClient,
				EthClient:                   ethClient,
				Alice:                       alice,
				Network:                     network,
				BuilderAddr:                 builderAddr,
				WETHAddr:                    wethAddr,
				CheckAndSendContract:        checkAndSendContract,
				BatchCallAndSponsorContract: batchcallAndSponsorContract,
				DefaultPriorityFee:          priorityFee,
			}

			return nil
		},
	}

	// lazy wraps a handler method so it's called at execution time (after Before initializes handler)
	lazy := func(fn func() func(*cli.Context) error) cli.ActionFunc {
		return func(cCtx *cli.Context) error {
			return fn()(cCtx)
		}
	}

	simulateV1Flags := append([]cli.Flag{
		&cli.StringFlag{
			Name:    "block",
			Aliases: []string{"b"},
			Value:   "latest",
			Usage:   "block number (hex e.g. 0x174d7ed) or tag (latest, pending, safe, finalized)",
		},
	}, txFlags...)

	backrunFlags := []cli.Flag{&cli.BoolFlag{
		Name:    "use-relay",
		Aliases: []string{"ur"},
	}}
	backrunFlags = append(backrunFlags, txFlags...)

	app.Commands = []*cli.Command{
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
		{
			Name:        "send-private-tx",
			Aliases:     []string{"stx"},
			Description: "send private test tx on flashbots rpc endpoint",
			Flags:       txFlags,
			Action:      lazy(func() func(*cli.Context) error { return handler.SendPrivateTx(ctx) }),
		},
		// This command is for the test goals. Sends fake tx which must fail
		{
			Name:        "send-fake-tx",
			Aliases:     []string{"sft"},
			Description: "send fake tx which must fail on flashbots rpc endpoint",
			Flags:       txFlags,
			Action:      lazy(func() func(*cli.Context) error { return handler.SendFakeTx(ctx) }),
		},
		{
			Name:        "send-private-relay-tx",
			Aliases:     []string{"sprt"},
			Description: "send private tx to relay",
			Flags:       txFlags,
			Action:      lazy(func() func(*cli.Context) error { return handler.SendPrivateRelayTx(ctx) }),
		},
		{
			Name:        "eth-call-bundle",
			Aliases:     []string{"ecb"},
			Description: "simulate eth bundle",
			Flags:       txFlags,
			Action:      lazy(func() func(*cli.Context) error { return handler.CallEthBundle(ctx) }),
		},
		{
			Name:        "simulate-v1",
			Aliases:     []string{"sv1"},
			Description: "simulate tx via eth_simulateV1 (reth)",
			Flags:       simulateV1Flags,
			Action:      lazy(func() func(*cli.Context) error { return handler.SimulateV1(ctx) }),
		},
		{
			Name:        "eth-send-bundle",
			Aliases:     []string{"esb"},
			Description: "send eth bundle",
			Flags:       txFlags,
			Action:      lazy(func() func(*cli.Context) error { return handler.SendEthBundle(ctx) }),
		},
		{
			Name:        "mev-send-bundle",
			Aliases:     []string{"msb"},
			Description: "send mev bundle",
			Flags:       txFlags,
			Action:      lazy(func() func(*cli.Context) error { return handler.SendMEVBundle(ctx) }),
		},
		{
			Name:        "eth-cancel-bundle",
			Aliases:     []string{"ecanb"},
			Description: "cancel eth bundle",
			Flags:       txFlags,
			Action:      lazy(func() func(*cli.Context) error { return handler.CancelEthBundle(ctx) }),
		},
		{
			Name:        "cancel-relay-tx",
			Aliases:     []string{"crt"},
			Description: "cancel private tx on relay",
			Flags:       txFlags,
			Action:      lazy(func() func(*cli.Context) error { return handler.CancelRelayTx(ctx) }),
		},
		{
			Name:        "cancel-rpc-tx",
			Aliases:     []string{"crpc"},
			Description: "cancel private tx via RPC using self-transfer detection",
			Flags:       txFlags,
			Action:      lazy(func() func(*cli.Context) error { return handler.CancelRpcTx(ctx) }),
		},
		// This command calls Flashbots Protect Transaction Status API and logs info txStatus
		//
		// For details, see: https://docs.flashbots.net/flashbots-protect/additional-documentation/status-api
		{
			Name:        "tx-status",
			Aliases:     []string{"ts"},
			Description: "query check tx status on Flashbots Protect endpoint",
			Flags:       txStatusFlags,
			Action:      lazy(func() func(*cli.Context) error { return handler.TxStatus(ctx) }),
		},
		// Flashbots provides a Server-Sent Events (SSE) stream to access MEV-Share events.
		//
		// This command connects to the MEV-Share SSE stream and listens for hint events.
		// The target hintHash is a keccak256 hash of the original transaction hash.
		// For more information, see:
		// https://docs.flashbots.net/flashbots-mev-share/searchers/event-stream#understanding-double-hash
		//
		// This tool allows searchers to subscribe to real-time MEV opportunities
		// by decoding and handling hint messages streamed from the Flashbots network.
		{
			Name:        "hints-stream",
			Aliases:     []string{"hs"},
			Description: "listen distributed MevShare events via SSE. Info log hints only",
			Action:      lazy(func() func(*cli.Context) error { return handler.HintsStream(ctx) }),
		},
		// This command demonstrates a simple MEV backrun flow using the Flashbots MEV-Share network.
		//
		// The example flow includes the following steps:
		// 1. Send a private transaction to the network.
		// 2. Subscribe to the MEV-Share SSE stream and listen for incoming hints.
		// 3. When a received hintHash matches the original transaction, send a backrun transaction.
		//
		// This tool serves as a minimal working example for understanding and testing
		// basic backrun logic.
		{
			Name:        "backrun",
			Aliases:     []string{"br"},
			Description: "backrun tx based on the MevShare events",
			Flags:       backrunFlags,
			Action:      lazy(func() func(*cli.Context) error { return handler.Backrun(ctx) }),
		},
	}

	if err := app.Run(os.Args); err != nil {
		panic(err)
	}
}
