package mev

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"
)

const (
	maxConnAttempts = 3

	defaultPingInterval       = time.Second * 15
	defaultConnRequestTimeout = time.Second * 3
)

var (
	ErrMaxConnAttemptsExceeded = errors.New("max init stream connection attempts exceeded")
)

type SubscriptionOpts struct {
	// PingInterval defines wait time for a ping response from the SSE server
	// before considering the connection as stale or unresponsive.
	PingInterval time.Duration

	// ConnRetryTimeout specifies the duration to wait before retrying to establish a connection
	// if the initial connection attempt fails
	ConnRetryTimeout time.Duration

	MaxConnAttempts int
}

func DefaultSubOpts() *SubscriptionOpts {
	return &SubscriptionOpts{
		PingInterval:     defaultPingInterval,
		ConnRetryTimeout: defaultConnRequestTimeout,
		MaxConnAttempts:  maxConnAttempts,
	}
}

// Stream implements a stream for Server-Sent Events (SSE) that provides MEV-Share hints.
type Stream struct {
	opts *SubscriptionOpts

	req     http.Request
	connErr atomic.Value
	hintsC  chan<- Hint
}

// SubscribeHints creates connection to the stream, parses incoming
// messages into Hint and produces them through hints channel.
func SubscribeHints(ctx context.Context, url string, ch chan<- Hint, opts *SubscriptionOpts) (*Stream, error) {
	if opts == nil {
		opts = DefaultSubOpts()
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create http request error %w", err)
	}
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Connection", "keep-alive")

	s := &Stream{
		opts:   opts,
		req:    *req,
		hintsC: ch,
	}

	go func() {
		if err := s.subscribe(ctx); err != nil {
			s.connErr.Store(err)
		}
	}()

	return s, nil
}

func (stream *Stream) Error() error {
	err := stream.connErr.Load()
	if err == nil {
		return nil
	}

	return err.(error)
}

func (stream *Stream) subscribe(ctx context.Context) error {
	streamCtx, cancelSub := context.WithCancel(ctx)
	defer cancelSub()

	conn := func() (*http.Response, error) {
		req := new(http.Request)
		*req = stream.req
		req = req.WithContext(streamCtx)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("init stream connection request failed error %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("init stream connection request failed. Status not 200")
		}

		return resp, nil
	}

	var (
		dataPref = []byte("data: ")
		ping     = []byte("ping:")

		readerBuff = make([]byte, bufio.MaxScanTokenSize*2)

		connAttempts int
	)
	for {
		resp, err := conn()
		if err != nil {
			if errors.Is(err, context.Canceled) {
				break
			}
			connAttempts++

			if connAttempts >= stream.opts.MaxConnAttempts {
				cancelSub()
				return errors.Join(ErrMaxConnAttemptsExceeded, err)
			}

			<-time.After(stream.opts.ConnRetryTimeout)
			continue
		}
		// reset attempts after successfully connected
		connAttempts = 0

		reader := bufio.NewScanner(resp.Body)
		reader.Split(bufio.ScanLines)
		reader.Buffer(readerBuff, bufio.MaxScanTokenSize*2)

		for reader.Scan() {
			payload := reader.Bytes()
			if len(payload) == 0 {
				continue
			}

			if bytes.Contains(payload, ping) {
				continue
			}

			var valid bool
			payload, valid = bytes.CutPrefix(payload, dataPref)
			if !valid {
				slog.Debug("Token doesn't contain required prefix. Some data can be lost")
				continue
			}

			var hint Hint
			if err := json.Unmarshal(payload, &hint); err != nil {
				return fmt.Errorf("failed to unmarshal hint object error %w", err)
			}
			stream.hintsC <- hint
		}

		_ = resp.Body.Close()

		if readerErr := reader.Err(); readerErr != nil {
			// means client closed the stream
			// exit point
			if errors.Is(readerErr, context.Canceled) {
				break
			}

			if errors.Is(readerErr, bufio.ErrTooLong) {
				slog.Debug("Failed to scan. Token is too large. Some data can be lost")
				continue
			}

			slog.Debug("Failed to scan. Reader closed some data can be lost.", "error", readerErr)
			continue
		}

		// readerErr is nil (EOF occurred reading data from resp body)
		// means connection closed by server. Reconnecting
	}

	return nil
}
