package protect

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

	defaultPingInterval = time.Second * 15
)

var (
	ErrMaxConnAttemptsExceeded = errors.New("max init stream connection attempts exceeded")
)

type SubscriptionOpts struct {
	// PingInterval defines wait time for a ping response from the SSE server
	// before considering the connection as stale or unresponsive.
	PingInterval time.Duration

	MaxConnAttempts int
}

func DefaultSubOpts() *SubscriptionOpts {
	return &SubscriptionOpts{
		PingInterval:    defaultPingInterval,
		MaxConnAttempts: maxConnAttempts,
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

	if err := s.subscribe(ctx); err != nil {
		return nil, err
	}

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
	conn := func() (*http.Response, error) {
		var lastErr error
		req := new(http.Request)
		*req = stream.req
		req = req.WithContext(ctx)
		for attempts := 0; attempts < maxConnAttempts; attempts++ {
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				// means client closed the stream
				if errors.Is(err, context.Canceled) {
					return nil, err
				}

				lastErr = err
				<-time.After(time.Second * 1)
				continue
			}

			if resp.StatusCode != http.StatusOK {
				lastErr = fmt.Errorf("init stream connection request failed. Status not 200")
				<-time.After(time.Second * 1)
				continue
			}

			return resp, nil
		}

		return nil, errors.Join(ErrMaxConnAttemptsExceeded, lastErr)
	}

	var (
		dataPref = []byte("data: ")
		ping     = []byte("ping:")

		readerBuff = make([]byte, bufio.MaxScanTokenSize*2)
	)

	resp, err := conn()
	if err != nil {
		stream.connErr.Store(err)
		return err
	}

	go func() {
		for {
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
					panic(fmt.Errorf("failed to unmarshal hint object error %w", err))
				}
				stream.hintsC <- hint
			}

			_ = resp.Body.Close()

			if readerErr := reader.Err(); readerErr != nil {
				// means client closed the stream
				// exit point
				if errors.Is(readerErr, context.Canceled) {
					return
				}

				if errors.Is(readerErr, bufio.ErrTooLong) {
					slog.Debug("Failed to scan. Token is too large. Some data can be lost")
				}

				slog.Debug("Failed to scan. Reader closed some data can be lost.", "error", readerErr)
			}

			// readerErr is nil (EOF occurred reading data from resp body)
			// means connection closed by server. Reconnecting
			resp, err = conn()
			if err != nil {
				stream.connErr.Store(err)
				return
			}
		}
	}()

	return nil
}
